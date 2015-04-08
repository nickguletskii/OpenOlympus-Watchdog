/*******************************************************************************
*                                                                             *
* Copyright (C) 2014-2015 Nick Guletskii                                      *
* All rights reserved.                                                        *
*                                                                             *
* Redistribution and use in source and binary forms, with or without          *
* modification, are permitted provided that the following conditions are met: *
*                                                                             *
* 1. Redistributions of source code must retain the above copyright notice,   *
*    this list of conditions and the following disclaimer.                    *
*                                                                             *
* 2. Redistributions in binary form must reproduce the above copyright        *
*    notice, this list of conditions and the following disclaimer in the      *
*    documentation and/or other materials provided with the distribution.     *
*                                                                             *
* 3. Neither the name of the author(s) nor the names of its contributors may  *
*    be used to endorse or promote products derived from this software        *
*    without specific prior written permission.                               *
*                                                                             *
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" *
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE   *
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE  *
* ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE    *
* LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR         *
* CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF        *
* SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS    *
* INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN     *
* CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)     *
* ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE  *
* POSSIBILITY OF SUCH DAMAGE.                                                 *
******************************************************************************/

#include "runner.hpp"

#include <cstring>
#include <iostream>
#include <sstream>
#include <sysexits.h>
#include <sys/resource.h>
#include <algorithm>
#include <fstream>
#include <map>
#include <random>
#include <getopt.h>
#include <semaphore.h>
#include <fcntl.h>

namespace openolympus {
#define FAIL_CHILD raise(SIGUSR1)

	bool to_bool(std::string const &s) {
		return s != "0";
	}

	static int install_syscall_filter(void) {
		struct sock_filter filter[] = {
				VALIDATE_ARCHITECTURE,
				EXAMINE_SYSCALL,
				ALLOW_SYSCALL(restart_syscall),
				ALLOW_SYSCALL(read),
				ALLOW_SYSCALL(write),
				ALLOW_SYSCALL(lseek),
				ALLOW_SYSCALL(brk),
				ALLOW_SYSCALL(ioctl),
				ALLOW_SYSCALL(munmap),
				ALLOW_SYSCALL(mprotect),
				ALLOW_SYSCALL(mremap),
				ALLOW_SYSCALL(mmap),
				ALLOW_SYSCALL(gettid),
				ALLOW_SYSCALL(set_thread_area),
				ALLOW_SYSCALL(exit_group),
				ALLOW_SYSCALL(fstat),
				ALLOW_SYSCALL(uname),
				ALLOW_SYSCALL(arch_prctl),
				ALLOW_SYSCALL(access),
				ALLOW_SYSCALL(open),
				ALLOW_SYSCALL(close),
				ALLOW_SYSCALL(stat),
				ALLOW_SYSCALL(readv),
				ALLOW_SYSCALL(writev),
				ALLOW_SYSCALL(dup3),
				ALLOW_SYSCALL(rt_sigaction),
				ALLOW_SYSCALL(rt_sigprocmask),
				ALLOW_SYSCALL(rt_sigreturn),
				ALLOW_SYSCALL(tgkill),
				ALLOW_SYSCALL(getrlimit),
				ALLOW_SYSCALL(readlink),
				ALLOW_SYSCALL(time),
				ALLOW_SYSCALL(execve),
				ALLOW_SYSCALL(nanosleep),
				KILL_PROCESS,
		};
		struct sock_fprog filter_program = {
				.len = (unsigned short) (sizeof(filter) / sizeof(filter[0])),
				.filter = filter,
		};

		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
			goto failed;
		}
		if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &filter_program)) {
			goto failed;
		}
		return 0;


		failed:
		ERR_LOG("Seccomp filter not available! Please check that your kernel is correct!" <<
				strerror(errno));
		FAIL_CHILD;
	}

	pid_t watchdog::getPid() const {
		return pid;
	}

	void watchdog::setup_io() {
		for (int file_descriptor = 0; file_descriptor < MAX_FILE_DESCRIPTOR; file_descriptor++) {
			if ((file_descriptor == input_file_descriptor)
					|| (file_descriptor == output_file_descriptor)
					|| (file_descriptor == error_file_descriptor)) {
				continue;
			}
			close(file_descriptor);
		}

		if (dup2(error_file_descriptor, STDERR_FILENO) < 0) {
			ERR_LOG("Couldn't redirect error output.");
			FAIL_CHILD;
		}

		if (dup2(output_file_descriptor, STDOUT_FILENO) < 0) {
			ERR_LOG("Couldn't redirect output.");
			FAIL_CHILD;
		}

		if (dup2(input_file_descriptor, STDIN_FILENO) < 0) {
			ERR_LOG("Couldn't redirect input.");
			FAIL_CHILD;
		}
	}

	void watchdog::setup_rlimit() {
		rlimit *core_dump_rlimit = new rlimit();
		core_dump_rlimit->rlim_cur = 0;
		core_dump_rlimit->rlim_max = 0;
		setrlimit(RLIMIT_CORE, core_dump_rlimit);

		rlimit *disk_rlimit = new rlimit();
		disk_rlimit->rlim_cur = disk_limit;
		disk_rlimit->rlim_max = disk_limit;
		setrlimit(RLIMIT_CORE, disk_rlimit);

	}

	void watchdog::execute_child(std::string program, std::vector<std::string> args) {
		if((securitySemaphore = sem_open(semaphoreName.c_str(), O_EXCL))==SEM_FAILED){
			ERR_LOG("Couldn't create security semaphore! " <<
					strerror(errno));
			exit(EX_SOFTWARE);
		}

		if (setsid() < 0) {
			ERR_LOG("Couldn't setsid! Error: " << strerror(errno));
			FAIL_CHILD;
		}

		setup_rlimit();
		setup_io();

		LOG("Bulding arguments...");
		std::array<char *, 256> argv;

		std::fill(argv.begin(), argv.end(), nullptr);
		argv[0] = new char[program.size() + 1];
		strcpy(argv[0], program.c_str());
		argv[0][program.size()] = '\0';

		for (size_t i = 0; i < args.size(); i++) {
			char *writable = new char[args[i].size() + 1];
			std::copy(args[i].begin(), args[i].end(), writable);
			writable[args[i].size()] = '\0';
			argv[i + 1] = writable;
		}


		std::array<char *, 1> envp;
		envp[0] = nullptr;


		if(!chroot_path.empty() && chroot_path!="/") {
			LOG("Chrooting...");

			if (chroot(chroot_path.c_str()) != 0) {
				ERR_LOG("Couldn't chroot! Error: " << strerror(errno));
				FAIL_CHILD;
			}

			LOG("Chrooted.");
		}

		if (setgid(gid) != 0) {
			ERR_LOG("Couldn't change gid! Error: " << strerror(errno));
			FAIL_CHILD;
		}
		if (setuid(uid) != 0) {
			ERR_LOG("Couldn't change uid! Error: " << strerror(errno));
			FAIL_CHILD;
		}

		LOG("Waiting for watcher threads to be ready");
		if(sem_wait(securitySemaphore) == EINTR) // Wait for the signal polling thread
			FAIL_CHILD;
		if(sem_wait(securitySemaphore) == EINTR)  // Wait for the timeout thread
			FAIL_CHILD;
		if(sem_wait(securitySemaphore) == EINTR)  // Wait for the CPU time/memory limiting thread
			FAIL_CHILD;
		LOG("Watcher threads are ready. Closing the semaphore.");
		sem_close(securitySemaphore);
		sem_unlink(semaphoreName.c_str());
		LOG("Closed semaphore.");

		if (enableSecurity)
			install_syscall_filter();
		LOG("Running execve: " << program);
		// No cleanup required: we exit here anyway!
		execve(program.c_str(), argv.data(), envp.data());
		ERR_LOG(
				"Execve failed! Error: " << errno << " " << strerror(errno));
		FAIL_CHILD;
	}

	void watchdog::enter_watchdog() {
		start_time = std::chrono::high_resolution_clock::now();

		clockid_t clock_id;
		clock_getcpuclockid(pid, &clock_id);

		exit_monitor_thread = std::thread([this]() {
			sem_post(securitySemaphore);

			int status;
			do {
				waitpid(pid, &status, WUNTRACED);

				if (!running)
					return;

				if (WIFEXITED(status)) {
					int code = WEXITSTATUS(status);
					if (code != 0) {
						finish(RUNTIME_ERROR);
					} else {
						finish(OK);
					}
				} else if (WIFSIGNALED(status)) {
					int signal = WTERMSIG(status);
					LOG("Child signaled: " << strsignal(signal));
					switch (signal) {
						case SIGXFSZ:
							finish(DISK_LIMIT);
							break;
						case SIGSEGV:
						case SIGBUS:
						case SIGFPE:
							finish(RUNTIME_ERROR);
							break;
						case SIGSYS:
							finish(SANDBOX_VIOLATION);
							break;
						case SIGUSR1:
							finish(INTERNAL_ERROR);
							break;
						default:
							shutdown(EXIT_FAILURE);
							break;
					}

				}
			} while (!WIFEXITED(status) && !WIFSIGNALED(status) && running);
		});
		exit_monitor_thread.detach();

		timeout_thread = std::thread([this]() {
			sem_post(securitySemaphore);

			std::unique_lock<std::mutex> lk(running_notifier_mutex);
			if (!running_notifier.wait_for(lk,
					std::chrono::milliseconds(time_limit),
					[this]() {return !running;})) {
				finish(TIME_LIMIT);
			}
		});
		timeout_thread.detach();

		sem_post(securitySemaphore);

		LOG("Opening procfs for the first time");
		std::ifstream procfs_stream("/proc/" + std::to_string(pid) + "/stat");

		while (running) {

			struct timespec ts;
			if (clock_getcpuclockid(pid, &clock_id) == 0 && clock_gettime(clock_id, &ts) == 0) {
				cpu_milliseconds_consumed = ((int64_t) ts.tv_sec) * 1000ll + ((int64_t) ts.tv_nsec / 1000000ll);
			}


			procfs_stream.seekg(0);
			procfs_stream.sync();

			if (procfs_stream.fail()) {
				break;
			}
			int64_t user_cpu_time;
			int64_t kernel_cpu_time;
			size_t virtual_memory_size;
			for (int i = 0; i < 40; i++) {
				switch (i) {
					case 13:
						procfs_stream >> user_cpu_time;
						break;
					case 14:
						procfs_stream >> kernel_cpu_time;
						break;
					case 22:
						procfs_stream >> virtual_memory_size;
						break;
					default:
						procfs_stream.ignore(256, ' ');
				}
			}

			if (cpu_milliseconds_consumed > cpu_time_limit) {
				finish(CPU_TIME_LIMIT);
			}

			peak_virtual_memory_size = std::max<size_t>(virtual_memory_size, peak_virtual_memory_size);

			if (peak_virtual_memory_size > memory_limit) {
				finish(MEMORY_LIMIT);
			}
			std::this_thread::sleep_for(std::chrono::milliseconds(10));
		}

		LOG("Finishing");
		auto end_time = std::chrono::high_resolution_clock::now();

		time_consumed = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();

		running = false;

		running_notifier.notify_all();

		if (exit_monitor_thread.joinable())
			exit_monitor_thread.join();
		if (timeout_thread.joinable())
			timeout_thread.join();

		std::map<exit_status, std::string> names{
				{OK, "OK"},
				{CPU_TIME_LIMIT, "TIME_LIMIT"},
				{TIME_LIMIT, "TIME_LIMIT"},
				{MEMORY_LIMIT, "MEMORY_LIMIT"},
				{DISK_LIMIT, "OUTPUT_LIMIT"},
				{RUNTIME_ERROR, "RUNTIME_ERROR"},
				{SANDBOX_VIOLATION, "SECURITY_VIOLATION"},
				{INTERNAL_ERROR, "INTERNAL_ERROR"},
				{ABNORMAL_TERMINATION, "ABNORMAL_TERMINATION"}
		};

		LOG("Writing verdict");

		std::ofstream verdict;
		std::ios_base::iostate exceptionMask = verdict.exceptions() | std::ios::failbit;
		verdict.exceptions(exceptionMask);
		verdict.open("verdict.txt", std::ios_base::out);

		verdict << names[status] << "(" << time_consumed << ", " << cpu_milliseconds_consumed << ", " <<
				peak_virtual_memory_size << ")" << std::endl;
		verdict.flush();
		verdict.close();

		LOG("Killing");
		std::cout.flush();

		if (status != OK && pid != 0)
			kill(pid, SIGKILL);
		LOG("Finished");

		shutdown(EXIT_SUCCESS);
	}

	void watchdog::shutdown(int exit_code) {
		running_notifier.notify_all();

		if (exit_monitor_thread.joinable())
			exit_monitor_thread.join();
		if (timeout_thread.joinable())
			timeout_thread.join();
		exit(exit_code);
	}

	void watchdog::finish(exit_status status) {
		running = false;
		this->status = status;

		LOG("Destroying semaphore.");
		sem_close(securitySemaphore);
		sem_unlink(semaphoreName.c_str());
		LOG("Destroyed semaphore.");
	}

	std::string watchdog::generate_semaphore_id(){
		std::vector<char> name(16);
		std::mt19937_64 mersenneTwister;
		std::seed_seq sseq{
				(int)(
						std::chrono::system_clock::now().time_since_epoch().count()
						% 1000000007
				),
				(int)(getpid() % 1000000007)
		};
		mersenneTwister.seed(sseq);
		std::uniform_int_distribution<> distribution(0, 15);

		std::generate(name.begin(), name.end(), [&]{
			return "0123456789ABCDEF"[distribution(mersenneTwister)];
		});

		return std::string(name.begin(), name.end());
	}

	void watchdog::fork_app(std::string program, std::vector<std::string> args) {
		running = true;
		if(!usedOnce)
			throw std::logic_error("A watchdog can only be used once!");
		usedOnce = false;

		semaphoreName = "/oolw" + generate_semaphore_id();

		if((securitySemaphore = sem_open(semaphoreName.c_str(), O_CREAT, 0664, 0))==SEM_FAILED){
			ERR_LOG("Couldn't create security semaphore! " <<
					strerror(errno));
			exit(EX_SOFTWARE);
		}

		pid = fork();

		if (pid == 0) {
			execute_child(program, args);
		} else {
			enter_watchdog();
		}
	}

	void run(int argc, char **argv) {
		int64_t memoryLimit = 64ll * 1024ll * 1024ll;
		int64_t cpuLimit = 1ll * 1000ll;
		int64_t timeLimit = 2ll * 1000ll;
		int64_t diskLimit = 1ll * 1024ll * 1024ll;

		uid_t uid;
		gid_t gid;

		bool enableSecurity = true;

		std::string jailPath = "/";

		{
			int c;
			while (true) {
				static struct option long_options[] = {

						{"memorylimit", required_argument, 0, 'm'},

						{"cpulimit", required_argument, 0, 'c'},

						{"timelimit", required_argument, 0, 't'},

						{"disklimit", required_argument, 0, 'd'},

						{"security", required_argument, 0, 's'},

						{"jail", required_argument, 0, 'j'},

						{"uid", required_argument, 0, 'u'},

						{"gid", required_argument, 0, 'g'},

						{0, 0, 0, 0}};

				int option_index = 0;
				c = getopt_long(argc, argv, "mctd", long_options, &option_index);
				if (c == -1)
					break;
				switch (c) {
					case 0:
						break;
					case 'm':
						memoryLimit = std::stoll(optarg);
						break;
					case 'c':
						cpuLimit = std::stoll(optarg);
						break;
					case 't':
						timeLimit = std::stoll(optarg);
						break;
					case 'd':
						diskLimit = std::stoll(optarg);
						break;
					case 'u':
						uid = std::stoll(optarg);
						break;
					case 'g':
						gid = std::stoll(optarg);
						break;
					case 's':
						enableSecurity = to_bool(optarg);
						break;
					case 'j':
						jailPath = std::string(optarg);
						break;
					case '?':
						break;
					default:
						exit(EX_USAGE);
				}
			}
		}

		if (argv[optind] == nullptr || argv[optind][0] == '\0') {
			exit(EX_USAGE);
		}


		std::vector<std::string> args;
		for (size_t index = optind + 1; index < argc; index++) {
			args.push_back(std::string(argv[index]));
		}

		watchdog watcher(enableSecurity, memoryLimit, diskLimit, timeLimit, cpuLimit, gid, uid, jailPath);
		watcher.fork_app(std::string(argv[optind]), args);
	}
}

int main(int argc, char **argv) {
	openolympus::run(argc, argv);
	return 0;
}