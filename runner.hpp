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


#include <time.h>
#include <sys/types.h>
#include <unistd.h>
#include <atomic>
#include <condition_variable>
#include <vector>
#include <thread>
#include <signal.h>
#include <sys/wait.h>
#include <linux/unistd.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <cstddef>
#include <semaphore.h>

#define LOG(x)
#define ERR_LOG(x)


#if defined(__x86_64__)
#define REG_SYSCALL     REG_RAX
#else
#error "Your architecture isn't supported!"
#endif

#define VALIDATE_ARCHITECTURE \
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, (offsetof(struct seccomp_data, arch))), \
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, AUDIT_ARCH_X86_64, 1, 0), \
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL)

#define EXAMINE_SYSCALL \
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, (offsetof(struct seccomp_data, nr)))

#define ALLOW_SYSCALL(name) \
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_##name, 0, 1), \
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)

#define KILL_PROCESS \
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL)


namespace openolympus {

	const int MAX_FILE_DESCRIPTOR = 256;

	enum exit_status {
		OK,
		CPU_TIME_LIMIT,
		TIME_LIMIT,
		MEMORY_LIMIT,
		DISK_LIMIT,
		RUNTIME_ERROR,
		SANDBOX_VIOLATION,
		INTERNAL_ERROR,
		ABNORMAL_TERMINATION
	};

	class watchdog {
	public:


	private:
		pid_t pid = 0;
	public:
		watchdog(bool enableSecurity, size_t memory_limit, size_t disk_limit, int64_t time_limit, int64_t cpu_time_limit, uid_t gid, uid_t uid, std::string chroot_path)
				: enableSecurity(enableSecurity),
				  memory_limit(memory_limit),
				  disk_limit(disk_limit),
				  time_limit(time_limit),
				  cpu_time_limit(cpu_time_limit),
				  chroot_path(chroot_path),
				  gid(gid),
				  uid(uid) {
		}

		void fork_app(std::string program, std::vector<std::string> args);

	private:
		bool usedOnce = true; // Flag that ensures that this watchdog will only be used once
		bool enableSecurity;

		size_t memory_limit;
		size_t disk_limit;
		int64_t time_limit;
		int64_t cpu_time_limit;
		std::string chroot_path;
		uid_t uid;
		gid_t gid;

		int input_file_descriptor = STDIN_FILENO;
		int output_file_descriptor = STDOUT_FILENO;
		int error_file_descriptor = STDERR_FILENO;
		std::atomic_bool running{false};

		int64_t cpu_milliseconds_consumed = 0;
		int64_t time_consumed = 0;
		size_t peak_virtual_memory_size = 0u;

		std::string semaphoreName;
		sem_t* securitySemaphore;

		std::chrono::time_point<std::chrono::high_resolution_clock> start_time;

		std::condition_variable running_notifier;
		std::mutex running_notifier_mutex;
		std::mutex finish_mutex;

		std::thread exit_monitor_thread;
		std::thread timeout_thread;

		pid_t getPid() const;

		void setup_io();

		void setup_rlimit();

		void execute_child(std::string program, std::vector<std::string> args);

		void enter_watchdog();

		void finish(exit_status status);

		void shutdown(int exit_code);

		exit_status status;

		std::string generate_semaphore_id();
	};

}