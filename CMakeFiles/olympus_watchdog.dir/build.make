# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 2.8

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list

# Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/nick/ClionProjects/olympus-watchdog

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/nick/ClionProjects/olympus-watchdog

# Include any dependencies generated for this target.
include CMakeFiles/olympus_watchdog.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/olympus_watchdog.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/olympus_watchdog.dir/flags.make

CMakeFiles/olympus_watchdog.dir/runner.cpp.o: CMakeFiles/olympus_watchdog.dir/flags.make
CMakeFiles/olympus_watchdog.dir/runner.cpp.o: runner.cpp
	$(CMAKE_COMMAND) -E cmake_progress_report /home/nick/ClionProjects/olympus-watchdog/CMakeFiles $(CMAKE_PROGRESS_1)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Building CXX object CMakeFiles/olympus_watchdog.dir/runner.cpp.o"
	/usr/bin/c++   $(CXX_DEFINES) $(CXX_FLAGS) -o CMakeFiles/olympus_watchdog.dir/runner.cpp.o -c /home/nick/ClionProjects/olympus-watchdog/runner.cpp

CMakeFiles/olympus_watchdog.dir/runner.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/olympus_watchdog.dir/runner.cpp.i"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_FLAGS) -E /home/nick/ClionProjects/olympus-watchdog/runner.cpp > CMakeFiles/olympus_watchdog.dir/runner.cpp.i

CMakeFiles/olympus_watchdog.dir/runner.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/olympus_watchdog.dir/runner.cpp.s"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_FLAGS) -S /home/nick/ClionProjects/olympus-watchdog/runner.cpp -o CMakeFiles/olympus_watchdog.dir/runner.cpp.s

CMakeFiles/olympus_watchdog.dir/runner.cpp.o.requires:
.PHONY : CMakeFiles/olympus_watchdog.dir/runner.cpp.o.requires

CMakeFiles/olympus_watchdog.dir/runner.cpp.o.provides: CMakeFiles/olympus_watchdog.dir/runner.cpp.o.requires
	$(MAKE) -f CMakeFiles/olympus_watchdog.dir/build.make CMakeFiles/olympus_watchdog.dir/runner.cpp.o.provides.build
.PHONY : CMakeFiles/olympus_watchdog.dir/runner.cpp.o.provides

CMakeFiles/olympus_watchdog.dir/runner.cpp.o.provides.build: CMakeFiles/olympus_watchdog.dir/runner.cpp.o

# Object files for target olympus_watchdog
olympus_watchdog_OBJECTS = \
"CMakeFiles/olympus_watchdog.dir/runner.cpp.o"

# External object files for target olympus_watchdog
olympus_watchdog_EXTERNAL_OBJECTS =

olympus_watchdog: CMakeFiles/olympus_watchdog.dir/runner.cpp.o
olympus_watchdog: CMakeFiles/olympus_watchdog.dir/build.make
olympus_watchdog: CMakeFiles/olympus_watchdog.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --red --bold "Linking CXX executable olympus_watchdog"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/olympus_watchdog.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/olympus_watchdog.dir/build: olympus_watchdog
.PHONY : CMakeFiles/olympus_watchdog.dir/build

CMakeFiles/olympus_watchdog.dir/requires: CMakeFiles/olympus_watchdog.dir/runner.cpp.o.requires
.PHONY : CMakeFiles/olympus_watchdog.dir/requires

CMakeFiles/olympus_watchdog.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/olympus_watchdog.dir/cmake_clean.cmake
.PHONY : CMakeFiles/olympus_watchdog.dir/clean

CMakeFiles/olympus_watchdog.dir/depend:
	cd /home/nick/ClionProjects/olympus-watchdog && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/nick/ClionProjects/olympus-watchdog /home/nick/ClionProjects/olympus-watchdog /home/nick/ClionProjects/olympus-watchdog /home/nick/ClionProjects/olympus-watchdog /home/nick/ClionProjects/olympus-watchdog/CMakeFiles/olympus_watchdog.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/olympus_watchdog.dir/depend

