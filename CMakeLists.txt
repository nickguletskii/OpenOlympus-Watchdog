cmake_minimum_required(VERSION 2.8.4)
project(olympus_watchdog)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

find_package (Threads)

set(SOURCE_FILES runner.cpp)
add_executable(olympus_watchdog ${SOURCE_FILES})
target_link_libraries (olympus_watchdog ${CMAKE_THREAD_LIBS_INIT})
INSTALL(TARGETS olympus_watchdog
  RUNTIME DESTINATION bin
)