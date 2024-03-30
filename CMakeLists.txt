cmake_minimum_required(VERSION 3.8.0)
project (libxom C CXX ASM)

if(NOT(${CMAKE_SYSTEM_PROCESSOR} MATCHES "x86_64"))
  message(FATAL_ERROR "Error: The architecture ${CMAKE_SYSTEM_PROCESSOR} is not supported. libxom requires x86_64.")
endif()

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

add_link_options("-znoexecstack")

add_subdirectory("libxom")

if(EPT)
add_subdirectory("modxom")
endif()

add_executable(demo demo.c)
target_link_libraries(demo PUBLIC xom)

install(TARGETS xom DESTINATION /usr/lib)
install(FILES xom.h DESTINATION include)
install(FILES modxom/modxom.h DESTINATION include)
install(FILES ./xom DESTINATION /usr/bin PERMISSIONS WORLD_READ WORLD_EXECUTE)
