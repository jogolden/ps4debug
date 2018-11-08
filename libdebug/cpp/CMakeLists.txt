cmake_minimum_required(VERSION 3.8)
project(libdebug)

set(CMAKE_STATIC_LIBRARY_PREFIX "")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/)
add_library(libdebug STATIC 
    source/PS4DBG.cpp
	source/Process.cpp
)
target_compile_features(libdebug PRIVATE cxx_std_17)
target_include_directories(libdebug
    PUBLIC 
        ${PROJECT_SOURCE_DIR}/include
)

 

 add_executable(example 
    example/example.cpp
)
target_compile_features(example PRIVATE cxx_std_17)
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
target_link_libraries( example
    PRIVATE 
        libdebug
        Threads::Threads
)