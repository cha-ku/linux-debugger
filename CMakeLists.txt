cmake_minimum_required(VERSION 3.0)

project(ChakuDbg)

set(CMAKE_CXX_FLAGS "-std=c++2a")

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include_directories(external/libelfin external/linenoise include)

add_executable(chakudbg src/debugger.cpp src/breakpoint.cpp src/register.cpp external/linenoise/linenoise.c src/linux-debugger.cpp)

add_custom_target(libelfin
    COMMAND make
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/external/libelfin)

target_link_libraries(chakudbg
    ${PROJECT_SOURCE_DIR}/external/libelfin/dwarf/libdwarf++.so
    ${PROJECT_SOURCE_DIR}/external/libelfin/elf/libelf++.so)

add_dependencies(chakudbg libelfin)

add_executable(hello example/hello-world.cpp)
set_target_properties(hello
    PROPERTIES COMPILE_FLAGS "-g -O0")
