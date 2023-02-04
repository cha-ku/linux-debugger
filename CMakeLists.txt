cmake_minimum_required(VERSION 3.0)

project(ChakuDbg)

set(CXX_STANDARD_REQUIRED ON)

set(CMAKE_CXX_STANDARD 20)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include_directories(external/libelfin external/linenoise include)

add_executable(chakudbg src/debugger.cpp src/breakpoint.cpp src/register.cpp external/linenoise/linenoise.c src/linux-debugger.cpp)

add_compile_options(-Wall -Wextra -pedantic -Werror)

add_custom_target(libelfin
    COMMAND make
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/external/libelfin)

target_link_libraries(chakudbg
    ${PROJECT_SOURCE_DIR}/external/libelfin/dwarf/libdwarf++.so
    ${PROJECT_SOURCE_DIR}/external/libelfin/elf/libelf++.so)

add_dependencies(chakudbg libelfin)

add_executable(hello example/hello-world.cpp)
set_source_files_properties(example/hello-world.cpp PROPERTIES COMPILE_FLAGS "-gdwarf-4")

add_executable(dwarf_example example/dwarf_example.cpp)
set_source_files_properties(example/dwarf_example.cpp PROPERTIES COMPILE_FLAGS "-gdwarf-4 -Wno-error")

add_custom_command(TARGET chakudbg POST_BUILD
    COMMAND mv ${CMAKE_CURRENT_BINARY_DIR}/compile_commands.json ${CMAKE_SOURCE_DIR}
    VERBATIM)
