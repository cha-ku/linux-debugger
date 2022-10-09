#include <iostream>
#include <vector>
#include <sstream>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <iomanip>
#include "linenoise.h"
#include "register.hpp"
#include "debugger.hpp"

using namespace chakudbg;

std::vector<std::string> split(const std::string& line, char delimiter=' ') {
    std::vector<std::string> tokens;
    std::stringstream tmp{line};
    std::string token;
    while(std::getline(tmp, token, delimiter)) {
        tokens.push_back(std::move(token));
    }
    return tokens;
}

bool is_prefix(const std::string& cmd, const std::string& keyword) {
    return keyword.compare(0, cmd.size(), cmd) == 0;
}

uint64_t debugger::read_memory(uint64_t address) {
    return ptrace(PTRACE_PEEKDATA, m_pid, address, nullptr);
}

void debugger::write_memory(uint64_t address, uint64_t value) {
    ptrace(PTRACE_POKEDATA, m_pid, address, value);
}


void debugger::handle_command(const std::string& line) {
    auto args = split(line);
    auto command = args[0];

    if(is_prefix(command, "continue")) {
        continue_execution();
    }
    else if (is_prefix(command, "break")) {
        std::string addr {args[1], 2};
        set_breakpoint_at_address(std::stol(addr, 0, 16));
    }
    else if (is_prefix(command, "register")) {
        if(is_prefix(args[1], "dump")) {
            dump_registers();
        }
        else if(is_prefix(args[1], "read")) {
            std::cout << get_register_value(m_pid, get_register_from_name(args[2])) << "\n";
        }
        else if(is_prefix(args[1], "write")) {
            std::string val{args[3], 2};
            set_register_value(m_pid, get_register_from_name(args[2]), std::stol(val, 0, 16));
        }
    }
    else if (is_prefix(command, "memory")) {
        std::string addr {args[2], 2}; //assume 0xADDRESS

        if(is_prefix(args[1], "read")) {
            std::cout << std::hex << read_memory(std::stol(addr, 0, 16)) << "\n";
        }
        else if(is_prefix(args[1], "write")) {
            std::string val {args[3], 2};
            write_memory(std::stol(addr, 0, 16), std::stol(val, 0, 16));
        }
    }
    else {
        std::cerr << "Unknown command\n";
    }
}

void debugger::run() {
    int wait_status;
    auto options = 0;
    waitpid(m_pid, &wait_status, options);

    char* line = nullptr;
    while((line = linenoise("chakudbg> ")) != nullptr) {
        handle_command(line);
        linenoiseHistoryAdd(line);
        linenoiseFree(line);
    }
}

void debugger::continue_execution() {
    step_over_breakpoint();
    ptrace(PTRACE_CONT, m_pid, nullptr, nullptr);
    wait_for_signal();
}

void debugger::set_breakpoint_at_address(std::intptr_t addr) {
    std::cout << "Set breakpoint at address 0x" << std::hex << addr << "\n";
    breakpoint bp {m_pid, addr};
    bp.enable();
    m_breakpoints[addr] = bp;
}

void debugger::dump_registers() {
    for (const auto& rd : g_register_descriptors) {
        std::cout << rd.name << " 0x" << std::setfill('0') << std::setw(16) << std::hex << get_register_value(m_pid, rd.r) << "\n";
    }
}

uint64_t debugger::get_pc() {
    return get_register_value(m_pid, reg::rip);
}

void debugger::set_pc(uint64_t value) {
    set_register_value(m_pid, reg::rip, value);
}

void debugger::step_over_breakpoint() {
    auto possible_breakpoint_location = get_pc() - 1;
    if (m_breakpoints.count(possible_breakpoint_location)) {
        auto& bp = m_breakpoints[possible_breakpoint_location];

        if (bp.is_enabled()) {
            auto previous_instruction_address = possible_breakpoint_location;
            set_pc(previous_instruction_address);

            bp.disable();
            ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr);
            wait_for_signal();
            bp.enable();
        }
    }
}

void debugger::wait_for_signal() {
    int wait_status;
    auto options = 0;
    waitpid(m_pid, &wait_status, options);
}

