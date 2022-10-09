#ifndef CHAKUDBG_DEBUGGER_HPP
#define CHAKUDBG_DEBUGGER_HPP

#include <utility>
#include <string>
#include <linux/types.h>
#include <unordered_map>
#include "breakpoint.hpp"

namespace chakudbg {
    class debugger {
    public:
        debugger (std::string prog_name, pid_t pid)
        : m_prog_name{std::move(prog_name)}, m_pid{pid} {}
        void run();
        void set_breakpoint_at_address(std::intptr_t addr);
        void dump_registers();

    private:
        void handle_command(const std::string& line);
        void continue_execution();
        uint64_t get_pc();
        void set_pc(uint64_t pc);
        void step_over_breakpoint();
        void wait_for_signal();
        uint64_t read_memory(uint64_t address);
        void write_memory(uint64_t address, uint64_t value);

        std::string m_prog_name;
        pid_t m_pid;
        std::unordered_map<std::intptr_t, breakpoint> m_breakpoints;
    };
}

#endif
