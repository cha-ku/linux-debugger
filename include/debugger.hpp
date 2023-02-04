#ifndef CHAKUDBG_DEBUGGER_HPP
#define CHAKUDBG_DEBUGGER_HPP

#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <utility>
#include <string>
#include <linux/types.h>
#include <unordered_map>
#include "breakpoint.hpp"
#include "dwarf/dwarf++.hh"
#include "elf/elf++.hh"

namespace chakudbg
{
    class debugger
    {
    public:
        debugger(std::string prog_name, pid_t pid)
            : m_prog_name{std::move(prog_name)}, m_pid{pid}
        {
            auto fd = open(m_prog_name.c_str(), O_RDONLY);
            m_elf = elf::elf{elf::create_mmap_loader(fd)};
            m_dwarf = dwarf::dwarf{dwarf::elf::create_loader(m_elf)};
        }
        void run();
        void set_breakpoint_at_address(std::intptr_t addr);
        void dump_registers();
        dwarf::die get_function_from_pc(uint64_t pc);
        dwarf::line_table::iterator get_line_entry_from_pc(uint64_t pc);
        void print_source(const std::string &fname, unsigned line, unsigned num_lines_context);

    private:
        void handle_command(const std::string &line);
        void continue_execution();
        uint64_t get_pc();
        void set_pc(uint64_t pc);
        void step_over_breakpoint();
        void wait_for_signal();
        void handle_sigtrap(siginfo_t info);
        uint64_t read_memory(uint64_t address);
        void write_memory(uint64_t address, uint64_t value);
        void initialise_load_address();
        uint64_t offset_load_address(uint64_t address);
        siginfo_t get_signal_info();

        std::string m_prog_name;
        pid_t m_pid;
        std::unordered_map<std::intptr_t, breakpoint> m_breakpoints;
        elf::elf m_elf;
        dwarf::dwarf m_dwarf;
        uint64_t m_load_address;
    };
}

#endif
