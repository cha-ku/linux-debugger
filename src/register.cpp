#include "register.hpp"
#include <stdexcept>

namespace chakudbg {
    uint64_t get_register_value(pid_t pid, reg r) {
        auto index = static_cast<int>(r);
        user_regs_struct regs;
        ptrace(PTRACE_GETREGS, pid, nullptr, &regs);
        /*
        * This relies on the following -
        * 1. Pointer to struct points to the first element in struct, although this is not guaranteed
        *    for subsequent elements because of struct padding
        * 2. Order of elements in struct does not change
        * 3. Type of each element in the struct is same so so it's safe to do pointer arithematic.
        */
        auto* p_reg = reinterpret_cast<uint64_t*>(&regs);
        return *(p_reg + index);
    }

    void set_register_value(pid_t pid, reg r, uint64_t value) {
        user_regs_struct regs;
        ptrace(PTRACE_GETREGS, pid, nullptr, &regs);
        auto it = std::find_if(begin(g_register_descriptors) , end(g_register_descriptors),
                                            [r] (auto&& reg_desc) { return reg_desc.r == r; });
        auto index = it - begin(g_register_descriptors);
        auto* p_reg = reinterpret_cast<uint64_t*>(&regs);
        *(p_reg + index) = value;
        ptrace(PTRACE_SETREGS, pid, nullptr, &regs);
    }

    uint64_t get_register_value_from_dwarf_register(pid_t pid, int dw_reg_num) {
        auto it = std::find_if(begin(g_register_descriptors) , end(g_register_descriptors),
                                            [dw_reg_num] (auto&& reg_desc)
                                            { return reg_desc.dwarf_reg_num == dw_reg_num; });

        if (it == end(g_register_descriptors)) {
            throw std::out_of_range{"Unknown dwarf register!\n"};
        }

        return get_register_value(pid, it->r);
    }

    std::string get_register_name(reg r) {
        auto it = std::find_if(begin(g_register_descriptors), end(g_register_descriptors),
                        [r](auto&& rd) { return rd.r == r; });
        return it->name;
    }

    reg get_register_from_name(const std::string& name) {
        auto it = std::find_if(begin(g_register_descriptors), end(g_register_descriptors),
                            [name] (auto&& rd) { return rd.name == name; });
        return it->r;
    }
}
