/*
    Copyright (C) 2018 Guido Vranken
    https://www.guidovranken.com/

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/


#include "emulator_x64.h"

namespace emufuzz {

EmulatorX64::EmulatorX64(const MemoryContents code, const MemoryContents stack, std::unordered_set<uint64_t>* _PCS) :
    Emulator(code, stack, EMU_ARCH_X64, _PCS) {
    WriteReg(getStackReg(), stack.End());
}

int EmulatorX64::getPCReg(void) const {
    return UC_X86_REG_RIP;
}

int EmulatorX64::getStackReg(void) const {
    return UC_X86_REG_RSP;
}

void EmulatorX64::printRegs(void) const {
    uint64_t rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp, r8, r9, r10, r11, r12, r13, r14, r15;

    uc_reg_read(uc, UC_X86_REG_RAX, &rax);
    uc_reg_read(uc, UC_X86_REG_RBX, &rbx);
    uc_reg_read(uc, UC_X86_REG_RCX, &rcx);
    uc_reg_read(uc, UC_X86_REG_RDX, &rdx);
    uc_reg_read(uc, UC_X86_REG_RSI, &rsi);
    uc_reg_read(uc, UC_X86_REG_RDI, &rdi);
    uc_reg_read(uc, UC_X86_REG_RBP, &rbp);
    uc_reg_read(uc, UC_X86_REG_RSP, &rsp);
    uc_reg_read(uc, UC_X86_REG_R8, &r8);
    uc_reg_read(uc, UC_X86_REG_R9, &r9);
    uc_reg_read(uc, UC_X86_REG_R10, &r10);
    uc_reg_read(uc, UC_X86_REG_R11, &r11);
    uc_reg_read(uc, UC_X86_REG_R12, &r12);
    uc_reg_read(uc, UC_X86_REG_R13, &r13);
    uc_reg_read(uc, UC_X86_REG_R14, &r14);
    uc_reg_read(uc, UC_X86_REG_R15, &r15);

    printf("RAX = 0x%lX\n", rax);
    printf("RBX = 0x%lX\n", rbx);
    printf("RCX = 0x%lX\n", rcx);
    printf("RDX = 0x%lX\n", rdx);
    printf("RSI = 0x%lX\n", rsi);
    printf("RDI = 0x%lX\n", rdi);
    printf("RBP = 0x%lX\n", rbp);
    printf("RSP = 0x%lX\n", rsp);
    printf("R8 = 0x%lX\n", r8);
    printf("R9 = 0x%lX\n", r9);
    printf("R10 = 0x%lX\n", r10);
    printf("R11 = 0x%lX\n", r11);
    printf("R12 = 0x%lX\n", r12);
    printf("R13 = 0x%lX\n", r13);
    printf("R14 = 0x%lX\n", r14);
    printf("R15 = 0x%lX\n", r15);
}

const std::vector<int> EmulatorX64::getCallingConvention(void) const {
    static const std::vector<int> regid_mapper = {
        UC_X86_REG_RDI,
        UC_X86_REG_RSI,
        UC_X86_REG_RDX,
        UC_X86_REG_RCX,
        UC_X86_REG_R8,
        UC_X86_REG_R9};
    return regid_mapper;
}

bool EmulatorX64::isRet(const int inst) const {
    return inst == X86_INS_RET;
}

} /* namespace emufuzz */
