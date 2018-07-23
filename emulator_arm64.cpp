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


#include "emulator_arm64.h"

namespace emufuzz {

EmulatorARM64::EmulatorARM64(const MemoryContents code, const MemoryContents stack, std::unordered_set<uint64_t>* _PCS) :
    Emulator(code, stack, EMU_ARCH_ARM64, _PCS) {
    WriteReg(getStackReg(), stack.End());
}

int EmulatorARM64::getPCReg(void) const {
    return UC_ARM64_REG_PC;
}

int EmulatorARM64::getStackReg(void) const {
    return UC_X86_REG_RSP;
}

void EmulatorARM64::printRegs(void) const {
    printf("TODO\n");
}

const std::vector<int> EmulatorARM64::getCallingConvention(void) const {
    static const std::vector<int> regid_mapper = {
        UC_ARM64_REG_X0,
        UC_ARM64_REG_X1,
        UC_ARM64_REG_X2,
        UC_ARM64_REG_X3,
        UC_ARM64_REG_X4,
        UC_ARM64_REG_X5,
        UC_ARM64_REG_X6,
        UC_ARM64_REG_X7};
    return regid_mapper;
}

bool EmulatorARM64::isRet(const int inst) const {
    return inst == ARM64_INS_RET;
}

} /* namespace emufuzz */
