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


#pragma once

#include "emulator.h"
#include "memory.h"

namespace emufuzz {

class EmulatorARM64 : public Emulator {
    private:
        int getPCReg(void) const override;
        int getStackReg(void) const override;
        const std::vector<int> getCallingConvention(void) const override;
        void printRegs(void) const override;
        bool isRet(const int inst) const override;
    public:
        EmulatorARM64(const MemoryContents code, const MemoryContents stack, std::unordered_set<uint64_t>* _PCS);
};

} /* namespace emufuzz */
