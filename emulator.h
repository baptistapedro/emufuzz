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

#include <unicorn/unicorn.h>
#include <capstone/capstone.h>
#include <vector>
#include <unordered_set>
#include "memory.h"

namespace emufuzz {

namespace hooks {
void code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void mem(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);
} /* namespace hooks */

class Emulator {
    public:
        enum Arch {
            EMU_ARCH_X64,
            EMU_ARCH_ARM64,
        };
    protected:
        enum Arch arch;
        uc_engine *uc = nullptr;
        bool uc_initialized = false;

        AddressRange codeRange, stackRange;

        uc_hook tracer_instruction, tracer_mem_write, tracer_mem_read;
        std::vector<uint64_t> parameters;
        csh capstone_handle = { 0 };

        void unicorn_error(const uc_err err) const;

        void addMemoryContents(const MemoryContents& mc);
        std::vector<MemoryContents> memories;

        std::unordered_set<uint64_t>* PCS = nullptr;
        bool updateCoverage(void);
        virtual void printRegs(void) const = 0;
        virtual int getPCReg(void) const = 0;
        virtual int getStackReg(void) const = 0;
        virtual const std::vector<int> getCallingConvention(void) const = 0;
        virtual bool isRet(const int inst) const = 0;
        std::string name;
        std::string getName(void) const;
    public:

        Emulator(const MemoryContents code, const MemoryContents stack, const enum Arch _arch, std::unordered_set<uint64_t>* _PCS);
        ~Emulator();
        void Run(const uint64_t PC);
        void Stop(void);
        void MemMap(const uint64_t address, const size_t size);
        void WriteMem(const uint64_t address, const uint64_t data);
        void WriteMem(const uint64_t address, const std::vector<uint8_t> data);
        void WriteMem(const MemoryContents data);
        void MapAndWriteMem(const MemoryContents data);
        void WriteParam(const MemoryContents data, const size_t paramIdx);
        void WriteParams(const std::vector<MemoryContents> params);
        void ReadMem(const uint64_t address, std::vector<uint8_t>& data, const size_t size);
        uint64_t ReadReg(const int regid);
        void WriteReg(const int regid, const uint64_t val);

        bool IsCode(const AddressRange range) const;
        bool IsValidRange(const AddressRange range) const;
        bool IsInitialized(const AddressRange range) const;
        void SetInitialized(const AddressRange range);

        size_t GetCoverage(void) const;

        void SetName(const std::string _name);

        friend void hooks::code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
        friend void hooks::mem(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);
};

} /* namespace emufuzz */
