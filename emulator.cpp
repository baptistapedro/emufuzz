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


#include "emulator.h"

namespace emufuzz {

namespace hooks {

void code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    (void)uc;

    Emulator* emu = static_cast<Emulator*>(user_data);

    const bool haveNewCoverage = emu->updateCoverage();

    {
        const size_t size_capped = size > 100 ? 100 : size;
        std::vector<uint8_t> bytes;
        emu->ReadMem(address, bytes, size_capped);

        cs_insn *insn = nullptr;

        bool stop = false;
        const size_t count = cs_disasm(emu->capstone_handle, bytes.data(), size_capped, address, 0, &insn);

        if ( count >= 1 ) {
            if ( emu->isRet(insn[0].id) && emu->ReadReg(emu->getStackReg()) == emu->stackRange.End() ) {
                /* Don't call emu->Stop() immediately, must free 'insn' first */
                stop = true;
            }

            if ( haveNewCoverage ) {
                printf("New PC (%s): 0x%lX:\t%s\t\t%s\n", emu->getName().c_str(), insn[0].address, insn[0].mnemonic, insn[0].op_str);
            }
        }

        cs_free(insn, count);

        if ( stop ) {
            emu->Stop();
        }
    }
}

void mem(uc_engine *uc, uc_mem_type type,
        uint64_t address, int size, int64_t value, void *user_data)
{
    (void)uc;
    (void)value;

    Emulator* emu = static_cast<Emulator*>(user_data);

    AddressRange range(address, size);
    if ( emu->IsCode(range) ) {
        throw std::runtime_error("Memory access to code section");
    }

    if ( emu->IsValidRange(range) == false ) {
        throw std::runtime_error("Memory access to unmapped section");
    }

    switch ( type ) {
        case UC_MEM_READ:
            if ( emu->IsInitialized(range) == false ) {
                throw std::runtime_error("Memory read of uninitialized data");
            }
            break;
        case UC_MEM_WRITE:
            emu->SetInitialized(range);
            break;
        default:
            break;
    }
}

} /* namespace hooks */

Emulator::Emulator(const MemoryContents code, const MemoryContents stack, const enum Arch _arch, std::unordered_set<uint64_t>* _PCS) :
    arch(_arch), codeRange(AddressRange(code)), stackRange(AddressRange(stack)), PCS(_PCS) {
    static const std::vector<enum Arch> validArch = {EMU_ARCH_X64, EMU_ARCH_ARM64};

    if ( std::find(validArch.begin(), validArch.end(), arch) == validArch.end() ) {
        throw std::runtime_error("Invalid architecture specified");
    }

    parameters.resize(6, 0);

    {
        cs_arch cs_arch;
        uc_arch uc_arch;
        cs_mode cs_mode;
        uc_mode uc_mode;

        switch ( arch ) {
            case EMU_ARCH_X64:
                cs_arch = CS_ARCH_X86;
                uc_arch = UC_ARCH_X86;
                cs_mode = CS_MODE_64;
                uc_mode = UC_MODE_64;
                break;
            case EMU_ARCH_ARM64:
                cs_arch = CS_ARCH_ARM64;
                uc_arch = UC_ARCH_ARM64;
                cs_mode = CS_MODE_ARM;
                uc_mode = UC_MODE_ARM;
                break;
            default:
                abort();
        }

        if ( cs_open(cs_arch, cs_mode, &capstone_handle) != CS_ERR_OK ) {
            throw std::runtime_error("Could not initialize Capstone");
        }
        if ( uc_open(uc_arch, uc_mode, &uc) ) {
            throw std::runtime_error("Could not initialize Unicorn");
        }
    }

    uc_initialized = true;

    MapAndWriteMem(code);
    MapAndWriteMem(stack);

    /* Set hooks */
    /* TODO code hook on all ranges? */
    uc_hook_add(uc, &tracer_instruction, UC_HOOK_CODE, (void*)hooks::code, this, codeRange.Start(), codeRange.End());
    uc_hook_add(uc, &tracer_mem_write, UC_HOOK_MEM_WRITE, (void*)hooks::mem, this, 1, 0);
    uc_hook_add(uc, &tracer_mem_read, UC_HOOK_MEM_READ, (void*)hooks::mem, this, 1, 0);
}

Emulator::~Emulator() {
    uc_initialized = false;
    cs_close(&capstone_handle);
    uc_close(uc);
}

void Emulator::addMemoryContents(const MemoryContents& mc) {
    for ( const auto& curMC : memories ) {
        if ( curMC.Intersects(mc) != 0 ) {
            throw std::runtime_error("Ranges overlap");
        }
    }
    memories.push_back(mc);
}

bool Emulator::updateCoverage(void) {
    const size_t oldPCSSize = PCS->size();
    PCS->insert(ReadReg(getPCReg()));
    return PCS->size() > oldPCSSize;
}

void Emulator::unicorn_error(const uc_err err) const {
    if ( err ) {
        if ( uc_initialized ) {
            printRegs();
        }
        throw std::runtime_error("Could not call Unicorn function. Error is " + std::string(uc_strerror(err)) );
    }
}

void Emulator::Run(const uint64_t PC) {
    if ( PC > codeRange.End() || codeRange.Start() + PC > codeRange.End() ) {
        throw std::runtime_error("Invalid PC");
    }

    for (size_t i = 0; i < 6; i++) {
        const std::vector<int> regid_mapper = getCallingConvention();

        WriteReg(regid_mapper[i], parameters[i]);
    }

    unicorn_error( uc_emu_start(uc, codeRange.Start() + PC, codeRange.End(), 0, 0) );
}

void Emulator::Stop(void) {
    unicorn_error( uc_emu_stop(uc) );
}

void Emulator::MemMap(const uint64_t address, const size_t size) {
    /* TODO overflow check ? */
    unicorn_error( uc_mem_map(uc, address, size, UC_PROT_ALL) );
}

void Emulator::WriteMem(const uint64_t address, const uint64_t data) {
    std::vector<uint8_t> datavec((uint8_t*)(&data), (uint8_t*)(&data) + sizeof(data));
    WriteMem(address, datavec);
}

void Emulator::WriteMem(const uint64_t address, const std::vector<uint8_t> data) {
    unicorn_error( uc_mem_write(uc, address, data.data(), data.size()) );
}

void Emulator::WriteMem(const MemoryContents data) {
    WriteMem(data.Start(), data.GetData());
}

void Emulator::MapAndWriteMem(const MemoryContents data) {
    addMemoryContents(data);
    MemMap(data.Start(), data.Size());
    WriteMem(data.Start(), data.GetData());
}

void Emulator::WriteParam(const MemoryContents data, const size_t paramIdx) {
    WriteMem(data);

    if ( paramIdx > 5 ) {
        throw std::runtime_error("Invalid parameter index");
    }

    parameters[paramIdx] = data.Start();
}

void Emulator::WriteParams(const std::vector<MemoryContents> params) {
    if ( params.size() > 6 ) {
        throw std::runtime_error("Too many parameters specified");
    }

    size_t paramIdx = 0;
    for (const auto& param : params ) {
        addMemoryContents(param);
        MemMap(param.Start(), param.Size());
        WriteParam(param, paramIdx);
        paramIdx++;
    }
}

void Emulator::ReadMem(const uint64_t address, std::vector<uint8_t>& data, const size_t size) {
    data.resize(size);
    unicorn_error( uc_mem_read(uc, address, data.data(), size) );
}

uint64_t Emulator::ReadReg(const int regid) {
    uint64_t ret = 0;
    unicorn_error( uc_reg_read(uc, regid, &ret) );

    return ret;
}

void Emulator::WriteReg(const int regid, const uint64_t val) {
    unicorn_error( uc_reg_write(uc, regid, &val) );
}

bool Emulator::IsCode(const AddressRange range) const {
    return codeRange.Intersects(range) != 0;
}

bool Emulator::IsValidRange(const AddressRange range) const {
    bool intersected = false;
    for ( const auto& curMC : memories ) {
        if ( curMC.IntersectsCompletely(range) ) {
            intersected = true;
            break;
        }
    }

    return intersected;
}

bool Emulator::IsInitialized(const AddressRange range) const {
    for ( const auto& curMC : memories ) {
        if ( curMC.IntersectsCompletely(range) ) {
            return curMC.IsInitialized(range);
        }
    }

    throw std::runtime_error("IsInitialized:: Range not matched");
}

void Emulator::SetInitialized(const AddressRange range) {
    for ( auto& curMC : memories ) {
        if ( curMC.IntersectsCompletely(range) ) {
            curMC.SetInitialized(range);
            return;
        }
    }

    throw std::runtime_error("SetInitialized:: Range not matched");
}

size_t Emulator::GetCoverage(void) const {
    return PCS->size();
}

void Emulator::SetName(const std::string _name) {
    name = _name;
}

std::string Emulator::getName(void) const {
    return name;
}

} /* namespace emufuzz */
