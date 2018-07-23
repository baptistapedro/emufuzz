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
#include "emulator_arm64.h"

#include "target_x64.h"
#include "target_arm64.h"

std::unordered_set<uint64_t>* PCS_ARM64 = nullptr;
std::unordered_set<uint64_t>* PCS_X64 = nullptr;

extern "C" int LLVMFuzzerInitialize(int *argc, char*** argv) {
    (void)argc;
    (void)argv;
    PCS_ARM64 = new std::unordered_set<uint64_t>;
    PCS_X64 = new std::unordered_set<uint64_t>;

    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    using namespace emufuzz;

    if ( size < 64 ) {
        return 0;
    }

    size_t totalCoverage = 0;

    {
        std::vector<uint8_t> param1(data, data + 32);
        std::vector<uint8_t> param2(data + 32, data + 64);

        EmulatorARM64 emu(
                /* code */
                MemoryContents(0x10000, std::vector<uint8_t>(target_arm64, target_arm64 + sizeof(target_arm64))),
                /* stack */
                MemoryContents(0x20000, std::vector<uint8_t>(4096, 0)),
                PCS_ARM64
                );
        emu.SetName("ARM64");

        /* Set function parameters */
        const std::vector<MemoryContents> parameters = {
            MemoryContents(0x30000, param1),
            MemoryContents(0x32000, param2)
        };

        emu.WriteParams(parameters);

        emu.Run(0);

        totalCoverage += emu.GetCoverage();
    }

    {
        std::vector<uint8_t> param1(data, data + 32);
        std::vector<uint8_t> param2(data + 32, data + 64);

        EmulatorX64 emu(
                /* code */
                MemoryContents(0x10000, std::vector<uint8_t>(target_x64, target_x64 + sizeof(target_x64))),
                /* stack */
                MemoryContents(0x20000, std::vector<uint8_t>(4096, 0)),
                PCS_X64
                );
        emu.SetName("X64");

        /* Set function parameters */
        const std::vector<MemoryContents> parameters = {
            MemoryContents(0x30000, param1),
            MemoryContents(0x32000, param2)
        };

        emu.WriteParams(parameters);

        emu.Run(0);

        totalCoverage += emu.GetCoverage();
    }

    return totalCoverage;

}
