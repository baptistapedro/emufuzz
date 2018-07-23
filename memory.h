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

#include <algorithm>
#include <vector>
#include <stdexcept>

#include "util.h"

namespace emufuzz {

class AddressRange {
    private:
        uint64_t start, size;
    public:
        AddressRange(const uint64_t _start, const uint64_t _size);
        uint64_t Start(void) const;
        uint64_t Size(void) const;
        uint64_t End(void) const;

        /* Returns:
         *  0 if no intersection
         *  1 if partial intersection
         *  2 if complete intersection
         */
        int Intersects(const AddressRange other) const;
        bool IntersectsPartially(const AddressRange other) const;
        bool IntersectsCompletely(const AddressRange other) const;
};

class MemoryContents : public AddressRange {
    private:
        std::vector<uint8_t> data;
        std::vector<uint8_t> initialized;
    public:
        MemoryContents(const uint64_t _start, const std::vector<uint8_t> _data);
        std::vector<uint8_t> GetData(void) const;
        bool IsInitialized(const AddressRange range) const;
        uint64_t VirtualToLogical(const uint64_t address) const;
        void SetInitialized(const AddressRange range);
};

} /* namespace emufuzz */
