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


#include "memory.h"
#include "util.h"
#include <string.h>

namespace emufuzz {

AddressRange::AddressRange(const uint64_t _start, const uint64_t _size) {
    if ( util::uint64_overflow(_start, _size) ) {
        throw std::runtime_error("AddressRange: size overflow");
    }

    start = _start;
    size = _size;
}

uint64_t AddressRange::Start(void) const {
    return start;
}

uint64_t AddressRange::Size(void) const {
    return size;
}

uint64_t AddressRange::End(void) const {
    return start + size;
}

/* Returns:
 *  0 if no intersection
 *  1 if partial intersection
 *  2 if complete intersection
 */
int AddressRange::Intersects(const AddressRange other) const {
    if ( std::max(other.Start(), Start()) <= std::min(other.End(), End()) ) {
        if ( other.Start() >= Start() && other.End() <= End() ) {
            return 2;
        } else {
            return 1;
        }
    } else {
        return 0;
    }
}

bool AddressRange::IntersectsPartially(const AddressRange other) const {
    return Intersects(other) == 1;
}

bool AddressRange::IntersectsCompletely(const AddressRange other) const {
    return Intersects(other) == 2;
}

MemoryContents::MemoryContents(const uint64_t _start, const std::vector<uint8_t> _data) :
    AddressRange(_start, util::aligned_size(_data.size())) {
    const size_t orig_size = _data.size();
    data = util::align(_data);

    /* some asserts that should always be true */
    if ( data.size() != Size() ) {
        throw std::runtime_error("Unexpected condition. This is a bug.");
    }
    if ( data.size() < orig_size ) {
        throw std::runtime_error("Unexpected condition. This is a bug.");
    }

    initialized.resize(data.size(), 0);
    memset(initialized.data(), 1, orig_size);
}

std::vector<uint8_t> MemoryContents::GetData(void) const {
    return data;
}

bool MemoryContents::IsInitialized(const AddressRange range) const {
    for (uint64_t i = range.Start(); i < range.End(); i++) {
        const uint64_t index = VirtualToLogical(i);
        if ( index > initialized.size() ) {
            throw std::runtime_error("IsInitialized: index out of bounds");
        }
        if ( initialized[index] == 0 ) {
            return false;
        }
    }

    return true;
}

uint64_t MemoryContents::VirtualToLogical(const uint64_t address) const {
    return address - Start();
}

void MemoryContents::SetInitialized(const AddressRange range) {
    for (uint64_t i = range.Start(); i < range.End(); i++) {
        const uint64_t index = VirtualToLogical(i);
        if ( index > initialized.size() ) {
            throw std::runtime_error("SetInitialized: index out of bounds");
        }
        initialized[index] = 1;
    }
}

} /* namespace emufuzz */
