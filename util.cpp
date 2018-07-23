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


#include "util.h"

namespace emufuzz {
namespace util {

bool uint64_overflow(const uint64_t a, const uint64_t b) {
    uint64_t x = a + b;
    if ( x < a ) {
        return true;
    } else {
        return false;
    }
}

size_t aligned_size(const size_t size) {
    return ((size + 4095) / 4096) * 4096;
}

std::vector<uint8_t> align(std::vector<uint8_t> data) {
    /* Round up to the nearest 4096 byte boundary */
    data.resize(aligned_size(data.size()), 0);
    return data;
}

} /* namespace util */
} /* namespace emufuzz */
