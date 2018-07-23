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


unsigned char target_arm64[] = {
  0x02, 0x00, 0x40, 0x39, 0x5f, 0x04, 0x00, 0x71, 0x40, 0x00, 0x00, 0x54,
  0xc0, 0x03, 0x5f, 0xd6, 0x02, 0x04, 0x40, 0x39, 0x5f, 0x08, 0x00, 0x71,
  0xa1, 0xff, 0xff, 0x54, 0x00, 0x7c, 0x40, 0x39, 0x1f, 0x0c, 0x00, 0x71,
  0x41, 0xff, 0xff, 0x54, 0x3f, 0x7c, 0x00, 0xa9, 0x3f, 0x7c, 0x01, 0xa9,
  0xc0, 0x03, 0x5f, 0xd6
};
unsigned int target_len = 52;
