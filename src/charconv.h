/* charconv.h - Recode short filenames from DOS codepage

   Copyright (C) 2010 Alexander Korolkov <alexander.korolkov@gmail.com>
   Copyright (C) 2010-2013 Daniel Baumann <mail@daniel-baumann.ch>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License along
   with this program; if not, write to the Free Software Foundation, Inc.,
   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

   The complete text of the GNU General Public License
   can be found in /usr/share/common-licenses/GPL-2 file.
*/

#ifndef _CHARCONV_H
#define _CHARCONV_H

#define DEFAULT_DOS_CODEPAGE 437

int set_dos_codepage(int codepage);
int dos_char_to_printable(char **p, unsigned char c);

#endif
