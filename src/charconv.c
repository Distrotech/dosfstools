/* charconv.c - Recode short filenames from DOS codepage

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

#include "charconv.h"
#include <iconv.h>
#include <langinfo.h>
#include <locale.h>
#include <stdio.h>

static iconv_t iconv_init_codepage(int codepage)
{
    iconv_t result;
    char codepage_name[16];
    snprintf(codepage_name, sizeof(codepage_name), "CP%d", codepage);
    result = iconv_open(nl_langinfo(CODESET), codepage_name);
    if (result == (iconv_t) - 1)
	perror(codepage_name);
    return result;
}

static iconv_t dos_to_local;

/*
 * Initialize conversion from codepage.
 * codepage = -1 means default codepage.
 * Returns 0 on success, non-zero on failure
 */
static int init_conversion(int codepage)
{
    static int initialized = -1;
    if (initialized < 0) {
	initialized = 1;
	if (codepage < 0)
	    codepage = DEFAULT_DOS_CODEPAGE;
	setlocale(LC_ALL, "");	/* initialize locale */
	dos_to_local = iconv_init_codepage(codepage);
	if (dos_to_local == (iconv_t) - 1 && codepage != DEFAULT_DOS_CODEPAGE) {
	    printf("Trying to set fallback DOS codepage %d\n",
		   DEFAULT_DOS_CODEPAGE);
	    dos_to_local = iconv_init_codepage(DEFAULT_DOS_CODEPAGE);
	    if (dos_to_local == (iconv_t) - 1)
		initialized = 0;	/* no conversion available */
	}
    }
    return initialized;
}

int set_dos_codepage(int codepage)
{
    return init_conversion(codepage);
}

int dos_char_to_printable(char **p, unsigned char c)
{
    char in[1] = { c };
    char *pin = in;
    size_t bytes_in = 1;
    size_t bytes_out = 4;
    if (!init_conversion(-1))
	return 0;
    return iconv(dos_to_local, &pin, &bytes_in, p, &bytes_out) != -1;
}
