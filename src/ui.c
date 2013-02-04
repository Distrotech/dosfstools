/* ui.c - Functions for handling the UI interface

   Copyright (C) 2013 Manoel Trapier <godzil@godzil.net>

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program. If not, see <http://www.gnu.org/licenses/>.

   The complete text of the GNU General Public License
   can be found in /usr/share/common-licenses/GPL-3 file.
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <time.h>
#include <unistd.h>

#define MAX_BAR (50)

int output_ui_fd, output_ui;
static uint16_t current_pass = 0;
static const char rotator[] = "|/-\\";

static char *cur_device;

static void ui_print_text(char *text)
{
    if (output_ui == 1) {
	if (output_ui_fd < 0) {
	    write(-output_ui_fd, text, strlen(text));
	    fsync(-output_ui_fd);
	} else if (output_ui_fd == 0) {
	    write(1, text, strlen(text));
	    fsync(1);
	} else {
	    write(output_ui_fd, text, strlen(text));
	    fsync(output_ui_fd);
	}
    }
}

void ui_print_new_pass(char *text)
{
    if (output_ui == 1) {
	char buffer[256];
	current_pass++;
	sprintf(buffer, "Pass %d: %s\n", current_pass, text);
	ui_print_text(buffer);
    }
}

void ui_print_progress(int pos, int max)
{
    if (output_ui == 1) {
	char buffer[256];
	static uint8_t last_car = 0;

	if (output_ui_fd == 0) {
	    double percent = ((double)pos / (double)max) * 100.0;
	    char bar[60];
	    uint32_t nbbar = (pos * MAX_BAR) / max;
	    uint32_t i;
	    memset(bar, 0, 60);
	    for (i = 0; i < MAX_BAR; i++) {
		if (i < nbbar)
		    bar[i] = '=';
		else
		    bar[i] = ' ';
	    }
	    sprintf(buffer, "|%s %c %2.1f%%\r", bar, rotator[last_car],
		    percent);
	    last_car = (last_car + 1) % 4;
	} else {
	    sprintf(buffer, "%d %d %d %s\n", current_pass, pos, max,
		    cur_device);
	}
	ui_print_text(buffer);
    }
}

void ui_set_device(char *device)
{
    cur_device = device;
}
