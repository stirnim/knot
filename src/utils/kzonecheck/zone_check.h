/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include "libknot/libknot.h"
#include "knot/zone/zonefile.h"

typedef struct {
	err_handler_t _cb;
	FILE *outfile;
	unsigned errors[(-ZC_ERR_UNKNOWN) + 1]; /*!< Counting errors by type */
	unsigned error_count; /*!< Total error count */
	unsigned warn[(-ZC_ERR_UNKNOWN) + 1]; /*!< Counting warnings by type */
	unsigned warn_count; /*!< Total warning count */
} err_handler_stats_t;

int zone_check(const char *zone_file, const knot_dname_t *zone_name,
               FILE *outfile, time_t time);
