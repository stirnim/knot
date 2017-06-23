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

#include <stdio.h>
#include <assert.h>

#include "knot/zone/contents.h"
#include "contrib/ucw/lists.h"
#include "utils/kzonecheck/zone_check.h"

int err_handler_printf(err_handler_t *handler, const zone_contents_t *zone,
			const zone_node_t *node, int error, const char *data, int severity)
{
	assert(handler != NULL);
	assert(zone != NULL);
	err_handler_stats_t *h = (err_handler_stats_t *)handler;

	const char *errmsg = semantic_check_error_msg(error);
	const char *sevstr = severity_to_str(severity);
	const char *type = node ? "record" : "zone";
	char *name = NULL;
	if (node) {
		name = knot_dname_to_str_alloc(node->owner);
	} else if (zone && zone->apex) {
		name = knot_dname_to_str_alloc(zone->apex->owner);
	}

	fprintf(h->outfile, "%s: %s '%s': %s%s%s%s\n", sevstr,
		type, name ? name : "?", errmsg, (data ? " (" : ""), (data ? data : ""),
		(data ? ")" : ""));

	free(name);

	if (severity == ZC_SEVERITY_ERROR) {
		h->errors[-error]++;
		h->error_count++;
	} else if (severity == ZC_SEVERITY_WARNING) {
		h->warn[-error]++;
		h->warn_count++;
	}

	return KNOT_EOK;
}

int err_handler_printf_nsec3(err_handler_t *handler, char *hash, const zone_contents_t *zone,
			const zone_node_t *node, int error, const char *data, int severity)
{
	assert(handler != NULL);
	assert(zone != NULL);
	err_handler_stats_t *h = (err_handler_stats_t *)handler;

	const char *errmsg = semantic_check_error_msg(error);

	const char *sevstr = severity_to_str(severity);
	const char *type = node ? "record" : "zone";
	char *name = NULL;
	if (node) {
		name = knot_dname_to_str_alloc(node->owner);
	} else if (zone && zone->apex) {
		name = knot_dname_to_str_alloc(zone->apex->owner);
	}

	fprintf(h->outfile, "%s: %s '%s' '%s': %s%s%s%s\n", sevstr, type, name ? name : "?", hash ? hash : "?",
		errmsg, (data ? " (" : ""), (data ? data : ""), (data ? ")" : ""));

	free(name);

	if (severity == ZC_SEVERITY_ERROR) {
		h->errors[-error]++;
		h->error_count++;
	} else if (severity == ZC_SEVERITY_WARNING) {
		h->warn[-error]++;
		h->warn_count++;
	}

	return KNOT_EOK;
}

static void print_statistics(err_handler_stats_t *handler)
{
	err_handler_stats_t *h = (err_handler_stats_t *)handler;
	if (h->error_count) {
		fprintf(h->outfile, "\nERROR SUMMARY:\n\tCount\tError\n");
		for(int i = ZC_ERR_UNKNOWN; i < ZC_ERR_LAST; ++i) {
			if (h->errors[-i] > 0) {
				fprintf(h->outfile, "\t%u\t%s\n", h->errors[-i],
					semantic_check_error_msg(i));
			}
		}
	}
	if (h->warn_count) {
		fprintf(h->outfile, "\nWARNING SUMMARY:\n\tCount\tWarning\n");
		for(int i = ZC_ERR_UNKNOWN; i < ZC_ERR_LAST; ++i) {
			if (h->warn[-i] > 0) {
				fprintf(h->outfile, "\t%u\t%s\n", h->warn[-i],
				semantic_check_error_msg(i));
			}
		}
	}
}

int zone_check(const char *zone_file, const knot_dname_t *zone_name,
	       FILE *outfile, time_t context)
{
	zloader_t zl;
	int ret = zonefile_open(&zl, zone_file, zone_name, true, context);
	if (ret != KNOT_EOK) {
		return ret;
	}

	err_handler_stats_t handler;
	memset(&handler, 0, sizeof(handler));
	handler._cb.cb = err_handler_printf;
	handler._cb.nsec3 = err_handler_printf_nsec3;
	handler.outfile = outfile;

	zl.err_handler = (err_handler_t *)&handler;
	zl.creator->master = true;

	zone_contents_t *contents;
	contents = zonefile_load(&zl);

	if (handler.error_count > 0) {
		ret = KNOT_ESEMCHECK;
	}

	print_statistics(&handler);

	zonefile_close(&zl);
	if (contents == NULL) {
		return KNOT_ERROR;
	}

	zone_contents_deep_free(&contents);

	return ret;
}
