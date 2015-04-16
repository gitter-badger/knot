/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "knot/common/log.h"
#include "knot/nameserver/process_query.h"
#include "knot/modules/query_stats.h"

#define MODULE_ERR(msg...) log_error("module 'query_stats', " msg)

/* Module configuration scheme. */
#define MOD_FILE "\x04""file"

const yp_item_t scheme_mod_query_stats[] = {
	{ C_ID,      YP_TSTR, YP_VNONE },
	{ MOD_FILE,  YP_TSTR, YP_VNONE },
	{ C_COMMENT, YP_TSTR, YP_VNONE },
	{ NULL }
};

struct query_stats {
	unsigned long queries;
};

static int count(int state, knot_pkt_t *pkt, struct query_data *qdata, void *ctx)
{
	if (pkt == NULL || qdata == NULL || ctx == NULL) {
		return KNOT_STATE_FAIL;
	}
	
	struct query_stats *qs = ctx;
	
	qs->queries++;
	
	return KNOT_EOK;
}

int query_stats_load(struct query_plan *plan, struct query_module *self)
{
	struct query_stats *qs = mm_alloc(self->mm, sizeof(struct query_stats));
	if (qs == NULL) {
		MODULE_ERR("not enough memory");
		return KNOT_ENOMEM;
	}
	memset(qs, 0, sizeof(struct query_stats));
	
	self->ctx = qs;

	return query_plan_step(plan, QPLAN_BEGIN, count, self->ctx);
}

int query_stats_unload(struct query_module *self)
{
	//FILE *f = fopen("/tmp/query_stats", "w");
	//fprintf(f, "Queries: %lu\n", ((struct query_stats*) self->ctx)->queries);
	//fclose(f);
	printf("Queries: %lu\n", ((struct query_stats*) self->ctx)->queries);
	
	mm_free(self->mm, self->ctx);
	return KNOT_EOK;
}
