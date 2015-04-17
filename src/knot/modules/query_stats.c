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
#include <jansson.h>

#include "libknot/libknot.h"
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

struct query_stats_opcode {
	uint64_t query;
	uint64_t iquery;
	uint64_t status;
	uint64_t notify;
	uint64_t update;
};

struct query_stats_rcode {
	uint64_t ok;
	uint64_t formerr;
	uint64_t servfail;
	uint64_t nxdomain;
	uint64_t notimpl;
	uint64_t refused;
	uint64_t yxdomain;
	uint64_t yxrrset;
	uint64_t nxrrset;
	uint64_t notauth;
	uint64_t notzone;
	uint64_t badvers;
	uint64_t tsig_badsig;
	uint64_t tsig_badkey;
	uint64_t tsig_badtime;
	uint64_t tsig_badtrunc;
};

struct query_stats_pkt_type {
	uint64_t invalid;
	uint64_t normal;
	uint64_t axfr;
	uint64_t ixfr;
	uint64_t notify;
	uint64_t update;
};

struct query_stats {
	uint64_t query;
	struct query_stats_opcode qso;
	struct query_stats_rcode qsr;
	struct query_stats_pkt_type qspt;
};

struct query_stats_ctx {
	const char *dump_file;
	struct query_stats qs;
};

static void count_opcode(struct query_data *qdata, struct query_stats_opcode *qso)
{
	switch (knot_wire_get_opcode(qdata->query->wire)) {
	case KNOT_OPCODE_QUERY:
		qso->query++;
		break;
	case KNOT_OPCODE_IQUERY:
		qso->iquery++;
		break;
	case KNOT_OPCODE_STATUS:
		qso->status++;
		break;
	case KNOT_OPCODE_NOTIFY:
		qso->notify++;
		break;
	case KNOT_OPCODE_UPDATE:
		qso->update++;
		break;
	}
}

static void count_not_auth(struct query_data *qdata, struct query_stats_rcode *qsr)
{
	switch (qdata->rcode_tsig) {
	case KNOT_TSIG_ERR_BADSIG:
		qsr->tsig_badsig++;
		break;
	case KNOT_TSIG_ERR_BADKEY:
		qsr->tsig_badkey++;
		break;
	case KNOT_TSIG_ERR_BADTIME:
		qsr->tsig_badtime++;
		break;
	case KNOT_TSIG_ERR_BADTRUNC:
		qsr->tsig_badtrunc++;
		break;
	}
}

static void count_rcode(struct query_data *qdata, struct query_stats_rcode *qsr)
{
	switch (qdata->rcode) {
	case KNOT_RCODE_NOERROR:
		qsr->ok++;
		break;
	case KNOT_RCODE_FORMERR:
		qsr->formerr++;
		break;
	case KNOT_RCODE_SERVFAIL:
		qsr->servfail++;
		break;
	case KNOT_RCODE_NXDOMAIN:
		qsr->nxdomain++;
		break;
	case KNOT_RCODE_NOTIMPL:
		qsr->notimpl++;
		break;
	case KNOT_RCODE_REFUSED:
		qsr->refused++;
		break;
	case KNOT_RCODE_YXDOMAIN:
		qsr->yxdomain++;
		break;
	case KNOT_RCODE_YXRRSET:
		qsr->yxrrset++;
		break;
	case KNOT_RCODE_NXRRSET:
		qsr->nxrrset++;
		break;
	case KNOT_RCODE_NOTAUTH:
		qsr->notauth++;
		count_not_auth(qdata, qsr);
		break;
	case KNOT_RCODE_NOTZONE:
		qsr->notzone++;
		break;
	case KNOT_RCODE_BADVERS:
		qsr->badvers++;
		break;
	}
}

static void count_pkt_type(struct query_data *qdata, struct query_stats_pkt_type *qspt)
{
	switch(qdata->packet_type) {
	case KNOT_QUERY_INVALID:
		qspt->invalid++;
		break;
	case KNOT_QUERY_NORMAL:
		qspt->normal++;
		break;
	case KNOT_QUERY_AXFR:
		qspt->axfr++;
		break;
	case KNOT_QUERY_IXFR:
		qspt->ixfr++;
		break;
	case KNOT_QUERY_NOTIFY:
		qspt->notify++;
		break;
	case KNOT_QUERY_UPDATE:
		qspt->update++;
		break;
	}
}

static int count(int state, knot_pkt_t *pkt, struct query_data *qdata, void *ctx)
{
	if (pkt == NULL || qdata == NULL || ctx == NULL) {
		return KNOT_STATE_FAIL;
	}

	struct query_stats_ctx *qsc = ctx;
	struct query_stats *qs = &qsc->qs;

	qs->query++;
	
	count_opcode(qdata, &qs->qso);
	count_rcode(qdata, &qs->qsr);
	count_pkt_type(qdata, &qs->qspt);

	return KNOT_STATE_DONE;
}

static json_t *build_json_opcode_stats(struct query_stats_opcode *qso)
{
	json_t *opcode_stats = json_pack("{s:i s:i s:i s:i s:i}",
	                                   "query",   qso->query,
	                                   "iquery",  qso->iquery,
	                                   "status",  qso->status,
	                                   "notify",  qso->notify,
	                                   "update",  qso->update);
	return opcode_stats;
}

static json_t *build_json_rcode_stats(struct query_stats_rcode *qsr)
{
	json_t *rcode_stats = json_pack("{s:i s:i s:i s:i s:i s:i s:i s:i " \
	                                "s:i s:i s:i s:i s:i s:i s:i s:i}",
	                                "ok",            qsr->ok,
	                                "formerr",       qsr->formerr,
	                                "servfail",      qsr->servfail,
	                                "nxdomain",      qsr->nxdomain,
	                                "notimpl",       qsr->notimpl,
	                                "refused",       qsr->refused,
	                                "yxdomain",      qsr->yxdomain,
	                                "yxrrset",       qsr->yxrrset,
	                                "nxrrset",       qsr->nxrrset,
	                                "notauth",       qsr->notauth,
	                                "notzone",       qsr->notzone,
	                                "badvers",       qsr->badvers,
	                                "tsig_badsig",   qsr->tsig_badsig,
	                                "tsig_badkey",   qsr->tsig_badkey,
	                                "tsig_badtime",  qsr->tsig_badtime,
	                                "tsig_badtrunc", qsr->tsig_badtrunc);

	return rcode_stats;
}

static json_t *build_json_pkt_type_stats(struct query_stats_pkt_type *qspt)
{
	json_t *pkt_type_stats = json_pack("{s:i s:i s:i s:i s:i s:i}",
	                                   "invalid", qspt->invalid,
	                                   "normal",  qspt->normal,
	                                   "axfr",    qspt->axfr,
	                                   "ixfr",    qspt->ixfr,
	                                   "notify",  qspt->notify,
	                                   "update",  qspt->update);
	return pkt_type_stats;
}

static json_t *build_json_stats(struct query_stats *qs)
{
	json_t *root = json_object();
	json_t *opcodes = build_json_opcode_stats(&qs->qso);
	json_object_set_new(root, "opcodes", opcodes);
	json_t *pkt_types = build_json_pkt_type_stats(&qs->qspt);
	json_object_set_new(root, "packet types", pkt_types);
	json_t *rcodes = build_json_rcode_stats(&qs->qsr);
	json_object_set_new(root, "rcodes", rcodes);

	return root;
}

static void dump_json_stats(struct query_stats_ctx *qsc)
{
	struct query_stats *qs = &qsc->qs;

	json_t *root = build_json_stats(qs);

	json_dump_file(root, qsc->dump_file, JSON_INDENT(4) | JSON_PRESERVE_ORDER);
	json_decref(root);
}

int query_stats_load(struct query_plan *plan, struct query_module *self)
{
	struct query_stats_ctx *qsc = mm_alloc(self->mm, sizeof(struct query_stats_ctx));
	if (qsc == NULL) {
		MODULE_ERR("not enough memory");
		return KNOT_ENOMEM;
	}
	memset(qsc, 0, sizeof(struct query_stats_ctx));
	self->ctx = qsc;

	conf_val_t val = conf_mod_get(self->config, MOD_FILE, self->id);
	if (val.code != KNOT_EOK) {
		if (val.code == KNOT_EINVAL) {
			MODULE_ERR("no file for '%s'", self->id->data);
		}
		return val.code;
	}
	qsc->dump_file = conf_str(&val);

	return query_plan_step(plan, QPLAN_END, count, self->ctx);
}

int query_stats_unload(struct query_module *self)
{
	struct query_stats_ctx *qsc = self->ctx;

	dump_json_stats(qsc);

	mm_free(self->mm, self->ctx);
	return KNOT_EOK;
}
