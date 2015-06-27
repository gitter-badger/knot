/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <tap/basic.h>

#include "libknot/yparser/ypscheme.h"
#include "libknot/yparser/yptrafo.h"
#include "libknot/libknot.h"

#define C_ID		"\x02""id"
#define C_INT		"\x07""integer"
#define C_BOOL		"\x04""bool"
#define C_OPT		"\x06""option"
#define C_STR		"\x06""string"
#define C_ADDR		"\x07""address"
#define C_NET		"\x07""network"
#define C_DNAME		"\x06""domain"
#define C_BASE64	"\x06""base64"
#define C_REF		"\x09""reference"
#define C_GRP		"\x05""group"
#define C_MULTIGRP	"\x0B""multi-group"

static const yp_item_t group[] = {
	{ C_INT, YP_TINT, YP_VINT = { 0, 100, YP_NIL } },
	{ C_STR, YP_TSTR, YP_VNONE, YP_FMULTI },
	{ NULL }
};

static const yp_item_t multi_group[] = {
	{ C_ID,     YP_TSTR, YP_VNONE },
	{ C_BASE64, YP_TB64, YP_VNONE },
	{ NULL }
};

static const lookup_table_t opts[] = {
	{ 1,   "one" },
	{ 10,  "ten" },
	{ 0, NULL }
	};

static const yp_item_t static_scheme[] = {
	{ C_OPT,      YP_TOPT,  YP_VOPT = { opts } },
	{ C_BOOL,     YP_TBOOL, YP_VNONE },
	{ C_GRP,      YP_TGRP,  YP_VGRP = { group } },
	{ C_MULTIGRP, YP_TGRP,  YP_VGRP = { multi_group }, YP_FMULTI },
	{ C_REF,      YP_TREF,  YP_VREF = { C_MULTIGRP } },
	{ NULL }
};

static int scheme_find_test(void) {
	int ret;
	yp_item_t *scheme;

	ret = yp_scheme_copy(&scheme, static_scheme);
	ok(ret == KNOT_EOK, "scheme copy");

	const yp_item_t *i = yp_scheme_find(C_OPT, NULL, scheme);
	ok(i != NULL, "scheme find");
	if (i == NULL) {
		goto error_scheme;
	}
	ok(strcmp(i->name + 1, "option") == 0, "name check");
	i = yp_scheme_find(C_STR, C_GRP, scheme);
	ok(i != NULL, "scheme find");
	if (i == NULL) {
		goto error_scheme;
	}
	ok(strcmp(i->name + 1, "string") == 0, "name check");

	yp_scheme_free(scheme);

error_scheme:
	return 0;
}

#define SET_INPUT_STR(str) { \
	ret = yp_set_input_string(yp, str, strlen(str)); \
	ok(ret == KNOT_EOK, "set input string"); \
	}

#define PARSE_CHECK(depth) { \
	ret = yp_parse(yp); \
	ok(ret == KNOT_EOK, "parse"); \
	ret = yp_scheme_check_parser(ctx, yp); \
	ok(ret == KNOT_EOK, "check parser"); \
	node = &ctx->nodes[ctx->current]; \
	parent = node->parent; \
	ok(ctx->current == depth, "depth check"); \
	}

static int parser_test(void) {
	int ret;
	yp_item_t *scheme;
	yp_node_t *node;
	yp_node_t *parent;
	const yp_item_t *id;

	ret = yp_scheme_copy(&scheme, static_scheme);
	ok(ret == KNOT_EOK, "scheme copy");

	yp_parser_t yparser;
	yp_parser_t *yp = &yparser;
	yp_init(yp);

	yp_check_ctx_t *ctx = yp_scheme_check_init(scheme);
	ok(ctx != NULL, "create check ctx");
	if (ctx == NULL) {
		goto error_parser;
	}

	/* Key0 test. */
	diag("parser key0 test");
	SET_INPUT_STR("option: one");
	PARSE_CHECK(0);
	ok(strcmp(node->item->name + 1, "option") == 0, "name check");
	ok(node->item->type == YP_TOPT, "type check");
	ok(yp_opt(node->data) == 1, "value check");

	/* Boolean test. */
	diag("parser boolean test");
	SET_INPUT_STR("bool: true\nbool: on\nbool: false\nbool: off");
	for (int i = 0; i < 2; i++) {
		PARSE_CHECK(0);
		ok(strcmp(node->item->name + 1, "bool") == 0, "name check");
		ok(node->item->type == YP_TBOOL, "type check");
		ok(yp_bool(node->data) == true, "value check");
	}
	for (int i = 0; i < 2; i++) {
		PARSE_CHECK(0);
		ok(strcmp(node->item->name + 1, "bool") == 0, "name check");
		ok(node->item->type == YP_TBOOL, "type check");
		ok(yp_bool(node->data) == false, "value check");
	}

	/* Group test. */
	diag("parser group test");
	SET_INPUT_STR("group:\n integer: 20\n string: [short, \"long string\"]");
	PARSE_CHECK(0);
	ok(strcmp(node->item->name + 1, "group") == 0, "name check");
	ok(node->item->type == YP_TGRP, "type check");
	ok(node->data_len == 0, "value length check");
	PARSE_CHECK(1);
	ok(strcmp(node->item->name + 1, "integer") == 0, "name check");
	ok(node->item->type == YP_TINT, "type check");
	ok(yp_int(node->data, node->data_len) == 20, "value check");
	PARSE_CHECK(1);
	ok(strcmp(node->item->name + 1, "string") == 0, "name check");
	ok(node->item->type == YP_TSTR, "type check");
	ok(strcmp(yp_str(node->data), "short") == 0, "value check");
	PARSE_CHECK(1);
	ok(strcmp(node->item->name + 1, "string") == 0, "name check");
	ok(node->item->type == YP_TSTR, "type check");
	ok(strcmp(yp_str(node->data), "long string") == 0, "value check");

	/* Multi-group test. */
	diag("parser multi-group test");
	SET_INPUT_STR("multi-group:\n - id: foo\n   base64: Zm9vYmFy\nreference: foo");
	PARSE_CHECK(0);
	ok(strcmp(node->item->name + 1, "multi-group") == 0, "name check");
	ok(node->item->type == YP_TGRP, "type check");
	ok(node->data_len == 0, "value length check");
	PARSE_CHECK(0);
	ok(node->id_len > 0, "id check");
	ok(strcmp(node->item->name + 1, "multi-group") == 0, "name check");
	ok(node->item->type == YP_TGRP, "type check");
	ok(node->data_len == 0, "value length check");
	id = node->item->var.g.id;
	ok(strcmp(id->name + 1, "id") == 0, "name check");
	ok(id->type == YP_TSTR, "type check");
	ok(strcmp(yp_str(node->id), "foo") == 0, "value check");
	PARSE_CHECK(1);
	id = parent->item->var.g.id;
	ok(strcmp(parent->item->name + 1, "multi-group") == 0, "name check");
	ok(parent->item->type == YP_TGRP, "type check");
	ok(parent->data_len == 0, "value length check");
	ok(strcmp(yp_str(parent->id), "foo") == 0, "value check");
	ok(strcmp(id->name + 1, "id") == 0, "name check");
	ok(id->type == YP_TSTR, "type check");
	ok(strcmp(node->item->name + 1, "base64") == 0, "name check");
	ok(node->item->type == YP_TB64, "type check");
	ok(memcmp(node->data, "foobar", node->data_len) == 0, "value check");
	ok(node->id_len == 0, "id length check");
	PARSE_CHECK(0);
	ok(strcmp(node->item->name + 1, "reference") == 0, "name check");
	ok(node->item->type == YP_TREF, "type check");
	ok(strcmp(yp_str(node->data), "foo") == 0, "value check");

	yp_scheme_check_deinit(ctx);
	yp_deinit(yp);
	yp_scheme_free(scheme);

error_parser:
	return 0;
}

#define STR_CHECK(depth) { \
	ok(ret == KNOT_EOK, "check str"); \
	ok(ctx->current == depth, "depth check"); \
	node = &ctx->nodes[ctx->current]; \
	parent = node->parent; \
	}

static int str_test(void) {
	int ret;
	yp_item_t *scheme;
	yp_node_t *node;
	yp_node_t *parent;
	const yp_item_t *id;

	ret = yp_scheme_copy(&scheme, static_scheme);
	ok(ret == KNOT_EOK, "scheme copy");

	yp_check_ctx_t *ctx = yp_scheme_check_init(scheme);
	ok(ctx != NULL, "create check ctx");
	if (ctx == NULL) {
		goto error_str;
	}

	/* Key0 test. */
	diag("str key0 test");
	ret = yp_scheme_check_str(ctx, "option", "", "", "one");
	STR_CHECK(0);
	ok(strcmp(node->item->name + 1, "option") == 0, "name check");
	ok(node->item->type == YP_TOPT, "type check");
	ok(yp_opt(node->data) == 1, "value check");

	/* Group test. */
	diag("str group test");
	ret = yp_scheme_check_str(ctx, "group", "", "", "");
	STR_CHECK(0);
	ok(strcmp(node->item->name + 1, "group") == 0, "name check");
	ok(node->item->type == YP_TGRP, "type check");
	ok(node->data_len == 0, "value length check");
	ret = yp_scheme_check_str(ctx, "group", "integer", "", "20");
	STR_CHECK(1);
	ok(strcmp(node->item->name + 1, "integer") == 0, "name check");
	ok(node->item->type == YP_TINT, "type check");
	ok(yp_int(node->data, node->data_len) == 20, "value check");
	ret = yp_scheme_check_str(ctx, "group", "string", "", "short");
	STR_CHECK(1);
	ok(strcmp(node->item->name + 1, "string") == 0, "name check");
	ok(node->item->type == YP_TSTR, "type check");
	ok(strcmp(yp_str(node->data), "short") == 0, "value check");
	ret = yp_scheme_check_str(ctx, "group", "string", "", "long string");
	STR_CHECK(1);
	ok(strcmp(node->item->name + 1, "string") == 0, "name check");
	ok(node->item->type == YP_TSTR, "type check");
	ok(strcmp(yp_str(node->data), "long string") == 0, "value check");

	diag("str multi-group test");
	ret = yp_scheme_check_str(ctx, "multi-group", "", "", "");
	STR_CHECK(0);
	ok(strcmp(node->item->name + 1, "multi-group") == 0, "name check");
	ok(node->item->type == YP_TGRP, "type check");
	ok(node->data_len == 0, "value length check");
	ret = yp_scheme_check_str(ctx, "multi-group", "", "foo", "");
	STR_CHECK(0);
	ok(node->id_len > 0, "id check");
	ok(strcmp(node->item->name + 1, "multi-group") == 0, "name check");
	ok(node->item->type == YP_TGRP, "type check");
	ok(node->data_len == 0, "value length check");
	id = node->item->var.g.id;
	ok(strcmp(id->name + 1, "id") == 0, "name check");
	ok(id->type == YP_TSTR, "type check");
	ok(strcmp(yp_str(node->id), "foo") == 0, "value check");
	ret = yp_scheme_check_str(ctx, "multi-group", "base64", "foo", "Zm9vYmFy");
	STR_CHECK(1);
	id = parent->item->var.g.id;
	ok(strcmp(parent->item->name + 1, "multi-group") == 0, "name check");
	ok(parent->item->type == YP_TGRP, "type check");
	ok(parent->data_len == 0, "value length check");
	ok(strcmp(yp_str(parent->id), "foo") == 0, "value check");
	ok(strcmp(id->name + 1, "id") == 0, "name check");
	ok(id->type == YP_TSTR, "type check");
	ok(strcmp(node->item->name + 1, "base64") == 0, "name check");
	ok(node->item->type == YP_TB64, "type check");
	ok(memcmp(node->data, "foobar", node->data_len) == 0, "value check");
	ok(node->id_len == 0, "id length check");
	ret = yp_scheme_check_str(ctx, "reference", "", "", "foo");
	STR_CHECK(0);
	ok(strcmp(node->item->name + 1, "reference") == 0, "name check");
	ok(node->item->type == YP_TREF, "type check");
	ok(strcmp(yp_str(node->data), "foo") == 0, "value check");

	yp_scheme_check_deinit(ctx);
	yp_scheme_free(scheme);

error_str:
	return 0;
}

int main(int argc, char *argv[])
{
	plan_lazy();

	scheme_find_test();

	parser_test();

	str_test();

	return 0;
}
