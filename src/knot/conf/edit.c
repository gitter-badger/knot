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

#include <assert.h>
#include <pthread.h>

#include "knot/conf/confdb.h"
#include "knot/conf/edit.h"
#include "libknot/yparser/yptrafo.h"

int conf_edit_start(
	void)
{
	assert(conf() != NULL);

	// Check for no edit mode.
	if (conf()->edit.active) {
		return KNOT_CONF_EEDITABLE;
	}

	// Open edit transaction.
	int ret = conf()->api->txn_begin(conf()->db, &conf()->edit.txn, 0);
	if (ret != KNOT_EOK) {
		return ret;
	}

	conf()->edit.active = true;

	return KNOT_EOK;
}

int conf_edit_commit(
	void)
{
	assert(conf() != NULL);

	// Check for edit mode.
	if (!conf()->edit.active) {
		return KNOT_CONF_ENOTEDITABLE;
	}

	// Commit edit transaction.
	int ret = conf()->api->txn_commit(&conf()->edit.txn);
	if (ret != KNOT_EOK) {
		return ret;
	}

	conf()->edit.active = false;

	// Clone new configuration.
	conf_t *new_conf = NULL;
	ret = conf_clone(&new_conf);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Update read-only transaction.
	new_conf->api->txn_abort(&new_conf->read_txn);
	ret = new_conf->api->txn_begin(new_conf->db, &new_conf->read_txn,
	                               NAMEDB_RDONLY);
	if (ret != KNOT_EOK) {
		conf_free(new_conf, true);
		return ret;
	}

	// Run post-open config operations.
	ret = conf_post_open(new_conf);
	if (ret != KNOT_EOK) {
		conf_free(new_conf, true);
		return ret;
	}

	// Update to the new config.
	conf_update(new_conf);

	return KNOT_EOK;
}

int conf_edit_abort(
	void)
{
	assert(conf() != NULL);

	// Check for edit mode.
	if (!conf()->edit.active) {
		return KNOT_CONF_ENOTEDITABLE;
	}

	// Abort edit transaction.
	conf()->api->txn_abort(&conf()->edit.txn);

	conf()->edit.active = false;

	return KNOT_EOK;
}

int conf_edit_set(
	const char *key0,
	const char *key1,
	const char *id,
	const char *data)
{
	assert(conf() != NULL);

	// Check for edit mode.
	if (!conf()->edit.active) {
		return KNOT_CONF_ENOTEDITABLE;
	}

	yp_check_ctx_t *ctx = yp_scheme_check_init(conf()->scheme);
	if (ctx == NULL) {
		return KNOT_ENOMEM;
	}

	// Check input.
	int ret = yp_scheme_check_str(ctx, key0, key1, id, data);
	if (ret != KNOT_EOK) {
		yp_scheme_check_deinit(ctx);
		return ret;
	}

	// Store data into db.
	ret = conf_db_set(conf(), &conf()->edit.txn, ctx);

	yp_scheme_check_deinit(ctx);

	return ret;
}

int conf_edit_del(
	const char *key0,
	const char *key1,
	const char *id,
	const char *data)
{
	assert(conf() != NULL);

	// Check for edit mode.
	if (!conf()->edit.active) {
		return KNOT_CONF_ENOTEDITABLE;
	}

	yp_check_ctx_t *ctx = yp_scheme_check_init(conf()->scheme);
	if (ctx == NULL) {
		return KNOT_ENOMEM;
	}

	// Check input.
	int ret = yp_scheme_check_str(ctx, key0, key1, id, data);
	if (ret != KNOT_EOK) {
		yp_scheme_check_deinit(ctx);
		return ret;
	}

	// Delete data from db.
	ret = conf_db_del(conf(), &conf()->edit.txn, ctx);

	yp_scheme_check_deinit(ctx);

	return ret;
}

int conf_edit_get(
	const char *key0,
	const char *key1,
	const char *id,
	bool get_current,
	conf_edit_get_f *fcn,
	conf_edit_get_params_t *params)
{
	if (fcn == NULL || params == NULL) {
		return KNOT_EINVAL;
	}

	assert(conf() != NULL);

	// Check for edit mode.
	if (!conf()->edit.active && !get_current) {
		return KNOT_CONF_ENOTEDITABLE;
	}

	yp_check_ctx_t *ctx = yp_scheme_check_init(conf()->scheme);
	if (ctx == NULL) {
		return KNOT_ENOMEM;
	}

	// Check input.
	int ret = yp_scheme_check_str(ctx, key0, key1, id, NULL);
	if (ret != KNOT_EOK) {
		goto get_error;
	}

	namedb_txn_t *txn = get_current ? &conf()->read_txn : &conf()->edit.txn;

	yp_node_t *node = &ctx->nodes[ctx->current];
	yp_node_t *parent = node->parent;

	// Get specific item data.
	if (parent != NULL) {
		conf_val_t bin;
		ret = conf_db_get(conf(), txn, ctx, &bin);
		if (ret != KNOT_EOK) {
			goto get_error;
		}

		params->key0 = parent->item;
		params->key1 = node->item;
		params->id = parent->id;
		params->id_len = parent->id_len;
		params->data = &bin;

		ret = fcn(params);
		if (ret != KNOT_EOK) {
			goto get_error;
		}
	// Get identifiers from the specific group.
	} else if (node->item->flags & YP_FMULTI && node->id_len == 0) {
		conf_iter_t iter;
		ret = conf_db_iter_begin(conf(), txn, node->item->name, &iter);
		if (ret != KNOT_EOK) {
			goto get_error;
		}

		while (ret == KNOT_EOK) {
			uint8_t *id;
			size_t id_len;
			ret = conf_db_iter_id(conf(), &iter, &id, &id_len);
			if (ret != KNOT_EOK) {
				conf_db_iter_finish(conf(), &iter);
				goto get_error;
			}

			params->key0 = node->item;
			params->key1 = NULL;
			params->id = id;
			params->id_len = id_len;
			params->data = NULL;

			ret = fcn(params);
			if (ret != KNOT_EOK) {
				conf_db_iter_finish(conf(), &iter);
				goto get_error;
			}

			ret = conf_db_iter_next(conf(), &iter);
		}

		conf_db_iter_finish(conf(), &iter);
	// Get group (block) items.
	} else {
		yp_item_t *item;
		for (item = node->item->sub_items; item->name != NULL; item++) {
			// Skip identifier item.
			if ((node->item->flags & YP_FMULTI) &&
			    node->item->var.g.id == item) {
				continue;
			}

			char *tmp_key1 = strndup(item->name + 1, item->name[0]);
			ret = conf_edit_get(key0, tmp_key1, id, get_current,
			                    fcn, params);
			free(tmp_key1);
			if (ret != KNOT_EOK && ret != KNOT_ENOENT) {
				goto get_error;
			}
		}
	}

	ret = KNOT_EOK;
get_error:
	yp_scheme_check_deinit(ctx);

	return ret;
}
