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
/*!
 * \file
 *
 * Configuration editing facility.
 *
 * \addtogroup config
 *
 * @{
 */

#pragma once

#include "knot/conf/conf.h"

typedef struct {
	const yp_item_t *key0;
	const yp_item_t *key1;
	uint8_t *id;
	size_t id_len;
	conf_val_t *data;
	bool first_data;
	void *misc;
} conf_edit_get_params_t;

typedef int conf_edit_get_f(conf_edit_get_params_t *);

/*!
 * Starts new edit transaction.
 *
 * \return Error code, KNOT_EOK if success.
 */
int conf_edit_start(
	void
);

/*!
 * Commits the current edit transaction.
 *
 * \return Error code, KNOT_EOK if success.
 */
int conf_edit_commit(
	void
);

/*!
 * Aborts the current edit transaction.
 *
 * \return Error code, KNOT_EOK if success.
 */
int conf_edit_abort(
	void
);

int conf_edit_set(
	const char *key0,
	const char *key1,
	const char *id,
	const char *data
);

int conf_edit_del(
	const char *key0,
	const char *key1,
	const char *id,
	const char *data
);

int conf_edit_get(
	const char *key0,
	const char *key1,
	const char *id,
	bool get_current,
	conf_edit_get_f *fcn,
	conf_edit_get_params_t *params
);

/*! @} */
