/*!
 * \file query_stats.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief Query statistics module
 *
 * Accepted configurations:
 *  * "<file>"
 *
 * Module gathers query statistics and outputs them into a file.
 *
 * \addtogroup query_processing
 * @{
 */
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

#pragma once

#include "knot/nameserver/query_module.h"

/*! \brief Module scheme. */
#define C_MOD_QUERY_STATS "\x0F""mod-query-stats"
extern const yp_item_t scheme_mod_query_stats[];

/*! \brief Module interface. */
int query_stats_load(struct query_plan *plan, struct query_module *self);
int query_stats_unload(struct query_module *self);

/*! @} */
