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

#include "libknot/dname.h"

struct timerdb;
typedef struct timerdb timerdb_t;

/*!
 * \brief Entry in the timer database for one zone.
 */
struct timerdb_entry {
	uint64_t last_flush;
	uint64_t next_refresh;
	uint64_t expire;
};

typedef struct timerdb_entry timerdb_entry_t;

/*!
 * \brief Open zone timer database.
 *
 * If LMDB support is not available, the timers are stored in-memory.
 *
 * \param[out] db       Created database.
 * \param[in]  storage  Path to storage directory.
 *
 * \return KNOT_E*
 */
int timerdb_open(timerdb_t **db, const char *storage);

/*!
 * \brief Close zone timer database.
 *
 * \param timer_db  Timer database.
 */
void timerdb_close(timerdb_t *db);

/*!
 * \brief Reads entry from the timer database.
 *
 * \param[in]  timer_db  Timer database.
 * \param[in]  zone      Zone to read timers for.
 * \param[out] timers    Zone timers.
 *
 * \return KNOT_E*
 */
int timerdb_read(timerdb_t *db, const knot_dname_t *zone,
                 timerdb_entry_t *timers);

/*!
 * \brief Writes zone timers to timer database.
 *
 * \param db      Timer database.
 * \param zone    Zone to store timers for.
 * \param timers  Zone timers to store.
 *
 * \return KNOT_E*
 */
int timerdb_write(timerdb_t *db, const knot_dname_t *zone,
                  const timerdb_entry_t *timers);

/*!
 * \brief Callback function for \ref timerdb_sweep.
 *
 * \param[in]  name  Zone name.
 * \param[out] keep  Shall the zone retain in the database.
 * \param[in]  ctx   Custom context.
 */
typedef int (*timerdb_sweep_cb)(const knot_dname_t *name, bool *keep, void *ctx);

/*!
 * \brief Remove stale zones info from timer database.
 *
 * \param timer_db  Timer database.
 * \param callback  Sweep callback.
 * \param ctx       Custom context passed to the callback function.
 *
 * \return KNOT_EOK or an error
 */
int timerdb_sweep(timerdb_t *timer_db, timerdb_sweep_cb callback, void *ctx);
