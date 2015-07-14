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

#include "libknot/dname.h"
#include "libknot/internal/namedb/namedb.h"
#include "libknot/internal/namedb/namedb_lmdb.h"
#include "libknot/internal/mem.h"
#include "knot/zone/timers.h"
#include "knot/zone/zonedb.h"

/* ---- Knot-internal event code to db key lookup tables ------------------ - */

#define PERSISTENT_EVENT_COUNT 3

enum {
	KEY_REFRESH = 1,
	KEY_EXPIRE,
	KEY_FLUSH
};

// Do not change these mappings if you want backwards compatibility.
static const uint8_t event_id_to_key[ZONE_EVENT_COUNT] = {
	[ZONE_EVENT_REFRESH] = KEY_REFRESH,
	[ZONE_EVENT_EXPIRE] = KEY_EXPIRE,
	[ZONE_EVENT_FLUSH] = KEY_FLUSH
};

static const int key_to_event_id[PERSISTENT_EVENT_COUNT + 1] = {
	[KEY_REFRESH] = ZONE_EVENT_REFRESH,
	[KEY_EXPIRE] = ZONE_EVENT_EXPIRE,
	[KEY_FLUSH] = ZONE_EVENT_FLUSH
};

static bool known_event_key(uint8_t key)
{
	return key <= KEY_FLUSH;
}

#define EVENT_KEY_PAIR_SIZE (sizeof(uint8_t) + sizeof(int64_t))

static bool event_persistent(size_t event)
{
	return event_id_to_key[event] != 0;
}

/*! \brief Clear array of timers. */
static void clear_timers(time_t *timers)
{
	memset(timers, 0, ZONE_EVENT_COUNT * sizeof(time_t));
}

/*! \brief Stores timers for persistent events. */
static int store_timers(namedb_ctx_t *timer_db, namedb_txn_t *txn, zone_t *zone)
{
	// Create key
	namedb_val_t key = { .len = knot_dname_size(zone->name), .data = zone->name };

	// Create value
	uint8_t packed_timer[EVENT_KEY_PAIR_SIZE * PERSISTENT_EVENT_COUNT];
	size_t offset = 0;
	for (zone_event_type_t event = 0; event < ZONE_EVENT_COUNT; ++event) {
		if (!event_persistent(event)) {
			continue;
		}

		// Write event key and timer to buffer
		packed_timer[offset] = event_id_to_key[event];
		offset += 1;
		wire_write_u64(packed_timer + offset,
		                    (int64_t)zone_events_get_time(zone, event));
		offset += sizeof(uint64_t);
	}
	namedb_val_t val = { .len = sizeof(packed_timer), .data = packed_timer };

	// Store
	return namedb_insert(timer_db, txn, &key, &val, 0);
}

/*! \brief Reads timers for persistent events. */
static int read_timers(namedb_ctx_t *timer_db, namedb_txn_t *txn,
                       const zone_t *zone, time_t *timers)
{
	namedb_val_t key = { .len = knot_dname_size(zone->name), .data = zone->name };
	namedb_val_t val;

	int ret = namedb_find(timer_db, txn, &key, &val, 0);
	if (ret != KNOT_EOK && ret != KNOT_ENOENT) {
		return ret;
	}

	clear_timers(timers);
	if (ret == KNOT_ENOENT) {
		return KNOT_EOK;
	}

	const size_t stored_event_count = val.len / EVENT_KEY_PAIR_SIZE;
	size_t offset = 0;
	for (size_t i = 0; i < stored_event_count; ++i) {
		const uint8_t db_key = ((uint8_t *)val.data)[offset];
		offset += 1;
		if (known_event_key(db_key)) {
			const zone_event_type_t event = key_to_event_id[db_key];
			timers[event] =
				(time_t)wire_read_u64((uint8_t *)val.data + offset);
		}
		offset += sizeof(uint64_t);
	}

	return KNOT_EOK;
}

/* -------- API ------------------------------------------------------------- */

int open_timers_db(const char *storage, namedb_ctx_t **db_ptr)
{
	if (storage == NULL || db_ptr == NULL) {
		return KNOT_EINVAL;
	}

	struct namedb_lmdb_opts opts = NAMEDB_LMDB_OPTS_INITIALIZER;
	opts.path = sprintf_alloc("%s/timers", storage);
	if (opts.path == NULL) {
		return KNOT_ENOMEM;
	}

	*db_ptr = malloc(sizeof(namedb_ctx_t));
	if (*db_ptr == NULL) {
		free((char *)opts.path);
	}

	int ret = namedb_init_lmdb(*db_ptr, NULL, &opts);
	if (ret != KNOT_EOK) {
		free(*db_ptr);
	}

	free((char *)opts.path);

	return ret;
}

void close_timers_db(namedb_ctx_t *timer_db)
{
	if (timer_db == NULL) {
		return;
	}

	namedb_deinit(timer_db);
	free(timer_db);
}

int read_zone_timers(namedb_ctx_t *timer_db, const zone_t *zone, time_t *timers)
{
	if (timer_db == NULL) {
		clear_timers(timers);
		return KNOT_EOK;
	}

	namedb_txn_t txn;
	int ret = namedb_begin_txn(timer_db, &txn, NAMEDB_RDONLY);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = read_timers(timer_db, &txn, zone, timers);
	namedb_abort_txn(timer_db, &txn);
	if (ret != KNOT_EOK) {
		return ret;
	}

	return KNOT_EOK;
}

int write_zone_timers(namedb_ctx_t *timer_db, zone_t *zone)
{
	if (timer_db == NULL) {
		return KNOT_EOK;
	}

	namedb_txn_t txn;
	int ret = namedb_begin_txn(timer_db, &txn, 0);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = store_timers(timer_db, &txn, zone);
	if (ret != KNOT_EOK) {
		namedb_abort_txn(timer_db, &txn);
		return ret;
	}

	return namedb_commit_txn(timer_db, &txn);
}

int sweep_timer_db(namedb_ctx_t *timer_db, knot_zonedb_t *zone_db)
{
	if (timer_db == NULL) {
		return KNOT_EOK;
	}

	namedb_txn_t txn;
	int ret = namedb_begin_txn(timer_db, &txn, NAMEDB_SORTED);
	if (ret != KNOT_EOK) {
		return ret;
	}


	if (namedb_count(timer_db, &txn) == 0) {
		namedb_abort_txn(timer_db, &txn);
		return KNOT_EOK;
	}

	namedb_iter_t *it = namedb_begin_iter(timer_db, &txn, 0);
	if (it == NULL) {
		namedb_abort_txn(timer_db, &txn);
		return KNOT_ERROR;
	}

	while (it) {
		namedb_val_t key;
		ret = namedb_key_iter(timer_db ,it, &key);
		if (ret != KNOT_EOK) {
			namedb_abort_txn(timer_db, &txn);
			return ret;
		}
		const knot_dname_t *dbkey = (const knot_dname_t *)key.data;
		if (!knot_zonedb_find(zone_db, dbkey)) {
			// Delete obsolete timers
			namedb_del(timer_db, &txn, &key);
		}

		it = namedb_next_iter(timer_db, it);
	}
	namedb_finish_iter(timer_db, it);

	return namedb_commit_txn(timer_db, &txn);
}
