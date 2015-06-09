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

#include "knot/zone/timers.h"
#include "knot/zone/zonedb.h"
#include "libknot/dname.h"
#include "libknot/internal/namedb/namedb.h"
#include "libknot/internal/namedb/namedb_lmdb.h"

/*!
 * \brief Timer database context.
 *
 * Key-value database is used to store the timers:
 *
 * - The key is a zone name in wire format.
 *
 * - The value is a sequence of timers. Each timer is an id-value pair. The
 *   ID is a 8-bit identifier of the timer. The value is encoded as a 64-bit
 *   number in network byte order.
 *
 */
struct timerdb {
	const namedb_api_t *api;
	namedb_t *backend;
};

/*!
 * \brief Timer identifiers used in the binary encoding.
 *
 * Assigned values should not be changed for compatibility.
 */
enum key {
	KEY_INVALID = 0,
	KEY_REFRESH = 1,
	KEY_EXPIRE,
	KEY_OBSOLETE_FUTURE_FLUSH, // obsolete since 1.6.4
	KEY_LAST_FLUSH,
};

#define VALUE_SIZE (sizeof(uint8_t) + sizeof(int64_t))

/*! \brief Convert zone name to the lookup key. */
static void dname_to_key(const knot_dname_t *name, namedb_val_t *key)
{
	key->data = (void *)name;
	key->len = knot_dname_size(name);
}

int timerdb_open(timerdb_t **db_ptr, const char *path)
{
	if (!db_ptr || !path) {
		return KNOT_EINVAL;
	}

	timerdb_t *db = calloc(1, sizeof(*db));
	if (!db) {
		return KNOT_ENOMEM;
	}

	db->api = namedb_lmdb_api();
	assert(db->api);

	struct namedb_lmdb_opts opts = NAMEDB_LMDB_OPTS_INITIALIZER;
	opts.path = path;
	int ret = db->api->init(&db->backend, NULL, &opts);
	if (ret != KNOT_EOK) {
		free(db);
		return ret;
	}

	*db_ptr = db;

	return KNOT_EOK;
}

void timerdb_close(timerdb_t *db)
{
	if (!db) {
		return;
	}

	db->api->deinit(db->backend);
	free(db);
}

static void serialize_value(uint8_t **write, enum key key, uint64_t value)
{
	*write[0] = (uint8_t)key;
	*write += sizeof(uint8_t);
	wire_write_u64(*write, value);
	*write += sizeof(uint64_t);
}

static int serialize_entry(const timerdb_entry_t *entry, namedb_val_t *value_ptr)
{
	namedb_val_t value = { 0 };
	value.len = 3 * VALUE_SIZE;
	value.data = malloc(value.len);
	if (!value.data) {
		return KNOT_ENOMEM;
	}

	uint8_t *write = value.data;
	serialize_value(&write, KEY_REFRESH, entry->next_refresh);
	serialize_value(&write, KEY_EXPIRE, entry->expire);
	serialize_value(&write, KEY_LAST_FLUSH, entry->last_flush);
	assert(write == value.data + value.len);

	*value_ptr = value;

	return KNOT_EOK;
}

int timerdb_write(timerdb_t *db, const knot_dname_t *zone,
                  const timerdb_entry_t *entry)
{
	if (!db || !zone || !entry) {
		return KNOT_EINVAL;
	}

	namedb_val_t key = { 0 };
	namedb_val_t data = { 0 };

	dname_to_key(zone, &key);
	int ret = serialize_entry(entry, &data);
	if (ret != KNOT_EOK) {
		return KNOT_ENOMEM;
	}

	namedb_txn_t txn = { 0 };
	ret = db->api->txn_begin(db->backend, &txn, 0);
	if (ret != KNOT_EOK) {
		free(data.data);
		return ret;
	}

	ret = db->api->insert(&txn, &key, &data, 0);
	if (ret != KNOT_EOK) {
		db->api->txn_abort(&txn);
		free(data.data);
		return ret;
	}

	ret = db->api->txn_commit(&txn);
	free(data.data);

	return ret;
}

static void deserialize_value(enum key key, uint64_t value, timerdb_entry_t *entry)
{
	switch (key) {
	case KEY_REFRESH:
		entry->next_refresh = value;
		break;
	case KEY_EXPIRE:
		entry->expire = value;
		break;
	case KEY_LAST_FLUSH:
		entry->last_flush = value;
		break;
	case KEY_OBSOLETE_FUTURE_FLUSH:
		// pretend we never flushed before
		break;
	default:
		// ignore unknown keys
		break;
	}
}

static int deserialize_entry(timerdb_entry_t *entry, const namedb_val_t *value)
{
	timerdb_entry_t result = { 0 };

	const uint8_t *read = value->data;
	size_t len = value->len;

	for (/* nothing */; len >= VALUE_SIZE; len -= VALUE_SIZE) {
		int key = read[0];
		read += sizeof(uint8_t);
		uint64_t value = wire_read_u64(read);
		read += sizeof(uint64_t);

		deserialize_value(key, value, &result);
	}

	if (len != 0) {
		return KNOT_EMALF;
	}

	assert(read == value->data + value->len);

	*entry = result;

	return KNOT_EOK;
}

int timerdb_read(timerdb_t *db, const knot_dname_t *zone, timerdb_entry_t *entry)
{
	if (!db || !zone || !entry) {
		return KNOT_EINVAL;
	}

	namedb_val_t key = { 0 };
	namedb_val_t val = { 0 };

	dname_to_key(zone, &key);

	namedb_txn_t txn = { 0 };
	int ret = db->api->txn_begin(db->backend, &txn, NAMEDB_RDONLY);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = db->api->find(&txn, &key, &val, 0);
	db->api->txn_abort(&txn);
	if (ret != KNOT_EOK) {
		return ret;
	}

	return deserialize_entry(entry, &val);
}

int timerdb_sweep(timerdb_t *db, knot_zonedb_t *zones)
{
	if (!db || !zones) {
		return KNOT_EINVAL;
	}

	namedb_txn_t txn = { 0 };
	int ret = db->api->txn_begin(db->backend, &txn, NAMEDB_SORTED);
	if (ret != KNOT_EOK) {
		return ret;
	}

	bool modified = false;

	namedb_iter_t *it = db->api->iter_begin(&txn, 0);
	if (!it) {
		db->api->txn_abort(&txn);
		return KNOT_ERROR;
	}

	while (it) {
		namedb_val_t key;
		ret = db->api->iter_key(it, &key);
		if (ret != KNOT_EOK) {
			db->api->txn_abort(&txn);
			return ret;
		}

		ret = knot_dname_wire_check(key.data, key.data + key.len, NULL);
		if (ret != key.len) {
			db->api->txn_abort(&txn);
			return ret;
		}

		const knot_dname_t *zone = key.data;
		if (knot_zonedb_find(zones, zone) == NULL) {
			db->api->del(&txn, &key);
			modified = true;
		}

		it = db->api->iter_next(it);
	}

	db->api->iter_finish(it);

	if (!modified) {
		db->api->txn_abort(&txn);
		return KNOT_EOK;
	}

	return db->api->txn_commit(&txn);
}
