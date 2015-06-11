/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <dirent.h>
#include <stdlib.h>
#include <time.h>
#include <tap/basic.h>

#include "knot/zone/timers.h"
#include "libknot/internal/mem.h"
#include "libknot/libknot.h"

static const knot_dname_t *zone_1 = (uint8_t *)"\x5""hello";
static const knot_dname_t *zone_2 = (uint8_t *)"\x4""knot";
static const knot_dname_t *zone_3 = (uint8_t *)"\x3""abc";

static int sweep_error(const knot_dname_t *zone, bool *keep, void *ctx)
{
	return KNOT_ERROR;
}

static int sweep_keep_all(const knot_dname_t *zone, bool *keep, void *ctx)
{
	if (!zone || !keep) {
		return KNOT_EINVAL;
	}

	*keep = true;

	return KNOT_EOK;
}

static int sweep_remove_one(const knot_dname_t *zone, bool *keep, void *ctx)
{
	if (!zone || !keep || !ctx) {
		return KNOT_EINVAL;
	}

	const knot_dname_t *to_remove = ctx;

	*keep = knot_dname_cmp(zone, to_remove) != 0;

	return KNOT_EOK;
}

int main(int argc, char *argv[])
{
	plan_lazy();

	// Temporary DB identifier.
	char dbid_buf[] = "/tmp/timerdb.XXXXXX";
	const char *dbid = mkdtemp(dbid_buf);


	timerdb_t *db = NULL;
	int ret = timerdb_open(&db, dbid);
	ok(ret == KNOT_EOK && db != NULL, "zone timers: open");

	// Sample entries

	const timerdb_entry_t entry_1 = {
		.last_flush   = UINT64_C(0x55) << 50,
		.next_refresh = UINT64_C(0x55) << 30,
		.expire       = UINT64_C(0x55) << 10,
	};

	const timerdb_entry_t entry_2 = {
		.last_flush   = 0,
		.next_refresh = 10,
		.expire       = 20,
	};

	const timerdb_entry_t entry_3 = {
		.last_flush   = 1025,
		.next_refresh = 1024,
		.expire       = 1023,
	};

	timerdb_entry_t timers = { 0 };

	// Write the timers.
	ret = timerdb_write(db, zone_1, &entry_1);
	ok(ret == KNOT_EOK, "zone timers: write zone1");

	ret = timerdb_write(db, zone_2, &entry_2);
	ok(ret == KNOT_EOK, "zone timers: write zone2");

	// Read the timers.
	memset(&timers, 0, sizeof(timers));
	ret = timerdb_read(db, zone_1, &timers);
	ok(ret == KNOT_EOK && memcmp(&entry_1, &timers, sizeof(timers)) == 0,
	   "zone timers: read zone1");

	memset(&timers, 0, sizeof(timers));
	ret = timerdb_read(db, zone_2, &timers);
	ok(ret == KNOT_EOK && memcmp(&entry_2, &timers, sizeof(timers)) == 0,
	   "zone timers: read zone2");

	// Replace a timer.
	ret = timerdb_write(db, zone_1, &entry_3);
	ok(ret == KNOT_EOK, "zone timers: rewrite zone1");

	memset(&timers, 0, sizeof(timers));
	ret = timerdb_read(db, zone_1, &timers);
	ok(ret == KNOT_EOK && memcmp(&entry_3, &timers, sizeof(timers)) == 0,
	   "zone timers: read rewritten");

	// Failing sweep.

	ret = timerdb_sweep(db, sweep_error, NULL);
	ok(ret == KNOT_ERROR, "zone timers: sweep raises error");

	memset(&timers, 0, sizeof(timers));
	ret = timerdb_read(db, zone_2, &timers);
	ok(ret == KNOT_EOK && memcmp(&entry_2, &timers, sizeof(timers)) == 0,
	   "zone timers: read zone2 after unsuccessful sweep");

	// Sweep keeps all.
	ret = timerdb_sweep(db, sweep_keep_all, NULL);
	ok(ret == KNOT_EOK, "zone timers: sweep kept all");

	memset(&timers, 0, sizeof(timers));
	ret = timerdb_read(db, zone_1, &timers);
	ok(ret == KNOT_EOK && memcmp(&entry_3, &timers, sizeof(timers)) == 0,
	   "zone timers: read zone1 after sweep keeping all");

	// Read non-existent.
	memset(&timers, 0, sizeof(timers));
	ret = timerdb_read(db, zone_3, &timers);
	ok(ret == KNOT_ENOENT, "zone timers: read non-existent");

	// Remove first zone from db and sweep.

	ret = timerdb_sweep(db, sweep_remove_one, (void *)zone_1);
	ok(ret == KNOT_EOK, "zone timers: sweep");

	ret = timerdb_read(db, zone_1, &timers);
	ok(ret == KNOT_ENOENT, "zone timers: read removed zone");

	// Clean up.
	timerdb_close(db);

	// Cleanup temporary DB.
	DIR *dir = opendir(dbid);
	struct dirent *dp;
	while ((dp = readdir(dir)) != NULL) {
		if (dp->d_name[0] == '.') {
			continue;
		}
		char *file = sprintf_alloc("%s/%s", dbid, dp->d_name);
		remove(file);
		free(file);
	}
	closedir(dir);
	remove(dbid);

	return EXIT_SUCCESS;
}
