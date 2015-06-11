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

#include "knot/zone/events/replan.h"
#include "knot/zone/zone.h"
#include "libknot/internal/macros.h"
#include "libknot/rrtype/soa.h"

/*!
 * \brief Recalculate since the last flush.
 */
static void replan_flush(const zone_t *zone, const timerdb_entry_t *persistent,
                         time_t *timer)
{
	conf_val_t val = conf_zone_get(conf(), C_ZONEFILE_SYNC, zone->name);
	int64_t config_sync = conf_int(&val);

	// immediate flush enabled

	if (config_sync <= 0) {
		// force immediate flush if the timer was running
		*timer = *timer > 0 ? ZONE_EVENT_NOW : 0;
		return;
	}

	// regular flushing

	*timer = persistent->last_flush + config_sync;
}

/*!
 * \brief DNSSEC should be run immeditaly in case the keys changed.
 */
static void replan_dnssec(const zone_t *zone, time_t *timer)
{
	// signing is part of the initial zone load

	if (zone_contents_is_empty(zone->contents)) {
		*timer = 0;
		return;
	}

	// automatically signed zone, keys could have changed
	//! \todo issue #247

	conf_val_t val = conf_zone_get(conf(), C_DNSSEC_SIGNING, zone->name);
	if (conf_bool(&val) && !zone_is_slave(zone)) {
		*timer = time(NULL);
		return;
	}

	// signing disabled

	*timer = 0;
	return;
}

void replan(const zone_t *zone, const timerdb_entry_t *persistent,
            zone_events_times_t timers)
{
	/* Cancel */

	timers[ZONE_EVENT_RELOAD] = 0;

	/* Cancel unless the zone is slave */

	if (!zone_is_slave(zone)) {
		timers[ZONE_EVENT_REFRESH] = 0;
		timers[ZONE_EVENT_XFER] = 0;
		timers[ZONE_EVENT_EXPIRE] = 0;
	}

	/* Always keep */

	// ZONE_EVENT_UPDATE
	// ZONE_EVENT_NOTIFY

	/* Recompute new value */

	replan_flush(zone, persistent, &timers[ZONE_EVENT_FLUSH]);
	replan_dnssec(zone, &timers[ZONE_EVENT_DNSSEC]);
}
