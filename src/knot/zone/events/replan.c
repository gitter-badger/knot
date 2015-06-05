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

time_t replan_reload(const zone_t *zone, time_t timer)
{
	return 0;
}

time_t replan_expire(const zone_t *zone, time_t timer)
{
	// master zone

	if (!zone_is_slave(zone)) {
		return 0;
	}

	// slave zone

	return timer;
}

time_t replan_refresh(const zone_t *zone, time_t timer)
{
	// master zone

	if (!zone_is_slave(zone)) {
		return 0;
	}

	// slave zone

	if (timer > 0) {
		return timer;
	}

	if (!zone_contents_is_empty(zone->contents)) {
		const knot_rdataset_t *soa = node_rdataset(zone->contents->apex,
		                                           KNOT_RRTYPE_SOA);
		assert(soa);
		return time(NULL) + knot_soa_refresh(soa);
	}

	return 0;
}

time_t replan_xfer(const zone_t *zone, time_t timer)
{
	// master zone

	if (!zone_is_slave(zone)) {
		return 0;
	}

	// slave zone

	if (timer > 0) {
		return timer;
	}

	if (zone_contents_is_empty(zone->contents)) {
		return time(NULL) + zone->bootstrap_retry;
	}

	return 0;
}

time_t replan_flush(const zone_t *zone, time_t timer)
{
	conf_val_t val = conf_zone_get(conf(), C_ZONEFILE_SYNC, zone->name);
	int64_t config_sync = conf_int(&val);

	// immediate syncing enabled

	if (config_sync <= 0 && timer == 0) {
		return 0;
	}

	// pick the sooner: old timer or new sync counted from now

	return MIN(timer, time(NULL) + config_sync);
}

time_t replan_dnssec(const zone_t *zone, time_t timer)
{
	// automatically signed zone

	conf_val_t val = conf_zone_get(conf(), C_DNSSEC_SIGNING, zone->name);
	if (conf_bool(&val) && !zone_is_slave(zone)) {
		// keys could have changed,
		//! \todo issue #247
		timer = time(NULL);
	}

	// signing disabled

	return 0;
}

time_t replan_notify(const zone_t *zone, time_t timer)
{
	return timer;
}

time_t replan_update(const zone_t *zone, time_t timer)
{
	return timer;
}
