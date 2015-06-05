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

#include "knot/zone/events/events.h"
#include "knot/zone/zone.h"

time_t replan_reload(const zone_t *zone, time_t timer);
time_t replan_refresh(const zone_t *zone, time_t timer);
time_t replan_xfer(const zone_t *zone, time_t timer);
time_t replan_update(const zone_t *zone, time_t timer);
time_t replan_expire(const zone_t *zone, time_t timer);
time_t replan_flush(const zone_t *zone, time_t timer);
time_t replan_notify(const zone_t *zone, time_t timer);
time_t replan_dnssec(const zone_t *zone, time_t timer);
