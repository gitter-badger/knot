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

#include "knot/dnssec/context.h"
#include "knot/zone/contents.h"
#include "libknot/rrtype/soa.h"

static uint32_t zone_soa_min_ttl(const zone_contents_t *zone)
{
	knot_rrset_t soa = node_rrset(zone->apex, KNOT_RRTYPE_SOA);
	return knot_soa_minimum(&soa.rrs);
}

static uint32_t zone_soa_ttl(const zone_contents_t *zone)
{
	knot_rrset_t soa = node_rrset(zone->apex, KNOT_RRTYPE_SOA);
	return knot_rrset_ttl(&soa);
}

void update_policy_from_zone(dnssec_kasp_policy_t *policy,
                             const zone_contents_t *zone)
{
	assert(policy);
	assert(zone);

	policy->soa_minimal_ttl = zone_soa_min_ttl(zone);
	policy->dnskey_ttl = zone_soa_ttl(zone);
	policy->zone_maximal_ttl = 0; // TODO
}

void set_default_policy(dnssec_kasp_policy_t *policy,
                        const zone_contents_t *zone)
{
	assert(policy);
	assert(zone);

	policy->rrsig_lifetime = 30 * 24 * 3600;
	policy->rrsig_refresh_before = policy->rrsig_lifetime / 10;
	policy->algorithm = 0;
	policy->propagation_delay = 0;

	update_policy_from_zone(policy, zone);
}
