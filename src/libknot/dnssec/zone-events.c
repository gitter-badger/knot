/*  Copyright (C) 2013 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <config.h>
#include <assert.h>
#include <time.h>
#include "knot/conf/conf.h"
#include "knot/server/zones.h"
#include "libknot/dnssec/policy.h"
#include "libknot/dnssec/zone-events.h"
#include "libknot/dnssec/zone-keys.h"
#include "libknot/dnssec/zone-nsec.h"
#include "libknot/dnssec/zone-sign.h"
#include "libknot/util/debug.h"
#include "libknot/zone/zone.h"

static uint32_t time_now(void)
{
	return (uint32_t)time(NULL);
}

static void init_default_policy(knot_dnssec_policy_t *p,
                                knot_update_serial_t soa_up)
{
	knot_dnssec_policy_t p_image = DEFAULT_DNSSEC_POLICY;
	memcpy(p, &p_image, sizeof(knot_dnssec_policy_t));
	p->soa_up = soa_up;
}

static void init_forced_policy(knot_dnssec_policy_t *p,
                               knot_update_serial_t soa_up)
{
	knot_dnssec_policy_t p_image = FORCED_DNSSEC_POLICY;
	memcpy(p, &p_image, sizeof(knot_dnssec_policy_t));
	p->soa_up = soa_up;
}

static int init_dnssec_structs(const knot_zone_t *zone,
                               knot_zone_keys_t *zone_keys,
                               knot_dnssec_policy_t *policy,
                               knot_update_serial_t soa_up, bool force)
{
	assert(zone);
	assert(zone_keys);
	assert(policy);

	// Read zone keys from disk
	bool nsec3_enabled = is_nsec3_enabled(zone->contents);
	int result = knot_load_zone_keys(conf()->dnssec_keydir,
	                                 zone->contents->apex->owner,
	                                 nsec3_enabled, zone_keys);
	if (result != KNOT_EOK) {
		char *zname = knot_dname_to_str(zone->name);
		log_zone_error("DNSSEC: Zone %s - %s\n", zname,
		               knot_strerror(result));
		free(zname);
		knot_free_zone_keys(zone_keys);
		return result;
	}

	// Init sign policy
	if (force) {
		init_forced_policy(policy, soa_up);
	} else {
		init_default_policy(policy, soa_up);
	}

	// Override signature lifetime, if set in config
	zonedata_t *zd = (zonedata_t *)zone->data;
	pthread_mutex_lock(&zd->lock);
	int sig_lf = zd->conf->sig_lifetime;
	pthread_mutex_unlock(&zd->lock);
	if (sig_lf > 0) {
		policy->sign_lifetime = sig_lf;
	}

	return KNOT_EOK;
}

static int zone_sign(knot_zone_t *zone, knot_changeset_t *out_ch, bool force,
                     knot_update_serial_t soa_up, uint32_t *expires_at)
{
	assert(zone);
	assert(zone->contents);
	assert(out_ch);

	char *zname = knot_dname_to_str(zone->name);
	char *msgpref = sprintf_alloc("DNSSEC: Zone %s -", zname);
	free(zname);
	if (msgpref == NULL) {
		return KNOT_ENOMEM;
	}

	dbg_dnssec_verb("Changeset empty before generating NSEC chain: %d\n",
	                knot_changeset_is_empty(out_ch));

	conf_zone_t *zone_config = ((zonedata_t *)knot_zone_data(zone))->conf;
	if (!zone_config->dnssec_enable) {
		log_server_warning("%s DNSSEC not enabled.\n", msgpref);
		free(msgpref);
		return KNOT_EOK;
	}

	// Init needed structs
	knot_zone_keys_t zone_keys = { '\0' };
	knot_dnssec_policy_t policy = { '\0' };
	int result = init_dnssec_structs(zone, &zone_keys, &policy, soa_up,
	                                 force);
	if (result != KNOT_EOK) {
		free(msgpref);
		return result;
	}

	// generate NSEC records
	result = knot_zone_create_nsec_chain(zone->contents, out_ch,
	                                     &zone_keys, &policy);
	if (result != KNOT_EOK) {
		log_zone_error("%s Could not create NSEC(3) chain (%s).\n",
		               msgpref, knot_strerror(result));
		free(msgpref);
		knot_free_zone_keys(&zone_keys);
		return result;
	}
	dbg_dnssec_verb("Changeset empty after generating NSEC chain: %d\n",
	                knot_changeset_is_empty(out_ch));

	// add missing signatures
	result = knot_zone_sign(zone->contents, &zone_keys, &policy, out_ch,
	                        expires_at);
	if (result != KNOT_EOK) {
		log_zone_error("%s Error while signing (%s).\n",
		               msgpref, knot_strerror(result));
		free(msgpref);
		knot_free_zone_keys(&zone_keys);
		return result;
	}
	dbg_dnssec_verb("Changeset emtpy after signing: %d\n",
	                knot_changeset_is_empty(out_ch));

	// Check if only SOA changed
	if (knot_changeset_is_empty(out_ch) &&
	    !knot_zone_sign_soa_expired(zone->contents, &zone_keys, &policy)) {
		log_server_info("%s No signing performed, zone is valid.\n",
		                msgpref);
		free(msgpref);
		knot_free_zone_keys(&zone_keys);
		assert(knot_changeset_is_empty(out_ch));
		return KNOT_EOK;
	}

	// update SOA if there were any changes
	const knot_rrset_t *soa = knot_node_rrset(zone->contents->apex,
	                                          KNOT_RRTYPE_SOA);
	assert(soa);
	result = knot_zone_sign_update_soa(soa, &zone_keys, &policy,
	                                   out_ch);
	if (result != KNOT_EOK) {
		log_server_error("%s Cannot update SOA record (%s). Not signing"
		                 "the zone!\n", msgpref, knot_strerror(result));
		free(msgpref);
		knot_free_zone_keys(&zone_keys);
		return result;
	}

	knot_free_zone_keys(&zone_keys);
	dbg_dnssec_detail("Zone signed: changes=%zu\n",
	                  knot_changeset_size(out_ch));
	free(msgpref);

	return KNOT_EOK;
}

int knot_dnssec_zone_sign(knot_zone_t *zone, knot_changeset_t *out_ch,
                          knot_update_serial_t soa_up, uint32_t *expires_at)
{
	if (zone == NULL || zone->contents == NULL || out_ch == NULL) {
		return KNOT_EINVAL;
	}

	return zone_sign(zone, out_ch, false, soa_up, expires_at);
}

int knot_dnssec_zone_sign_force(knot_zone_t *zone,
                                knot_changeset_t *out_ch, uint32_t *expires_at)
{
	if (zone == NULL || zone->contents == NULL || out_ch == NULL) {
		return KNOT_EINVAL;
	}

	return zone_sign(zone, out_ch, true, KNOT_SOA_SERIAL_INC, expires_at);
}

int knot_dnssec_sign_changeset(const knot_zone_contents_t *zone,
                               const knot_changeset_t *in_ch,
                               knot_changeset_t *out_ch,
                               knot_update_serial_t soa_up,
                               uint32_t *used_lifetime,
                               uint32_t *used_refresh)
{
	if (!used_lifetime || !used_refresh) {
		return KNOT_EINVAL;
	}

	*used_lifetime = 0;
	*used_refresh = 0;

	if (!conf()->dnssec_enable) {
		return KNOT_EOK;
	}

	if (zone == NULL || in_ch == NULL || out_ch == NULL) {
		return KNOT_EINVAL;
	}

	// Init needed structures
	knot_zone_keys_t zone_keys = { '\0' };
	knot_dnssec_policy_t policy = { '\0' };
	int ret = init_dnssec_structs(zone->zone, &zone_keys, &policy, soa_up,
	                              false);
	if (ret != KNOT_EOK) {
		return ret;
	}

	char *zname = knot_dname_to_str(knot_zone_name(zone->zone));
	char *msgpref = sprintf_alloc("DNSSEC: Zone %s -", zname);
	free(zname);
	if (msgpref == NULL) {
		return KNOT_ENOMEM;
	}

	// Fix NSEC(3) chain
	ret = knot_zone_create_nsec_chain(zone, out_ch, &zone_keys, &policy);
	if (ret != KNOT_EOK) {
		log_zone_error("%s Failed to fix NSEC(3) chain (%s)\n",
		               msgpref, knot_strerror(ret));
		knot_free_zone_keys(&zone_keys);
		free(msgpref);
		return ret;
	}

	// Sign added and removed RRSets in changeset
	ret = knot_zone_sign_changeset(zone, in_ch, out_ch, &zone_keys,
	                               &policy);
	if (ret != KNOT_EOK) {
		log_zone_error("%s Failed to sign changeset (%s)\n",
		               msgpref, knot_strerror(ret));
		knot_free_zone_keys(&zone_keys);
		free(msgpref);
		return ret;
	}

	// Update SOA RRSIGs
	ret = knot_zone_sign_update_soa(knot_node_rrset(zone->apex,
	                                                KNOT_RRTYPE_SOA),
	                                &zone_keys, &policy,
	                                out_ch);
	if (ret != KNOT_EOK) {
		log_zone_error("%s Failed to sign SOA RR (%s)\n", msgpref,
		               knot_strerror(ret));
		knot_free_zone_keys(&zone_keys);
		free(msgpref);
		return ret;
	}

	knot_free_zone_keys(&zone_keys);
	free(msgpref);

	*used_lifetime = policy.sign_lifetime;
	*used_refresh = policy.sign_refresh;

	return KNOT_EOK;
}