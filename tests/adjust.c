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

#include <tap/basic.h>

#include "knot/zone/adjust.h"
#include "knot/zone/zonefile.h"
#include "knot/zone/node-ref.h"
#include "knot/updates/apply.h"
#include "knot/dnssec/zone-nsec.h"

static const char *zone_str =
"test. 3600 IN SOA a. b. 1 1 1 1 1\n"
"b.test. IN TXT \"test\"\n"
"e.test. IN TXT \"test\"\n"
"x.test. IN TXT \"test\"\n";

static const char *add1 =
"test. 3600 IN SOA a. b. 1 1 1 1 1\n"
"c.test. IN TXT \"test\"\n"
"d.test. IN TXT \"test\"\n";

static const char *switch_nsec3 =
"test. 3600 IN SOA a. b. 1 1 1 1 1\n"
"test. 0 IN NSEC3PARAM 1 0 10 DEADBEEF\n"
"65QBS2TUD2SO2HMDIIFLAQVDHPL7EH56.test. IN NSEC3 1 0 10 DEADBEEF 7B4NC67ERA0FFG0QFHRRDCKH0OK3PESO TXT\n" // d.test.
"7B4NC67ERA0FFG0QFHRRDCKH0OK3PESO.test. IN NSEC3 1 0 10 DEADBEEF R8A5UNFOSHQNDVESUCUULJ8IHQ7N7ID7 SOA NSEC3PARAM\n" // test.
"R8A5UNFOSHQNDVESUCUULJ8IHQ7N7ID7.test. IN NSEC3 1 0 10 DEADBEEF RQPTAJDPMTSC4ADKMOMIA5K3QS1HHKE9 TXT\n" // e.test
"RQPTAJDPMTSC4ADKMOMIA5K3QS1HHKE9.test. IN NSEC3 1 0 10 DEADBEEF 65QBS2TUD2SO2HMDIIFLAQVDHPL7EH56 TXT\n"; // c.test

static const char *add_nsec3=
"test. 3600 IN SOA a. b. 1 1 1 1 1\n"
"f.test. IN TXT \"test\"\n"
"HAPB22MLBPNJTUSSFP5QNIBAQJHPP0VM.test. IN NSEC3 1 0 10 DEADBEEF R8A5UNFOSHQNDVESUCUULJ8IHQ7N7ID7 TXT\n";

static const char *del1 =
"test. 3600 IN SOA a. b. 1 1 1 1 1\n"
"x.test. IN TXT \"test\"\n";

static const char *del2 =
"test. 3600 IN SOA a. b. 1 1 1 1 1\n"
"b.test. IN TXT \"test\"\n"
"x.test. IN TXT \"test\"\n";

static const char *flags_zone =
"test. 3600 IN SOA a. b. 1 1 1 1 1\n"
"*.test. IN A 5.6.7.8\n"
"sub.test. IN NS glue.sub.test.\n"
"glue.sub.test. IN A 1.2.3.4\n"
"x.test. IN TXT \"test\"\n"
"below.x.test. IN A 1.2.3.4\n";

static const char *add_ns =
"test. 3600 IN SOA a. b. 1 1 1 1 1\n"
"sub.test. IN A 1.2.3.4\n"
"x.test. IN NS deleg.somewhere.\n";

static const char *add_ns_pair =
"test. 3600 IN SOA a. b. 1 1 1 1 1\n"
"sub2.test. IN NS glue2.sub.test.\n"
"glue2.sub.test. IN A 1.2.3.4\n";

static const char *remove_ns =
"test. 3600 IN SOA a. b. 1 1 1 1 1\n"
"sub.test. IN NS glue.sub.test.\n";

static const char *remove_glue =
"test. 3600 IN SOA a. b. 1 1 1 1 1\n"
"glue.sub.test. IN A 1.2.3.4\n";

struct zone_flags {
	uint8_t *name;
	union {
		uint8_t flags;
		const uint8_t *deleg[16];
	} data;
};

#define HINTS_SIZE 2

struct zone_flags ZONE_HINTS_INIT[HINTS_SIZE] = {
{(uint8_t *)"\4sub2\4test\0", .data.deleg = {(uint8_t *)"\5glue2\3sub\4test\0"}},
{(uint8_t *)"\3sub\4test\0", .data.deleg = {(uint8_t *)"\4glue\3sub\4test\0"}}};

struct zone_flags ZONE_HINTS_ADD[HINTS_SIZE] = {
{(uint8_t *)"\3sub\4test\0", .data.deleg = {NULL}},
{(uint8_t *)"\4sub2\4test\0", .data.deleg = {(uint8_t *)"\5glue2\3sub\4test\0"}}};

struct adjust_params {
	zcreator_t *zc;
	changeset_t *ch;
};

knot_rrset_t *old_soa;

static zone_node_t *get_ref(const zone_node_t *n,
                            const zone_tree_t *t,
                            const zone_contents_t *zone,
                            enum node_ref_type type)
{
	zone_t z = { .contents = (zone_contents_t *)zone, .name = zone->apex->owner };
	zone_read_t zr = { .zone = &z };
	if (t == zone->nodes) {
		return node_ref_get(n, type, &zr);
	} else {
		return node_ref_get_nsec3(n, type, &zr);
	}
}

static void scanner_process(zs_scanner_t *scanner)
{
	struct adjust_params *params = scanner->data;
//#error fix me as I am in zone_update.c unittest
	//knot_rrset_t rr;
	uint8_t owner[KNOT_DNAME_MAXLEN];
	memcpy(owner, scanner->r_owner, knot_dname_size(scanner->r_owner));
	knot_dname_to_lower((knot_dname_t *)&owner);
	// create data
	knot_rrset_t *rr = knot_rrset_new(owner,
	                                  scanner->r_type,
	                                  scanner->r_class, NULL);
	assert(rr);
	//knot_rrset_init(&rr, owner, scanner->r_type, scanner->r_class);
	int ret = knot_rrset_add_rdata(rr, scanner->r_data, scanner->r_data_length,
	                               scanner->r_ttl, NULL);
	assert(ret == KNOT_EOK);

	if (rr->type == KNOT_RRTYPE_SOA) {
		if (params->ch) {
			// Store SOA into changeset, do not add to zone.
			knot_rrset_free(&params->ch->soa_to, NULL);
			params->ch->soa_to = knot_rrset_copy(rr, NULL);
			assert(params->ch->soa_to);
			knot_rdataset_clear(&rr->rrs, NULL);
			return;
		} else {
			ret = node_add_rrset(params->zc->up->zone->contents->apex, rr, NULL);
			assert(ret == 0);
		}
	}
	ret = zcreator_step(params->zc, rr);
	assert(ret == KNOT_EOK);
	knot_rdataset_clear(&rr->rrs, NULL);
}

static bool nsec3_set_ok(const zone_node_t *n, const zone_contents_t *zone)
{
	if (n->nsec3_node == NULL) {
		diag("NSEC3 node not set");
		return false;
	}

	knot_dname_t *nsec3_name =
		knot_create_nsec3_owner(n->owner,
		                        zone->apex->owner,
		                        node_rdataset(zone->apex,
		                                      KNOT_RRTYPE_NSEC3PARAM));
	assert(nsec3_name);
	zone_node_t *found_nsec3 = zone_tree_get(zone->nsec3_nodes, nsec3_name);
	assert(found_nsec3);

	const zone_node_t *zone_nsec3_node = get_ref(n, zone->nodes, zone, REF_NSEC3);
	return zone_nsec3_node == found_nsec3;
}

static bool test_parent_for_tree(zone_tree_t *t, const zone_contents_t *zone)
{
	if (t == NULL) {
		return true;
	}

	hattrie_iter_t *itt = hattrie_iter_begin(t->db, false);
	assert(itt);

	while(!hattrie_iter_finished(itt)) {
		const zone_node_t *n = *hattrie_iter_val(itt);
		const zone_node_t *real_parent = zone_tree_get(t, knot_wire_next_label(n->owner, NULL));
		const zone_node_t *ref_parent = get_ref(n, t, zone, REF_PARENT);
		if (real_parent != ref_parent) {
			return false;
		}
		hattrie_iter_next(itt);
	}

	return true;
}

// Iterates through the zone and checks previous pointers
static bool test_prev_for_tree(const zone_tree_t *t, const zone_contents_t *zone)
{
	if (t == NULL) {
		return true;
	}

	hattrie_iter_t *itt = hattrie_iter_begin(t->db, true);
	assert(itt);

	//zone_node_t *first = (zone_node_t *)(*hattrie_iter_val(itt));
	value_t *val = hattrie_iter_val(itt);
	zone_node_t *first = (zone_node_t *)(val ? *val : NULL);
	zone_node_t *prev = NULL;
	zone_node_t *curr = NULL;
	while(!hattrie_iter_finished(itt)) {
		prev = curr;
		curr = *hattrie_iter_val(itt);
		if (prev) {
			const zone_node_t *zone_prev = get_ref(curr, t, zone, REF_PREVIOUS);
			if (zone_prev != prev) {
				diag("Prev is not set properly");
				hattrie_iter_free(itt);
				return false;
			}
		}

		if (node_rrtype_exists(zone->apex, KNOT_RRTYPE_NSEC3PARAM) &&
		    !node_rrtype_exists(curr, KNOT_RRTYPE_NSEC3)) {
			if (!nsec3_set_ok(curr, zone)) {
				diag("NSEC3 pointer not set properly for %s",
				     knot_dname_to_str_alloc(curr->owner));
				hattrie_iter_free(itt);
				return false;
			}
		}

		hattrie_iter_next(itt);
	}

	hattrie_iter_free(itt);
	const zone_node_t *first_prev = get_ref(first, t, zone, REF_PREVIOUS);
	return first_prev == curr;
}

static bool test_zone(const zone_contents_t *zone)
{
	return test_prev_for_tree(zone->nodes, zone) &&
	       test_prev_for_tree(zone->nsec3_nodes, zone) &&
	       test_parent_for_tree(zone->nodes, zone) &&
	       test_parent_for_tree(zone->nsec3_nodes, zone);
}

static bool hints_contain(const struct rr_data *data,
                          const uint8_t **hints, size_t hint_count)
{
	if (data->additional == NULL) {
		diag("Additional hints not set");
		return false;
	}

	for (uint16_t i = 0; i < data->rrs.rr_count; ++i) {
		if (data->additional[i]) {
			for (size_t j = 0; j < hint_count; ++j) {
				if (hints[j]) {
					if (knot_dname_is_equal(data->additional[i]->n->owner,
					                        hints[j])) {
						return true;
					}
				} else {
					if (data->additional[i] == NULL) {
						return true;
					}
				}
			}
		}
	}

	return false;
}

static bool test_hints(const zone_contents_t *zone, struct zone_flags *hints,
                       const size_t hints_size)
{
	for (size_t i = 0; i < hints_size; ++i) {
		zone_node_t *n = zone_tree_get(zone->nodes, hints[i].name);
		assert(n);
		for (uint16_t j = 0; j < n->rrset_count; ++j) {
			if (knot_rrtype_additional_needed(n->rrs[j].type)) {
				if (!hints_contain(&n->rrs[j],
				                   hints[i].data.deleg, 1)) {
					return false;
				}
			}
		}
	}

	return true;
}

static void add_and_update(zone_contents_t *zone, changeset_t *ch,
                           zs_scanner_t *sc, const char *str)
{
	// Parse record
	int ret = zs_scanner_parse(sc, str, str + strlen(str), true);
	assert(ret == 0);
	knot_rrset_free(&ch->soa_from, NULL);
	ch->soa_from = node_create_rrset(zone->apex, KNOT_RRTYPE_SOA);
	assert(ch->soa_to && ch->soa_from);
	// Insert
	ret = apply_changeset_directly(zone, ch);
	assert(ret == KNOT_EOK);
}

#define TEST_VALIDITY(zone, up, ch, msg) \
	ok(test_zone(zone), msg); \
	changeset_clear(ch); \
	changeset_init(ch, zone->apex->owner);

int main(int argc, char *argv[])
{
	plan_lazy();

	// Fill zone
	knot_dname_t *owner = knot_dname_from_str_alloc("test.");
	assert(owner);
	zone_contents_t *zone = zone_contents_new(owner);
	assert(zone);
	zone_t z = { .contents = zone, .name = owner };
	zone_update_t up;
	int ret = zone_update_init(&up, &z, UPDATE_FULL);
	assert(ret == KNOT_EOK);
	zcreator_t zc = {.up = &up, .master = true, .ret = KNOT_EOK };
	struct adjust_params params = {.zc = &zc, .ch = NULL };
	zs_scanner_t *sc = zs_scanner_create("test.", KNOT_CLASS_IN, 3600, scanner_process,
	                                     NULL, &params);
	assert(sc);
	ret = zs_scanner_parse(sc, zone_str, zone_str + strlen(zone_str), true);
	assert(ret == 0);

	// Init zone update structure
	changeset_t *ch = &up.change;
	// incremental update will not work for full or minimal adjust, only partial
	// also, this overwrites previous init
	//zone_update_init(&up, &z, UPDATE_INCREMENTAL);

	// Test full adjust
	ret = zone_adjust_full(&up);
	ok(ret == KNOT_EOK && test_zone(zone), "zone adjust: full adjust");
	TEST_VALIDITY(zone, &up, ch, "zone adjust: addition");

	// --- PREV pointer tests ---
#ifdef fixme
	// Add a record
	//zc.z = ch->add;
	params.ch = ch;
	add_and_update(zone, ch, sc, add1);
	TEST_VALIDITY(zone, &up, ch, "zone adjust: addition");

	// Remove a record
	//sc->data = ch->remove;
	add_and_update(zone, ch, sc, add1);
	TEST_VALIDITY(zone, &up, ch, "zone adjust: deletion");

	// Remove the last record
	//sc->data = ch->remove;
	add_and_update(zone, ch, sc, del1);
	TEST_VALIDITY(zone, &up, ch, "zone adjust: delete last");

	// Add record that will become last
	//sc->data = ch->add;
	add_and_update(zone, ch, sc, del1);
	TEST_VALIDITY(zone, &up, ch, "zone adjust: add last");

	// Add and remove records
	//sc->data = ch->add;
	add_and_update(zone, ch, sc, add1);
	//sc->data = ch->remove;
	add_and_update(zone, ch, sc, del2);
	TEST_VALIDITY(zone, &up, ch, "zone adjust: add and remove");

	// --- NSEC3 tests ---

	// Add all NSEC3 records
	//sc->data = ch->add;
	add_and_update(zone, ch, sc, switch_nsec3);
	TEST_VALIDITY(zone, &up, ch, "zone adjust: switch NSEC3");

	// Add new record and its NSEC3
	//sc->data = ch->add;
	add_and_update(zone, ch, sc, add_nsec3);
	TEST_VALIDITY(zone, &up, ch, "zone adjust: add NSEC3");

	// Remove previously added NSEC3
	//sc->data = ch->remove;
	add_and_update(zone, ch, sc, add_nsec3);
	TEST_VALIDITY(zone, &up, ch, "zone adjust: remove NSEC3");

	// --- Additional pointers tests ---

	ok(test_hints(zone, ZONE_HINTS_INIT, 2), "zone adjust: additional hints");

	// Remove glue from zone

	//sc->data = ch->remove;
	add_and_update(zone, ch, sc, remove_glue);
	ok(test_hints(zone, ZONE_HINTS_ADD, 2), "zone adjust: remove glue hints");
#endif
	return 0;
}

