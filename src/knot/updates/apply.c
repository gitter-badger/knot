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

#include <assert.h>
#include <urcu.h>

#include "knot/updates/apply.h"

#include "knot/zone/zone.h"
#include "knot/updates/changesets.h"
#include "knot/updates/zone-update.h"
#include "knot/zone/zonefile.h"
#include "knot/zone/adjust.h"
#include "libknot/internal/lists.h"
#include "libknot/internal/macros.h"
#include "libknot/rrtype/soa.h"
#include "libknot/rrtype/rrsig.h"

/* --------------------------- Update cleanup ------------------------------- */

/*!
 * \brief Post update cleanup: frees data that are in the tree that will not
 *        be used (old tree if success, new tree if failure).
 *          Freed data:
 *           - actual data inside knot_rrs_t. (the rest is part of the node)
 */
static void rrs_list_clear(list_t *l, mm_ctx_t *mm)
{
	if (l == NULL) {
		return;
	}

	ptrnode_t *n;
	node_t *nxt;
	WALK_LIST_DELSAFE(n, nxt, *l) {
		mm_free(mm, (void *)n->d);
		mm_free(mm, n);
	};
}

/*! \brief Frees additional data from single node */
static int free_additional(zone_node_t *node, void *data)
{
	UNUSED(data);
	for (uint16_t i = 0; i < node->rrset_count; ++i) {
		struct rr_data *rr_data = &node->rrs[i];
		if (rr_data->additional) {
			free(rr_data->additional);
			rr_data->additional = NULL;
		}
	}

	return KNOT_EOK;
}

static int free_node_data(zone_node_t *node, void *data)
{
	if (node) {
		node_free(&node, NULL);
	}

	return KNOT_EOK;
}

/* -------------------- Changeset application helpers ----------------------- */

/*! \brief Replaces rdataset of given type with a copy. */
static int replace_rdataset_with_copy(zone_node_t *node, uint16_t type)
{
	// Find data to copy.
	struct rr_data *data = NULL;
	for (uint16_t i = 0; i < node->rrset_count; ++i) {
		if (node->rrs[i].type == type) {
			data = &node->rrs[i];
			break;
		}
	}
	assert(data);

	// Create new data.
	knot_rdataset_t *rrs = &data->rrs;
	void *copy = malloc(knot_rdataset_size(rrs));
	if (copy == NULL) {
		return KNOT_ENOMEM;
	}

	memcpy(copy, rrs->data, knot_rdataset_size(rrs));

	// Store new data into node RRS.
	rrs->data = copy;

	return KNOT_EOK;
}

/*! \brief Stores RR data for update cleanup. */
static void clear_new_rrs(zone_node_t *node, uint16_t type)
{
	knot_rdataset_t *new_rrs = node_rdataset(node, type);
	if (new_rrs) {
		knot_rdataset_clear(new_rrs, NULL);
	}
}

/*! \brief Stores RR data for update cleanup. */
static int add_old_data(changeset_t *chset, knot_rdata_t *old_data)
{
	if (ptrlist_add(&chset->old_data, old_data, NULL) == NULL) {
		return KNOT_ENOMEM;
	}

	return KNOT_EOK;
}

/*! \brief Stores RR data for update rollback. */
static int add_new_data(changeset_t *chset, knot_rdata_t *new_data)
{
	if (ptrlist_add(&chset->new_data, new_data, NULL) == NULL) {
		return KNOT_ENOMEM;
	}

	return KNOT_EOK;
}

/*! \brief Returns true if given RR is present in node and can be removed. */
static bool can_remove(const zone_node_t *node, const knot_rrset_t *rr)
{
	if (node == NULL) {
		// Node does not exist, cannot remove anything.
		return false;
	}
	const knot_rdataset_t *node_rrs = node_rdataset(node, rr->type);
	if (node_rrs == NULL) {
		// Node does not have this type at all.
		return false;
	}

	const bool compare_ttls = false;
	for (uint16_t i = 0; i < rr->rrs.rr_count; ++i) {
		knot_rdata_t *rr_cmp = knot_rdataset_at(&rr->rrs, i);
		if (knot_rdataset_member(node_rrs, rr_cmp, compare_ttls)) {
			// At least one RR matches.
			return true;
		}
	}

	// Node does have the type, but no RRs match.
	return false;
}

/*! \brief Removes single RR from zone contents. */
static int remove_rr(zone_contents_t *zone, zone_tree_t *tree, zone_node_t *node,
                     const knot_rrset_t *rr, changeset_t *chset)
{
	knot_rrset_t removed_rrset = node_rrset(node, rr->type);
	knot_rdata_t *old_data = removed_rrset.rrs.data;
	int ret = replace_rdataset_with_copy(node, rr->type);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Store old data for cleanup.
	ret = add_old_data(chset, old_data);
	if (ret != KNOT_EOK) {
		clear_new_rrs(node, rr->type);
		return ret;
	}

	knot_rdataset_t *changed_rrs = node_rdataset(node, rr->type);
	// Subtract changeset RRS from node RRS.
	ret = knot_rdataset_subtract(changed_rrs, &rr->rrs, NULL);
	if (ret != KNOT_EOK) {
		clear_new_rrs(node, rr->type);
		return ret;
	}

	if (changed_rrs->rr_count > 0) {
		// Subtraction left some data in RRSet, store it for rollback.
		ret = add_new_data(chset, changed_rrs->data);
		if (ret != KNOT_EOK) {
			knot_rdataset_clear(changed_rrs, NULL);
			return ret;
		}
	} else {
		// RRSet is empty now, remove it from node, all data freed.
		node_remove_rdataset(node, rr->type);
		// If node is empty now, delete it from zone tree.
		if (node->rrset_count == 0) {
			zone_contents_delete_empty_node(zone, tree, node);
		}
	}

	return KNOT_EOK;
}

/*! \brief Removes all RRs from changeset from zone contents. */
static int apply_remove(zone_contents_t *contents, changeset_t *chset)
{
	changeset_iter_t itt;
	changeset_iter_rem(&itt, chset, false);

	knot_rrset_t rr = changeset_iter_next(&itt);
	while (!knot_rrset_empty(&rr)) {
		// Find node for this owner
		zone_node_t *node = zone_contents_find_node_for_rr(contents, &rr);
		if (!can_remove(node, &rr)) {
			// Nothing to remove from, skip.
			rr = changeset_iter_next(&itt);
			continue;
		}

		zone_tree_t *tree = zone_contents_rrset_is_nsec3rel(&rr) ?
		                    contents->nsec3_nodes : contents->nodes;
		int ret = remove_rr(contents, tree, node, &rr, chset);
		if (ret != KNOT_EOK) {
			changeset_iter_clear(&itt);
			return ret;
		}

		rr = changeset_iter_next(&itt);
	}
	changeset_iter_clear(&itt);

	return KNOT_EOK;
}

/*! \brief Adds a single RR into zone contents. */
static int add_rr(const zone_contents_t *zone, zone_node_t *node,
                  const knot_rrset_t *rr, changeset_t *chset, bool master)
{
	knot_rrset_t changed_rrset = node_rrset(node, rr->type);
	if (!knot_rrset_empty(&changed_rrset)) {
		// Modifying existing RRSet.
		knot_rdata_t *old_data = changed_rrset.rrs.data;
		int ret = replace_rdataset_with_copy(node, rr->type);
		if (ret != KNOT_EOK) {
			return ret;
		}

		// Store old RRS for cleanup.
		ret = add_old_data(chset, old_data);
		if (ret != KNOT_EOK) {
			clear_new_rrs(node, rr->type);
			return ret;
		}
	}

	// Insert new RR to RRSet, data will be copied.
	int ret = node_add_rrset(node, rr, NULL);
	if (ret == KNOT_EOK || ret == KNOT_ETTL) {
		// RR added, store for possible rollback.
		knot_rdataset_t *rrs = node_rdataset(node, rr->type);
		int data_ret = add_new_data(chset, rrs->data);
		if (data_ret != KNOT_EOK) {
			knot_rdataset_clear(rrs, NULL);
			return data_ret;
		}

		if (ret == KNOT_ETTL) {
			// Handle possible TTL errors.
			log_ttl_error(zone->apex->owner, rr, master);
			if (!master) {
				// TTL errors fatal only for master.
				return KNOT_EOK;
			}
		}
	}

	return ret;
}

/*! \brief Adds all RRs from changeset into zone contents. */
static int apply_add(zone_contents_t *contents, changeset_t *chset,
                     bool master)
{
	changeset_iter_t itt;
	changeset_iter_add(&itt, chset, false);

	knot_rrset_t rr = changeset_iter_next(&itt);
	while(!knot_rrset_empty(&rr)) {
		// Get or create node with this owner
		zone_node_t *node = zone_contents_get_node_for_rr(contents, &rr);
		if (node == NULL) {
			changeset_iter_clear(&itt);
			return KNOT_ENOMEM;
		}

		int ret = add_rr(contents, node, &rr, chset, master);
		if (ret != KNOT_EOK) {
			changeset_iter_clear(&itt);
			return ret;
		}
		rr = changeset_iter_next(&itt);
	}
	changeset_iter_clear(&itt);

	return KNOT_EOK;
}

/*! \brief Replace old SOA with a new one. */
static int apply_replace_soa(zone_contents_t *contents, changeset_t *chset)
{
	assert(chset->soa_from && chset->soa_to);
	int ret = remove_rr(contents, contents->nodes, contents->apex, chset->soa_from, chset);
	if (ret != KNOT_EOK) {
		return ret;
	}

	assert(!node_rrtype_exists(contents->apex, KNOT_RRTYPE_SOA));

	return add_rr(contents, contents->apex, chset->soa_to, chset, false);
}

/*! \brief Apply single change to zone contents structure. */
static int apply_single(zone_contents_t *contents, changeset_t *chset,
                           bool master)
{
	/*
	 * Applies one changeset to the zone. Checks if the changeset may be
	 * applied (i.e. the origin SOA (soa_from) has the same serial as
	 * SOA in the zone apex.
	 */

	if (chset->soa_from == NULL || chset->soa_to == NULL) {
		return KNOT_EINVAL;
	}

	// check if serial matches
	const knot_rdataset_t *soa = node_rdataset(contents->apex, KNOT_RRTYPE_SOA);
	if (soa == NULL || knot_soa_serial(soa) != knot_soa_serial(&chset->soa_from->rrs)) {
		return KNOT_EINVAL;
	}

	int ret = apply_remove(contents, chset);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = apply_add(contents, chset, master);
	if (ret != KNOT_EOK) {
		return ret;
	}

	return apply_replace_soa(contents, chset);
}

/* --------------------- Zone copy and finalization ------------------------- */

/*! \brief Creates a shallow zone contents copy. */
static int prepare_zone_copy(zone_contents_t *old_contents,
                             zone_contents_t **new_contents)
{
	if (old_contents == NULL || new_contents == NULL) {
		return KNOT_EINVAL;
	}

	/*
	 * Create a shallow copy of the zone, so that the structures may be
	 * updated.
	 *
	 * This will create new zone contents structures (normal nodes' tree,
	 * NSEC3 tree), and copy all nodes.
	 * The data in the nodes (RRSets) remain the same though.
	 */
	zone_contents_t *contents_copy = NULL;
	int ret = zone_contents_shallow_copy(old_contents, &contents_copy);
	if (ret != KNOT_EOK) {
		return ret;
	}

	*new_contents = contents_copy;

	return KNOT_EOK;
}

/* ------------------------------- API -------------------------------------- */

int apply_changeset(zone_t *zone, changeset_t *change, zone_contents_t **new_contents)
{
	if (zone == NULL || change == NULL || new_contents == NULL) {
		return KNOT_EINVAL;
	}

	zone_contents_t *old_contents = zone->contents;
	if (!old_contents) {
		return KNOT_EINVAL;
	}

	zone_contents_t *contents_copy = NULL;
	int ret = prepare_zone_copy(old_contents, &contents_copy);
	if (ret != KNOT_EOK) {
		return ret;
	}

	rcu_read_lock();
	bool is_master = zone_is_master(zone);
	rcu_read_unlock();

	ret = apply_single(contents_copy, change, is_master);
	if (ret != KNOT_EOK) {
		update_rollback(change);
		update_free_zone(&contents_copy);
		return ret;
	}

	*new_contents = contents_copy;

	return KNOT_EOK;
}

int apply_changeset_directly(zone_contents_t *contents, changeset_t *ch)
{
	if (contents == NULL || ch == NULL) {
		return KNOT_EINVAL;
	}

	const bool master = true; // Only DNSSEC changesets are applied directly.
	int ret = apply_single(contents, ch, master);
	if (ret != KNOT_EOK) {
		update_cleanup(ch);
		return ret;
	}

	return KNOT_EOK;
}

void update_cleanup(changeset_t *change)
{
	if (change) {
		// Delete old RR data
		rrs_list_clear(&change->old_data, NULL);
		init_list(&change->old_data);
		// Keep new RR data
		ptrlist_free(&change->new_data, NULL);
		init_list(&change->new_data);
	}
}

void update_rollback(changeset_t *change)
{
	if (change) {
		// Delete new RR data
		rrs_list_clear(&change->new_data, NULL);
		init_list(&change->new_data);
		// Keep old RR data
		ptrlist_free(&change->old_data, NULL);
		init_list(&change->old_data);
	}
}

void update_free_zone(zone_contents_t **contents)
{
	zone_tree_apply((*contents)->nodes, free_additional, NULL, false);
	zone_tree_apply((*contents)->nodes, free_node_data, NULL, false);
	zone_tree_apply((*contents)->nsec3_nodes, free_node_data, NULL, false);

	free(*contents);
	*contents = NULL;
}
