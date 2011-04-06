#include <config.h>
#include <stdint.h>
#include <malloc.h>
#include <assert.h>

#include "dnslib/dnslib-common.h"
#include "dnslib/rrset.h"
#include "dnslib/descriptor.h"
#include "dnslib/error.h"

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

dnslib_rrset_t *dnslib_rrset_new(dnslib_dname_t *owner, uint16_t type, 
                                 uint16_t rclass, uint32_t ttl)
{
	dnslib_rrset_t *ret = malloc(sizeof(dnslib_rrset_t));
	if (ret == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	ret->rdata = NULL;

	ret->owner = owner;
	ret->type = type;
	ret->rclass = rclass;
	ret->ttl = ttl;
	ret->rrsigs = NULL;

	return ret;
}

/*----------------------------------------------------------------------------*/

int dnslib_rrset_add_rdata(dnslib_rrset_t *rrset, dnslib_rdata_t *rdata)
{
	if (rrset == NULL || rdata == NULL) {
		return DNSLIB_EBADARG;
	}

	if (rrset->rdata == NULL) {
		rrset->rdata = rdata;
		rrset->rdata->next = rrset->rdata;
	} else {
		dnslib_rdata_t *tmp;

		tmp = rrset->rdata;

		while (tmp->next != rrset->rdata) {
			tmp = tmp->next;
		}
		rdata->next = tmp->next;
		tmp->next = rdata;
	}
	return DNSLIB_EOK;
}

/*----------------------------------------------------------------------------*/

int dnslib_rrset_set_rrsigs(dnslib_rrset_t *rrset, dnslib_rrset_t *rrsigs)
{
	if (rrset == NULL || rrsigs == NULL) {
		return DNSLIB_EBADARG;
	}

	rrset->rrsigs = rrsigs;
	return DNSLIB_EOK;
}

/*----------------------------------------------------------------------------*/

const dnslib_dname_t *dnslib_rrset_owner(const dnslib_rrset_t *rrset)
{
	return rrset->owner;
}

/*----------------------------------------------------------------------------*/

uint16_t dnslib_rrset_type(const dnslib_rrset_t *rrset)
{
	return rrset->type;
}

/*----------------------------------------------------------------------------*/

uint16_t dnslib_rrset_class(const dnslib_rrset_t *rrset)
{
	return rrset->rclass;
}

/*----------------------------------------------------------------------------*/

uint32_t dnslib_rrset_ttl(const dnslib_rrset_t *rrset)
{
	return rrset->ttl;
}

/*----------------------------------------------------------------------------*/

const dnslib_rdata_t *dnslib_rrset_rdata(const dnslib_rrset_t *rrset)
{
	return rrset->rdata;
}

/*----------------------------------------------------------------------------*/

const dnslib_rdata_t *dnslib_rrset_rdata_next(const dnslib_rrset_t *rrset,
                                              const dnslib_rdata_t *rdata)
{
	if (rdata->next == rrset->rdata) {
		return NULL;
	} else {
		return rdata->next;
	}
}

/*----------------------------------------------------------------------------*/

dnslib_rdata_t *dnslib_rrset_get_rdata(dnslib_rrset_t *rrset)
{
	if (rrset == NULL) {
		return NULL;
	} else {
		return rrset->rdata;
	}
}

/*----------------------------------------------------------------------------*/

const dnslib_rrset_t *dnslib_rrset_rrsigs(const dnslib_rrset_t *rrset)
{
	if (rrset == NULL) {
		return NULL;
	} else {
		return rrset->rrsigs;
	}
}

/*----------------------------------------------------------------------------*/

void dnslib_rrset_free(dnslib_rrset_t **rrset)
{
	if (rrset == NULL || *rrset == NULL) {
		return;
	}

	free(*rrset);
	*rrset = NULL;
}

/*----------------------------------------------------------------------------*/

void dnslib_rrset_deep_free(dnslib_rrset_t **rrset, int free_owner,
                            int free_rdata_dnames)
{
	if (rrset == NULL || *rrset == NULL) {
		return;
	}

	dnslib_rdata_t *tmp_rdata;
	dnslib_rdata_t *next_rdata;
	tmp_rdata = (*rrset)->rdata;

	while ((tmp_rdata != NULL) && (tmp_rdata->next != (*rrset)->rdata) &&
		(tmp_rdata->next != NULL)) {
		next_rdata = tmp_rdata->next;
		dnslib_rdata_deep_free(&tmp_rdata, (*rrset)->type,
		                       free_rdata_dnames);
		tmp_rdata = next_rdata;
	}

	dnslib_rdata_deep_free(&tmp_rdata, (*rrset)->type, free_rdata_dnames);

	// RRSIGs should have the same owner as this RRSet, so do not delete it
	if ((*rrset)->rrsigs != NULL) {
		dnslib_rrset_deep_free(&(*rrset)->rrsigs, 0, free_rdata_dnames);
	}

	if (free_owner) {
		dnslib_dname_free(&(*rrset)->owner);
	}

	free(*rrset);
	*rrset = NULL;
}

/*----------------------------------------------------------------------------*/

int dnslib_rrset_merge(void **r1, void **r2)
{
	dnslib_rrset_t *rrset1 = (dnslib_rrset_t *)(*r1);
	dnslib_rrset_t *rrset2 = (dnslib_rrset_t *)(*r2);

	if (rrset1->owner != rrset2->owner
	    || rrset1->rclass != rrset2->rclass
	    || rrset1->type != rrset2->type
	    || rrset1->ttl != rrset2->ttl) {
		return DNSLIB_EBADARG;
	}

	// add all RDATAs from rrset2 to rrset1 (i.e. concatenate linked lists)

	// no RDATA in RRSet 1
	if (rrset1->rdata == NULL) {
		rrset1->rdata = rrset2->rdata;
		return DNSLIB_EOK;
	}

	dnslib_rdata_t *tmp_rdata = rrset1->rdata;

	while (tmp_rdata->next != rrset1->rdata) {
		tmp_rdata = tmp_rdata->next;
	}

	tmp_rdata->next = rrset2->rdata;

	tmp_rdata = rrset2->rdata; //maybe unnecessary, but is clearer

	while (tmp_rdata->next != rrset2->rdata) {
		tmp_rdata = tmp_rdata->next;
	}

	tmp_rdata->next = rrset1->rdata;

	return DNSLIB_EOK;
}
