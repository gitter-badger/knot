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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <inttypes.h>

#include "libknot/libknot.h"
#include "libknot/internal/strlcat.h"
#include "libknot/internal/strlcpy.h"
#include "libknot/internal/macros.h"
#include "knot/zone/semantic-check.h"
#include "knot/zone/contents.h"
#include "knot/dnssec/zone-nsec.h"
#include "knot/common/debug.h"
#include "knot/zone/zonefile.h"
#include "knot/zone/adjust.h"
#include "libknot/rdata.h"
#include "knot/zone/zone-dump.h"
#include "libknot/rrtype/naptr.h"
#include "knot/updates/zone-update.h"
#include "knot/updates/apply.h"

#define ERROR(zone, fmt, ...) log_zone_error(zone, "zone loader, " fmt, ##__VA_ARGS__)
#define WARNING(zone, fmt, ...) log_zone_warning(zone, "zone loader, " fmt, ##__VA_ARGS__)
#define INFO(zone, fmt, ...) log_zone_info(zone, "zone loader, " fmt, ##__VA_ARGS__)

void process_error(zs_scanner_t *s)
{
	zcreator_t *zc = s->data;
	const knot_dname_t *zname = zc->up->zone->name;

	ERROR(zname, "%s in zone, file '%s', line %"PRIu64" (%s)",
	      s->stop ? "fatal error" : "error",
	      s->file.name, s->line_counter,
	      zs_strerror(s->error_code));
}

static int add_rdata_to_rr(knot_rrset_t *rrset, const zs_scanner_t *scanner)
{
	return knot_rrset_add_rdata(rrset, scanner->r_data, scanner->r_data_length,
	                         scanner->r_ttl, NULL);
}

static bool handle_err(zcreator_t *zc, const knot_rrset_t *rr, int ret, bool master)
{
	const knot_dname_t *zname = zc->up->zone->name;
	char *rrname = rr ? knot_dname_to_str_alloc(rr->owner) : NULL;
	if (ret == KNOT_EOUTOFZONE) {
		WARNING(zname, "ignoring out-of-zone data, owner '%s'",
		        rrname ? rrname : "unknown");
		free(rrname);
		return true;
	} else if (ret == KNOT_ETTL) {
		free(rrname);
		log_ttl_error(zc->up->zone->name, rr, master);
		// Fail if we're the master for this zone.
		return !master;
	} else {
		ERROR(zname, "failed to process record, owner '%s' (%s)",
		      rrname ? rrname : "unknown", knot_strerror(ret));
		free(rrname);
		return false;
	}
}

void log_ttl_error(const knot_dname_t *zone_name, const knot_rrset_t *rr, bool master)
{
	// Prepare info string.
	char info_str[64] = { '\0' };
	char type_str[16] = { '\0' };
	knot_rrtype_to_string(rr->type, type_str, sizeof(type_str));
	int ret = snprintf(info_str, sizeof(info_str), "record type %s",
	                   type_str);
	if (ret <= 0 || ret >= sizeof(info_str)) {
		*info_str = '\0';
	}

	if (master) {
		log_semantic_error(zone_name, rr->owner, TTL_MISMATCH);
	} else {
		log_semantic_warning(zone_name, rr->owner, TTL_MISMATCH);
	}
}

int zcreator_step(zcreator_t *zc, const knot_rrset_t *rr)
{
	if (zc == NULL || rr == NULL || rr->rrs.rr_count != 1) {
		return KNOT_EINVAL;
	}

	if (rr->type == KNOT_RRTYPE_SOA) {
		const zone_node_t *apex = zone_update_get_apex(zc->up);
		if (node_rrtype_exists(apex, KNOT_RRTYPE_SOA)) {
			// Ignore extra SOA
			return KNOT_EOK;
		}
	}

	int ret = zone_update_add(zc->up, rr);
	if (ret != KNOT_EOK) {
		if (!handle_err(zc, rr, ret, zc->master)) {
			// Fatal error
			return ret;
		}
		if (ret == KNOT_EOUTOFZONE) {
			// Skip out-of-zone record
			return KNOT_EOK;
		}
	}

	const uint16_t qtype = zone_contents_rrset_is_nsec3rel(rr) ? KNOT_RRTYPE_NSEC3 : KNOT_RRTYPE_ANY;
	const zone_node_t *n = zone_update_get_node(zc->up, rr->owner, qtype);
	assert(n);
	return sem_check_node(zc->up, n) ? KNOT_EOK : KNOT_ESEMCHECK;
}

/*! \brief Creates RR from parser input, passes it to handling function. */
static void scanner_process(zs_scanner_t *scanner)
{
	zcreator_t *zc = scanner->data;
	if (zc->ret != KNOT_EOK) {
		scanner->stop = true;
		return;
	}

	knot_dname_t *owner = knot_dname_copy(scanner->r_owner, NULL);
	if (owner == NULL) {
		zc->ret = KNOT_ENOMEM;
		return;
	}

	knot_rrset_t rr;
	knot_rrset_init(&rr, owner, scanner->r_type, scanner->r_class);
	int ret = add_rdata_to_rr(&rr, scanner);
	if (ret != KNOT_EOK) {
		char *rr_name = knot_dname_to_str_alloc(rr.owner);
		const knot_dname_t *zname = zc->up->zone->name;
		ERROR(zname, "failed to add RDATA, file '%s', line %"PRIu64", owner '%s'",
		      scanner->file.name, scanner->line_counter, rr_name);
		free(rr_name);
		knot_dname_free(&owner, NULL);
		zc->ret = ret;
		return;
	}

	/* Convert RDATA dnames to lowercase before adding to zone. */
	ret = knot_rrset_rr_to_canonical(&rr);
	if (ret != KNOT_EOK) {
		knot_dname_free(&owner, NULL);
		zc->ret = ret;
		return;
	}

	zc->ret = zcreator_step(zc, &rr);
	knot_dname_free(&owner, NULL);
	knot_rdataset_clear(&rr.rrs, NULL);
}

int zonefile_open(zloader_t *loader, const char *source,
                  const knot_dname_t *origin)
{
	if (!loader) {
		return KNOT_EINVAL;
	}

	/* Check zone file. */
	if (access(source, F_OK | R_OK) != 0) {
		return KNOT_EACCES;
	}

	/* Create context. */
	zcreator_t *zc = malloc(sizeof(zcreator_t));
	if (zc == NULL) {
		return KNOT_ENOMEM;
	}
	memset(zc, 0, sizeof(zcreator_t));

	/* Prepare textual owner for zone scanner. */
	char *origin_str = knot_dname_to_str_alloc(origin);
	if (origin_str == NULL) {
		free(zc);
		return KNOT_ENOMEM;
	}

	/* Create file loader. */
	memset(loader, 0, sizeof(zloader_t));
	loader->scanner = zs_scanner_create(origin_str, KNOT_CLASS_IN, 3600,
	                                    scanner_process, process_error,
	                                    zc);
	if (loader->scanner == NULL) {
		free(origin_str);
		free(zc);
		return KNOT_ERROR;
	}

	loader->source = strdup(source);
	loader->origin = origin_str;
	loader->creator = zc;

	return KNOT_EOK;
}

int zonefile_load(zloader_t *loader)
{
	zcreator_t *zc = loader->creator;
	zone_t *zone = zc->up->zone;
	const knot_dname_t *zname = zone->name;

	// Load zone contents from a file.
	int ret = zs_scanner_parse_file(loader->scanner, loader->source);
	if (ret != 0 && loader->scanner->error_counter == 0) {
		ERROR(zname, "failed to load zone, file '%s' (%s)",
		      loader->source, zs_strerror(loader->scanner->error_code));
		return KNOT_EPARSEFAIL;
	}

	if (zc->ret != KNOT_EOK) {
		ERROR(zname, "failed to load zone, file '%s' (%s)",
		      loader->source, knot_strerror(zc->ret));
		return ret;
	}

	if (loader->scanner->error_counter > 0) {
		ERROR(zname, "failed to load zone, file '%s', %"PRIu64" errors",
		      loader->source, loader->scanner->error_counter);
		return KNOT_EPARSEFAIL;
	}

	if (!node_rrtype_exists(zone_update_get_apex(zc->up), KNOT_RRTYPE_SOA)) {
		ERROR(zname, "no SOA record, file '%s'", loader->source);
		return KNOT_EMALF;
	}
	
	// Apply possible changes to the zone contents.
	/*if (!journal_exists(zone->conf->ixfr_db)) {
		return KNOT_EOK;
	}*/

	/* Fetch SOA serial. */
	const uint32_t serial = zone_update_current_serial(zc->up);

	changeset_t ch;
	ret = changeset_init(&ch, zname);
	if (ret != KNOT_EOK) {
		return ret;
	}
	char *path = conf_journalfile(conf(), zone->name);
	ret = journal_load_changesets(path, &ch, serial, serial - 1);
	if ((ret != KNOT_EOK && ret != KNOT_ERANGE) || changeset_empty(&ch)) {
		changeset_clear(&ch);
		/* Absence of records is not an error. */
		if (ret == KNOT_ENOENT) {
			return KNOT_EOK;
		} else {
			return ret;
		}
	}
	free(path);

	// Apply changes fetched from jurnal. */
	ret = apply_changeset_directly(zc->up->new_cont, &ch);
	changeset_clear(&ch);
	return ret;
}

/*! \brief Return zone file mtime. */
time_t zonefile_mtime(const char *path)
{
	struct stat zonefile_st = { 0 };
	int result = stat(path, &zonefile_st);
	if (result < 0) {
		return result;
	}
	return zonefile_st.st_mtime;
}

/*! \brief Moved from zones.c, no doc. @mvavrusa */
static int zones_open_free_filename(const char *old_name, char **new_name)
{
	/* find zone name not present on the disk */
	char *suffix = ".XXXXXX";
	size_t name_size = strlen(old_name);
	size_t max_size = name_size + strlen(suffix) + 1;
	*new_name = malloc(max_size);
	if (*new_name == NULL) {
		return -1;
	}
	strlcpy(*new_name, old_name, max_size);
	strlcat(*new_name, suffix, max_size);
	mode_t old_mode = umask(077);
	int fd = mkstemp(*new_name);
	UNUSED(umask(old_mode));
	if (fd < 0) {
		free(*new_name);
		*new_name = NULL;
	}

	return fd;
}

int zonefile_write(const char *path, zone_read_t *zr,
                   const struct sockaddr_storage *from)
{
	if (!zr || !path) {
		return KNOT_EINVAL;
	}

	char *new_fname = NULL;
	int fd = zones_open_free_filename(path, &new_fname);
	if (fd < 0) {
		return KNOT_EWRITABLE;
	}

	const knot_dname_t *zname = zr->zone->name;

	FILE *f = fdopen(fd, "w");
	if (f == NULL) {
		WARNING(zname, "failed to open zone, file '%s' (%s)",
		        new_fname, knot_strerror(knot_map_errno()));
		unlink(new_fname);
		free(new_fname);
		return KNOT_ERROR;
	}

	if (zone_dump_text(zr, from, f) != KNOT_EOK) {
		WARNING(zname, "failed to save zone, file '%s'", new_fname);
		fclose(f);
		unlink(new_fname);
		free(new_fname);
		return KNOT_ERROR;
	}

	/* Set zone file rights to 0640. */
	fchmod(fd, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP);

	/* Swap temporary zonefile and new zonefile. */
	fclose(f);

	int ret = rename(new_fname, path);
	if (ret < 0 && ret != EEXIST) {
		WARNING(zname, "failed to swap zone files, old '%s', new '%s'",
		        path, new_fname);
		unlink(new_fname);
		free(new_fname);
		return KNOT_ERROR;
	}

	free(new_fname);
	return KNOT_EOK;
}

void zonefile_close(zloader_t *loader)
{
	if (!loader) {
		return;
	}

	zs_scanner_free(loader->scanner);

	free(loader->source);
	free(loader->origin);
	free(loader->creator);
}

#undef ERROR
#undef WARNING
#undef INFO
