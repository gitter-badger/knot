/*!
 * \file parser-util.h
 *
 * \author NLnet Labs
 *         Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *         See LICENSE for the license.
 *
 * \brief Zone compiler utility functions.
 *
 * \addtogroup zoneparser
 * @{
 */

#ifndef _KNOT_PARSER_UTIL_H_
#define _KNOT_PARSER_UTIL_H_

#include <assert.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <netinet/in.h>
#include <netdb.h>

#include "zcompile/zcompile.h"
#include "dnslib/descriptor.h"

int inet_pton4(const char *src, uint8_t *dst);
int inet_pton6(const char *src, uint8_t *dst);
//int my_b32_pton(const char *src, uint8_t *target, size_t tsize);
const char *inet_ntop4(const u_char *src, char *dst, size_t size);
const char *inet_ntop6(const u_char *src, char *dst, size_t size);
int inet_pton(int af, const char *src, void *dst);
void b64_initialize_rmap();
int b64_pton_do(char const *src, uint8_t *target, size_t targsize);
int b64_pton_len(char const *src);
int b64_pton(char const *src, uint8_t *target, size_t targsize);
void set_bit(uint8_t bits[], size_t index);
uint32_t strtoserial(const char *nptr, const char **endptr);
void write_uint32(void *dst, uint32_t data);
uint32_t strtottl(const char *nptr, const char **endptr);
time_t mktime_from_utc(const struct tm *tm);
#endif /* _KNOT_PARSER_UTIL_H_ */

/*! @} */
