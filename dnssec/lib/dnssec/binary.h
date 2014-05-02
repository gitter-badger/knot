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
/*!
 * \file
 *
 * Binary data container.
 */

#pragma once

#include <stdint.h>
#include <stdlib.h>

/*!
 * Universal structure to hold binary data.
 */
typedef struct dnssec_binary {
	size_t size;
	union {
		uint8_t *data;
		const uint8_t *const_data;
	};
} dnssec_binary_t;

/*!
 * Allocate new binary data structure.
 *
 * \param[out] data  Binary to be allocated.
 * \param[in]  size  Requested size of the binary.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int dnssec_binary_alloc(dnssec_binary_t *data, size_t size);

/*!
 * Free content of binary structure.
 *
 * \param binary  Binary structure to be freed.
 */
void dnssec_binary_free(dnssec_binary_t *binary);

/*!
 * Create a copy of a binary structure.
 *
 * \param[in]  from  Source of the copy.
 * \param[out] to    Target of the copy.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int dnssec_binary_dup(const dnssec_binary_t *from, dnssec_binary_t *to);

/*!
 * Resize binary structure to a new size.
 *
 * Internally uses realloc, which means that this function can be also used
 * as a malloc or free.
 *
 * \param data      Binary to be resized.
 * \param new_size  New size.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int dnssec_binary_resize(dnssec_binary_t *data, size_t new_size);

/*!
 * Compare two binary structures (equivalent of memcmp).
 *
 * \note NULL sorts before data.
 *
 * \param one  First binary.
 * \param two  Second binary.
 *
 * \return 0 if one equals two, <0 if one sorts before two, >0 otherwise.
 */
int dnssec_binary_cmp(const dnssec_binary_t *one, const dnssec_binary_t *two);

/*!
 * Trim leading zeroes from the binary data.
 *
 * If the input are zeroes only, the last zero will be preserved.
 *
 * \param binary  Input to be trimmed.
 */
void dnssec_binary_ltrim(dnssec_binary_t *binary);

/*!
 * Allocate binary from Base64 encoded string.
 *
 * \param[in]  base64  Base64 encoded data.
 * \param[out] binary  Decoded binary data.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int dnssec_binary_from_base64(const dnssec_binary_t *base64,
			      dnssec_binary_t *binary);
