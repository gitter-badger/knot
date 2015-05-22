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
/*!
 * \file mempattern.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief Memory allocation related functions.
 *
 * \addtogroup alloc
 * @{
 */

#pragma once

#include <stddef.h>
#include "libknot/mempattern.h"

/* Default memory block size. */
#define MM_DEFAULT_BLKSIZE 4096

#define mm_alloc_t knot_mm_alloc_t
#define mm_free_t knot_mm_free_t
#define mm_flush_t knot_mm_flush_t
#define mm_ctx knot_mm_ctx
#define mm_ctx_t knot_mm_ctx_t
#define mm_alloc knot_mm_alloc
#define mm_realloc knot_mm_realloc
#define mm_free knot_mm_free
#define mm_ctx_init knot_mm_ctx_init
#define mm_ctx_mempool knot_mm_ctx_mempool

/*! @} */
