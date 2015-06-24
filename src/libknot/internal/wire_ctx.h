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

#pragma once

#include <assert.h>
#include <stdbool.h>
#include <string.h>

#include "errcode.h"
#include "libknot/rdata.h"

// For unit testing replace assert macro
#ifdef UNIT_TESTING
	extern void mock_assert(const int result, const char* const expression,
				const char * const file, const int line);
	#undef assert
	#define assert(expression) \
	mock_assert(!!(expression), #expression, __FILE__, __LINE__);
#endif

/**
 * \brief Struct for keep position and size with wire data
 */
typedef struct wire_ctx {
	uint8_t *wire;
	size_t size;
	uint8_t *position;
	int error;
	bool readonly;
} wire_ctx_t;


static inline wire_ctx_t wire_ctx_init(uint8_t *data, size_t size)
{
	assert(data);

	wire_ctx_t result = {
		.wire = data,
		.size = size,
		.position = data,
		.error = KNOT_EOK,
		.readonly = false,
	};
	return result;
}

/**
 * \brief Initialize strucuture from const data.
 *
 * Every write will fail on assertion. If assertion is disabled then
 * no write is performed, and error is set to KNOT_ESPACE.
 *
 */
static inline wire_ctx_t wire_ctx_init_const(const uint8_t *data, size_t size)
{
	assert(data);

	wire_ctx_t result = {
		.wire = (uint8_t*) data,
		.size = size,
		.position = (uint8_t*) data,
		.error = KNOT_EOK,
		.readonly = true,
	};
	return result;
}

static inline wire_ctx_t wire_ctx_init_rdata(const knot_rdata_t *rdata)
{
	assert(rdata);
	return wire_ctx_init_const(knot_rdata_data(rdata), knot_rdata_rdlen(rdata));
}

/**
 * \brief Set whole data to zero.
 */
static inline void wire_ctx_clear(wire_ctx_t *ctx)
{
	assert(ctx);
	memset(ctx->wire, 0, ctx->size);
}

/**
 * \brief Set position offset from begin
 */
static inline void wire_ctx_setpos(wire_ctx_t *ctx, size_t offset)
{
	assert(ctx);
	ctx->position = ctx->wire + offset;
}

/**
 * \brief Add offset to current position
 *
 * \note Cannot seek before actual data
 */
static inline void wire_ctx_seek(wire_ctx_t *ctx, ssize_t offset)
{
	assert(ctx);
	ctx->position += offset;
	if (ctx->position < ctx->wire) {
		ctx->position = ctx->wire;
	}
}

/**
 * \brief Gets actual position
 * \return position from begin
 */
static inline size_t wire_ctx_tell(wire_ctx_t *ctx)
{
	assert(ctx);
	return ctx->position - ctx->wire;
}

/**
 * \brief Gets available bytes
 * \return Number of bytes to end
 */
static inline size_t wire_ctx_available(wire_ctx_t *ctx)
{
	assert(ctx);

	size_t position = wire_ctx_tell(ctx);

	return ctx->size > position ? (ctx->size - position) : 0;
}

static inline uint8_t wire_ctx_read_u8(wire_ctx_t *ctx)
{
	assert(ctx);

	if (ctx->position + sizeof(uint8_t) > ctx->wire + ctx->size) {
		ctx->error = KNOT_EFEWDATA;
		return 0;
	}

	uint8_t result = *ctx->position;
	ctx->position += sizeof(uint8_t);

	return result;
}

static inline uint16_t wire_ctx_read_u16(wire_ctx_t *ctx)
{
	assert(ctx);

	if (ctx->position + sizeof(uint16_t) > ctx->wire + ctx->size) {
		ctx->error = KNOT_EFEWDATA;
		return 0;
	}

	uint16_t result = *((uint16_t *)ctx->position);
	ctx->position += sizeof(uint16_t);

	return be16toh(result);
}

static inline uint32_t wire_ctx_read_u32(wire_ctx_t *ctx)
{
	assert(ctx);

	if (ctx->position + sizeof(uint32_t) > ctx->wire + ctx->size) {
		ctx->error = KNOT_EFEWDATA;
		return 0;
	}

	uint32_t result = *((uint32_t *)ctx->position);
	ctx->position += sizeof(uint32_t);

	return be32toh(result);
}

static inline void wire_ctx_read(wire_ctx_t *ctx, uint8_t *data, size_t size)
{
	assert(ctx);
	assert(data);

	if (ctx->position + size > ctx->wire + ctx->size) {
		ctx->error = KNOT_EFEWDATA;
		return;
	}

	memmove(data, ctx->position, size);
	ctx->position += size;
}

static inline int wire_ctx_can_write(wire_ctx_t *ctx, size_t size)
{
	assert(ctx);
	return !ctx->readonly && ctx->position + size <= ctx->wire + ctx->size;
}

static inline void wire_ctx_write_u8(wire_ctx_t *ctx, uint8_t value)
{
	assert(ctx);
	assert(!ctx->readonly);

	if (!wire_ctx_can_write(ctx, sizeof(uint8_t))) {
		ctx->error = KNOT_ESPACE;
		return;
	}

	*ctx->position = value;
	ctx->position += sizeof(uint8_t);
}

static inline void wire_ctx_write_u16(wire_ctx_t *ctx, uint16_t value)
{
	assert(ctx);
	assert(!ctx->readonly);

	if (!wire_ctx_can_write(ctx, sizeof(uint16_t))) {
		ctx->error = KNOT_ESPACE;
		return;
	}

	*((uint16_t *)ctx->position) = htobe16(value);
	ctx->position += sizeof(uint16_t);
}

static inline void wire_ctx_write_u32(wire_ctx_t *ctx, uint32_t value)
{
	assert(ctx);
	assert(!ctx->readonly);

	if (!wire_ctx_can_write(ctx, sizeof(uint32_t))) {
		ctx->error = KNOT_ESPACE;
		return;
	}

	*((uint32_t *)ctx->position) = htobe32(value);
	ctx->position += sizeof(uint32_t);
}

static inline void wire_ctx_write_u48(wire_ctx_t *ctx, uint64_t value)
{
	assert(ctx);
	assert(!ctx->readonly);

	if (!wire_ctx_can_write(ctx, 6)) {
		ctx->error = KNOT_ESPACE;
		return;
	}

	uint64_t swapped = htobe64(value << 8);
	memcpy(ctx->position, (uint8_t *)&swapped + 1, 6);
	ctx->position += 6;
}

static inline void wire_ctx_write_u64(wire_ctx_t *ctx, uint64_t value)
{
	assert(ctx);
	assert(!ctx->readonly);

	if (!wire_ctx_can_write(ctx, sizeof(uint64_t))) {
		ctx->error = KNOT_ESPACE;
		return;
	}

	*((uint64_t *)ctx->position) = htobe64(value);
	ctx->position += sizeof(uint64_t);
}


/**
 * \brief Write data to wire without endian transaltion
 *
 * \note It is possible to pass NULL for data if size is zero. Memcpy with NULL
 * src pointer has undefined behavior.
 *
 * \param data pointer to data, or NULL if size is 0
 * \param size size of data to write
 */
static inline void wire_ctx_write(wire_ctx_t *ctx, const uint8_t *data, size_t size)
{
	assert(ctx);
	if (size == 0) {
		return;
	}
	assert(data);
	assert(!ctx->readonly);

	if (!wire_ctx_can_write(ctx, size)) {
		ctx->error = KNOT_ESPACE;
		return;
	}

	memmove(ctx->position, data, size);
	ctx->position += size;
}