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
#include "libknot/internal/endian.h"

/*!
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

/*!
 * \brief Initialize strucuture from const data.
 *
 * Every write will fail on assertion. If assertion is disabled then
 * no write is performed, and error is set to KNOT_ESPACE.
 *
 */
static inline wire_ctx_t wire_ctx_init_const(const uint8_t *data, size_t size)
{
	assert(data);

	wire_ctx_t result = wire_ctx_init((uint8_t *) data, size);
	result.readonly = true;
	return result;
}

static inline wire_ctx_t wire_ctx_init_rdata(const knot_rdata_t *rdata)
{
	assert(rdata);
	return wire_ctx_init_const(knot_rdata_data(rdata), knot_rdata_rdlen(rdata));
}

/*!
 * \brief Set whole data to zero.
 */
static inline void wire_ctx_clear(wire_ctx_t *ctx)
{
	assert(ctx);
	memset(ctx->wire, 0, ctx->size);
}

/*!
 * \brief Set position offset from begin
 */
static inline void wire_ctx_set_offset(wire_ctx_t *ctx, size_t offset)
{
	assert(ctx);
	if (ctx->error != KNOT_EOK) {
		return;
	}
	if (offset > ctx->size) {
		ctx->error = KNOT_ERANGE;
		return;
	}
	ctx->position = ctx->wire + offset;
}

/*!
 * \brief Add offset to current position
 *
 * \note Cannot seek before actual data
 */
static inline void wire_ctx_skip(wire_ctx_t *ctx, ssize_t offset)
{
	assert(ctx);
	if (ctx->error != KNOT_EOK) {
		return;
	}
	ctx->position += offset;
	// check for scope
	if (ctx->position < ctx->wire || ctx->position > ctx->wire + ctx->size) {
		ctx->position -= offset; // revert position
		ctx->error = KNOT_ERANGE;
	}
}

/*!
 * \brief Gets actual position
 * \return position from begin
 */
static inline size_t wire_ctx_offset(wire_ctx_t *ctx)
{
	assert(ctx);
	return ctx->position - ctx->wire;
}

/*!
 * \brief Gets available bytes
 * \return Number of bytes to end
 */
static inline size_t wire_ctx_available(wire_ctx_t *ctx)
{
	assert(ctx);

	size_t position = wire_ctx_offset(ctx);

	return ctx->size > position ? (ctx->size - position) : 0;
}

static inline bool wire_ctx_can_read(wire_ctx_t *ctx, size_t size)
{
	assert(ctx);
	return ctx->error == KNOT_EOK &&
	       ctx->position + size <= ctx->wire + ctx->size;
}

static inline uint8_t wire_ctx_read_u8(wire_ctx_t *ctx)
{
	assert(ctx);

	if (ctx->error != KNOT_EOK) {
		return 0;
	}
	if (!wire_ctx_can_read(ctx, sizeof(uint8_t))) {
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

	if (ctx->error != KNOT_EOK) {
		return 0;
	}
	if (!wire_ctx_can_read(ctx, sizeof(uint16_t))) {
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

	if (ctx->error != KNOT_EOK) {
		return 0;
	}
	if (!wire_ctx_can_read(ctx, sizeof(uint32_t))) {
		ctx->error = KNOT_EFEWDATA;
		return 0;
	}

	uint32_t result = *((uint32_t *)ctx->position);
	ctx->position += sizeof(uint32_t);

	return be32toh(result);
}

static inline uint64_t wire_ctx_read_u48(wire_ctx_t *ctx)
{
	assert(ctx);

	if (ctx->error != KNOT_EOK) {
		return 0;
	}
	if (!wire_ctx_can_read(ctx, 6)) {
		ctx->error = KNOT_EFEWDATA;
		return 0;
	}

	uint64_t input = 0;
	memcpy((uint8_t *)&input + 1, ctx->position, 6);
	return be64toh(input) >> 8;
}

static inline uint64_t wire_ctx_read_u64(wire_ctx_t *ctx)
{
	assert(ctx);

	if (ctx->error != KNOT_EOK) {
		return 0;
	}
	if (!wire_ctx_can_read(ctx, sizeof(uint64_t))) {
		ctx->error = KNOT_EFEWDATA;
		return 0;
	}

	uint64_t result = *((uint64_t *)ctx->position);
	ctx->position += sizeof(uint64_t);

	return be64toh(result);
}

static inline void wire_ctx_read(wire_ctx_t *ctx, uint8_t *data, size_t size)
{
	assert(ctx);
	assert(data);

	if (ctx->error != KNOT_EOK) {
		return;
	}
	if (!wire_ctx_can_read(ctx, size)) {
		ctx->error = KNOT_EFEWDATA;
		return;
	}

	memcpy(data, ctx->position, size);
	ctx->position += size;
}

static inline bool wire_ctx_can_write(wire_ctx_t *ctx, size_t size)
{
	assert(ctx);
	return ctx->error == KNOT_EOK && !ctx->readonly &&
	       ctx->position + size <= ctx->wire + ctx->size;
}

static inline void wire_ctx_write_u8(wire_ctx_t *ctx, uint8_t value)
{
	assert(ctx);

	if (ctx->error != KNOT_EOK) {
		return;
	}
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

	if (ctx->error != KNOT_EOK) {
		return;
	}
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

	if (ctx->error != KNOT_EOK) {
		return;
	}
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

	if (ctx->error != KNOT_EOK) {
		return;
	}
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

	if (ctx->error != KNOT_EOK) {
		return;
	}
	if (!wire_ctx_can_write(ctx, sizeof(uint64_t))) {
		ctx->error = KNOT_ESPACE;
		return;
	}

	*((uint64_t *)ctx->position) = htobe64(value);
	ctx->position += sizeof(uint64_t);
}

/*!
 * \brief Write data to wire without endian translation
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
	if (ctx->error != KNOT_EOK) {
		return;
	}
	if (!wire_ctx_can_write(ctx, size)) {
		ctx->error = KNOT_ESPACE;
		return;
	}

	memcpy(ctx->position, data, size);
	ctx->position += size;
}
