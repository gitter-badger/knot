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

#include <stdlib.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <netinet/in.h>
#include <stdio.h>

#include "libknot/internal/wire_ctx.h"


void write_to_limit(void **state)
{
	uint32_t buf=0;
	wire_ctx_t wire = wire_ctx_init((uint8_t*)&buf, sizeof(buf));

	uint32_t data = 42;
	wire_ctx_write_u32(&wire, data);

	assert_int_equal(data, ntohl(buf));

	wire_ctx_set_offset(&wire, 0);
	assert_ptr_equal(wire.position, &buf);

	assert_int_equal(wire.error, KNOT_EOK);

	assert_int_equal(wire_ctx_read_u32(&wire), data);

	assert_int_equal(wire.error, KNOT_EOK);

}

void read_to_limit(void **state)
{
	uint32_t buf = ntohl(0x002a0056);
	wire_ctx_t wire = wire_ctx_init((uint8_t*)&buf, sizeof(buf));

	uint32_t data = 0;
	data = wire_ctx_read_u32(&wire);

	assert_int_equal(wire.error, KNOT_EOK);

	assert_int_equal(0x002a0056, data);

	wire_ctx_set_offset(&wire, 0);

	assert_int_equal(0x002a, wire_ctx_read_u16(&wire));
	assert_int_equal(0x0056, wire_ctx_read_u16(&wire));

	assert_int_equal(wire.error, KNOT_EOK);

	wire_ctx_skip(&wire, -4);

	assert_int_equal(0x00, wire_ctx_read_u8(&wire));
	assert_int_equal(0x2a, wire_ctx_read_u8(&wire));
	assert_int_equal(0x00, wire_ctx_read_u8(&wire));
	assert_int_equal(0x56, wire_ctx_read_u8(&wire));

	assert_int_equal(wire.error, KNOT_EOK);
}

void write_readonly(void **state)
{
	const uint32_t buf = 42;
	wire_ctx_t wire = wire_ctx_init_const((uint8_t*)&buf, sizeof(buf));

	wire_ctx_write_u8(&wire, 1);
	assert_int_not_equal(wire.error, KNOT_EOK);
	assert_int_equal(buf, 42);
}

void can_write(void **state)
{
	uint32_t buf;
	wire_ctx_t wire = wire_ctx_init((uint8_t*)&buf, sizeof(buf));

	assert_true(wire_ctx_can_write(&wire, 1));
	assert_true(wire_ctx_can_write(&wire, 0));
	assert_true(wire_ctx_can_write(&wire, sizeof(buf)));
	assert_false(wire_ctx_can_write(&wire, sizeof(buf) + 1));
}

void write_over_limit(void **state)
{
	uint32_t buf = 0;
	wire_ctx_t wire = wire_ctx_init((uint8_t*)&buf, sizeof(buf));

	// pos 0, write ok
	wire_ctx_write_u8(&wire, 42);
	assert_int_equal(wire.error, KNOT_EOK);
	// pos 1, write fail
	wire_ctx_write_u32(&wire, 42);
	assert_int_not_equal(wire.error, KNOT_EOK);
	wire.error = KNOT_EOK;
	// pos 1, write ok
	wire_ctx_write_u16(&wire, 42);
	assert_int_equal(wire.error, KNOT_EOK);
	// pos 3, write fail
	wire_ctx_write_u32(&wire, 42);
	assert_int_not_equal(wire.error, KNOT_EOK);
	wire.error = KNOT_EOK;
	// pos 3, write fail
	wire_ctx_write_u16(&wire, 42);
	assert_int_not_equal(wire.error, KNOT_EOK);
	wire.error = KNOT_EOK;
	// pos 3, write ok
	wire_ctx_write_u8(&wire, 42);
	assert_int_equal(wire.error, KNOT_EOK);
	// pos 4, write FAIL
	wire_ctx_write_u8(&wire, 42);
	assert_int_not_equal(wire.error, KNOT_EOK);
}

void seek_before(void **state)
{
	uint32_t buf;
	wire_ctx_t wire = wire_ctx_init((uint8_t*)&buf, sizeof(buf));

	wire_ctx_skip(&wire, 1);
	size_t position = wire_ctx_offset(&wire); // save current position (1)
	wire_ctx_skip(&wire, -2);
	assert_int_equal(position, wire_ctx_offset(&wire)); // no changes
	assert_int_not_equal(KNOT_EOK, wire.error);
}

void seek_over(void **state)
{
	uint32_t buf;
	wire_ctx_t wire = wire_ctx_init((uint8_t*)&buf, sizeof(buf));

	wire_ctx_skip(&wire, 1);
	size_t position = wire_ctx_offset(&wire); // save current position (1)
	wire_ctx_skip(&wire, sizeof(buf));
	assert_int_equal(position, wire_ctx_offset(&wire)); // no changes
	assert_int_not_equal(KNOT_EOK, wire.error);
}

void available(void **state)
{
	uint64_t buf;
	wire_ctx_t wire = wire_ctx_init((uint8_t*)&buf, sizeof(buf));

	assert_int_equal(wire_ctx_available(&wire), sizeof(buf));

	wire_ctx_skip(&wire, sizeof(buf));

	assert_int_equal(wire_ctx_available(&wire), 0);
	assert_int_equal(KNOT_EOK, wire.error);
}

int main(void)
{
	cmocka_set_message_output(CM_OUTPUT_TAP);

	const struct CMUnitTest tests[] = {
		cmocka_unit_test(write_to_limit),
		cmocka_unit_test(read_to_limit),
		cmocka_unit_test(write_readonly),
		cmocka_unit_test(can_write),
		cmocka_unit_test(write_over_limit),
		cmocka_unit_test(seek_before),
		cmocka_unit_test(seek_over),
		cmocka_unit_test(available),
	};

	cmocka_run_group_tests(tests, NULL, NULL);

	return 0;
}
