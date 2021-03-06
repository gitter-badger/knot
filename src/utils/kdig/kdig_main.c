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

#include <stdlib.h>

#include "dnssec/crypto.h"
#include "utils/kdig/kdig_params.h"
#include "utils/kdig/kdig_exec.h"
#include "libknot/libknot.h"

int main(int argc, char *argv[])
{
	int ret = EXIT_SUCCESS;

	kdig_params_t params;
	if (kdig_parse(&params, argc, argv) == KNOT_EOK) {
		if (!params.stop) {
			dnssec_crypto_init();
			if (kdig_exec(&params) != KNOT_EOK) {
				ret = EXIT_FAILURE;
			}
			dnssec_crypto_cleanup();
		}
	} else {
		ret = EXIT_FAILURE;
	}

	kdig_clean(&params);
	return ret;
}
