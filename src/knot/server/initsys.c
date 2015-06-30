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

#include "knot/server/initsys.h"

#ifdef ENABLE_SYSTEMD

#include <stdbool.h>
#include <systemd/sd-daemon.h>

void initsys_signal_ready(void)
{
	sd_notify(0, "READY=1");
}

#else

void initsys_signal_ready(void)
{
	// no-op
}

#endif
