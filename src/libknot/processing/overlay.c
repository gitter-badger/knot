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

#include "libknot/errcode.h"
#include "libknot/processing/overlay.h"
#include "libknot/internal/macros.h"

/*! \note Macro for state-chaining layers. */
#define ITERATE_LAYERS(overlay, func, ...) \
	knot_layer_state_t state = overlay->state; \
	knot_layer_t *layer = NULL; \
	WALK_LIST(layer, (overlay)->layers) { \
		layer->state = state; /* Pass-through state. */ \
		state = (func)(layer, ##__VA_ARGS__); \
	} \
	return overlay->state = state;

_public_
void knot_overlay_init(knot_overlay_t *overlay, mm_ctx_t *mm)
{
	overlay->state = KNOT_STATE_NOOP;
	init_list(&overlay->layers);
	overlay->mm = mm;
}

_public_
void knot_overlay_deinit(knot_overlay_t *overlay)
{
	knot_layer_t *layer = NULL, *next = NULL;
	WALK_LIST_DELSAFE(layer, next, overlay->layers) {
		mm_free(overlay->mm, layer);
	}
}

_public_
int knot_overlay_add(knot_overlay_t *overlay, const knot_layer_api_t *module,
                     void *module_param)
{
	knot_layer_t *layer = mm_alloc(overlay->mm, sizeof(knot_layer_t));
	if (layer == NULL) {
		return KNOT_ENOMEM;
	}

	memset(layer, 0, sizeof(knot_layer_t));
	layer->mm = overlay->mm;
	layer->state = overlay->state;

	add_tail(&overlay->layers, (node_t *)layer);
	overlay->state = knot_layer_begin(layer, module, module_param);

	return KNOT_EOK;
}

_public_
knot_layer_state_t knot_overlay_reset(knot_overlay_t *overlay)
{
	ITERATE_LAYERS(overlay, knot_layer_reset);
}

_public_
knot_layer_state_t knot_overlay_finish(knot_overlay_t *overlay)
{
	/* Only in operable state. */
	if (overlay->state == KNOT_STATE_NOOP) {
		return overlay->state;
	}

	ITERATE_LAYERS(overlay, knot_layer_finish);
}

_public_
knot_layer_state_t knot_overlay_consume(knot_overlay_t *overlay, knot_pkt_t *pkt)
{
	/* Only if expecting data. */
	if (overlay->state != KNOT_STATE_CONSUME) {
		return overlay->state;
	}

	ITERATE_LAYERS(overlay, knot_layer_consume, pkt);
}

_public_
knot_layer_state_t knot_overlay_produce(knot_overlay_t *overlay, knot_pkt_t *pkt)
{
	/* Only in operable state. */
	if (overlay->state == KNOT_STATE_NOOP) {
		return overlay->state;
	}

	ITERATE_LAYERS(overlay, knot_layer_produce, pkt);
}
