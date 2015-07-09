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
 * \file overlay.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \addtogroup query_processing
 * @{
 */

#pragma once

#include "libknot/processing/layer.h"

/*! \brief Processsing overlay (list of aggregated FSMs). */
typedef struct knot_overlay {
	knot_layer_state_t state;
	list_t layers;
	mm_ctx_t *mm;
} knot_overlay_t;

/*!
 * \brief Initialize overlay and memory context.
 *
 * \param overlay Overlay context.
 * \param mm Memory context.
 */
void knot_overlay_init(knot_overlay_t *overlay, mm_ctx_t *mm);

/*!
 * \brief Clear structure nad free list of layers.
 *
 * \param overlay Overlay context.
 */
void knot_overlay_deinit(knot_overlay_t *overlay);

/*!
 * \brief Add an overlay on top of the list and begin execution.
 *
 * \param overlay Overlay context.
 * \param module Layer module.
 * \param module_param Module parameters.
 *
 * \return KNOT_EOK or an error.
 */
int knot_overlay_add(knot_overlay_t *overlay, const knot_layer_api_t *module,
                     void *module_param);

/*!
 * \brief Reset layer processing.
 *
 * \param overlay Overlay context.
 *
 * \return Overlay state.
 */
knot_layer_state_t knot_overlay_reset(knot_overlay_t *overlay);

/*!
 * \brief Finish layer processing.
 *
 * \param overlay Overlay context.
 *
 * \return Overlay state.
 */
knot_layer_state_t knot_overlay_finish(knot_overlay_t *overlay);

/*!
 * \brief Add more data to layer processing.
 *
 * \param overlay Overlay context.
 * \param pkg Packet context.
 *
 * \return Overlay state.
 */
knot_layer_state_t knot_overlay_consume(knot_overlay_t *overlay, knot_pkt_t *pkt);

/*!
 * \brief Generate output from layers.
 *
 * \param overlay Overlay context.
 * \param pkg Packet context.
 *
 * \return Overlay state.
 */
knot_layer_state_t knot_overlay_produce(knot_overlay_t *overlay, knot_pkt_t *pkt);

/*! @} */
