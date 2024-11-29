/**
 * @file
 * Render Expandos using Data
 *
 * @authors
 * Copyright (C) 2023-2024 Tóth János <gomba007@gmail.com>
 * Copyright (C) 2023-2024 Richard Russon <rich@flatcap.org>
 *
 * @copyright
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 2 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef MUTT_EXPANDO_RENDER_H
#define MUTT_EXPANDO_RENDER_H

#include <stdint.h>

struct Buffer;
struct ExpandoNode;

typedef uint8_t MuttFormatFlags;         ///< Flags for expando_render(), e.g. #MUTT_FORMAT_FORCESUBJ
#define MUTT_FORMAT_NO_FLAGS          0  ///< No flags are set
#define MUTT_FORMAT_FORCESUBJ   (1 << 0) ///< Print the subject even if unchanged
#define MUTT_FORMAT_TREE        (1 << 1) ///< Draw the thread tree
#define MUTT_FORMAT_STAT_FILE   (1 << 2) ///< Used by attach_format_str
#define MUTT_FORMAT_ARROWCURSOR (1 << 3) ///< Reserve space for arrow_cursor
#define MUTT_FORMAT_INDEX       (1 << 4) ///< This is a main index entry
#define MUTT_FORMAT_PLAIN       (1 << 5) ///< Do not prepend DISP_TO, DISP_CC ...

/**
 * @defgroup expando_get_string_api Expando Get String API
 * @ingroup expando_get_data_api
 *
 * get_string_t - Get some string data
 * @param[in]  node      ExpandoNode containing the callback
 * @param[in]  data      Private data
 * @param[in]  flags     Flags, see #MuttFormatFlags
 * @param[out] buf       Buffer in which to save string
 *
 * Get some string data to be formatted.
 */
typedef void (*get_string_t)(const struct ExpandoNode *node, void *data, MuttFormatFlags flags, struct Buffer *buf);

/**
 * @defgroup expando_get_number_api Expando Get Number API
 * @ingroup expando_get_data_api
 *
 * get_number_t - Get some numeric data
 * @param[in]  node      ExpandoNode containing the callback
 * @param[in]  data      Private data
 * @param[in]  flags     Flags, see #MuttFormatFlags
 * @retval num Data as a number
 *
 * Get some numeric data to be formatted.
 */
typedef long (*get_number_t)(const struct ExpandoNode *node, void *data, MuttFormatFlags flags);

/**
 * @defgroup expando_get_data_api Expando Get Data API
 *
 * Define callback functions to get data to be formatted.
 * Each function is associated with a Domain+UID pair.
 */
struct ExpandoRenderCallback
{
  int did;                  ///< Domain ID, #ExpandoDomain
  int uid;                  ///< Unique ID, e.g. #ExpandoDataAlias

  get_string_t get_string;  // Callback function to get a string
  get_number_t get_number;  // Callback function to get a number
};

/**
 * struct ExpandoRenderData - Render Data + Callback Functions
 */
struct ExpandoRenderData
{
  int                                 did;     ///< Domain ID, #ExpandoDomain
  const struct ExpandoRenderCallback *rcall;   ///< Render callback functions
  void                               *obj;     ///< Object to pass to callback function
  int                                 flags;   ///< Flags  to pass to callback function
};

int node_render(const struct ExpandoNode *node, const struct ExpandoRenderData *rdata,
                int max_cols, struct Buffer *buf);

#endif /* MUTT_EXPANDO_RENDER_H */
