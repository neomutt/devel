/**
 * @file
 * Alias Expando definitions
 *
 * @authors
 * Copyright (C) 2024 Richard Russon <rich@flatcap.org>
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

/**
 * @page compose_expando Alias Expando definitions
 *
 * Alias Expando definitions
 */

#include <stdbool.h>
#include <stdio.h>
#include "private.h"
#include "mutt/lib.h"
#include "expando.h"
#include "expando/lib.h"
#include "menu/lib.h"
#include "attach_data.h"
#include "globals.h"
#include "muttlib.h"
#include "shared_data.h"

/**
 * compose_attach_count_num - Compose: Number of attachments - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long compose_attach_count_num(const struct ExpandoNode *node, void *data,
                                     MuttFormatFlags flags)
{
  const struct ComposeSharedData *shared = data;
  struct ComposeAttachData *adata = shared->adata;

  if (!adata || !adata->menu)
    return 0;

  return adata->menu->max;
}

/**
 * compose_attach_size - Compose: Size in bytes - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void compose_attach_size(const struct ExpandoNode *node, void *data,
                                MuttFormatFlags flags, struct Buffer *buf)
{
  const struct ComposeSharedData *shared = data;

  mutt_str_pretty_size(buf, cum_attachs_size(shared->sub, shared->adata));
}

/**
 * compose_attach_size_num - Compose: Size in bytes - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long compose_attach_size_num(const struct ExpandoNode *node, void *data,
                                    MuttFormatFlags flags)
{
  const struct ComposeSharedData *shared = data;
  return cum_attachs_size(shared->sub, shared->adata);
}

/**
 * global_hostname - Compose: Hostname - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void global_hostname(const struct ExpandoNode *node, void *data,
                            MuttFormatFlags flags, struct Buffer *buf)
{
  const char *s = ShortHostname;
  buf_strcpy(buf, s);
}

/**
 * global_version - Compose: Version - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void global_version(const struct ExpandoNode *node, void *data,
                           MuttFormatFlags flags, struct Buffer *buf)
{
  const char *s = mutt_make_version();
  buf_strcpy(buf, s);
}

/**
 * ComposeRenderCallbacks1 - Callbacks for Compose Expandos
 *
 * @sa ComposeFormatDef, ExpandoDataCompose, ExpandoDataGlobal
 */
const struct ExpandoRenderCallback ComposeRenderCallbacks1[] = {
  // clang-format off
  { ED_COMPOSE, ED_COM_ATTACH_COUNT, NULL,                compose_attach_count_num },
  { ED_COMPOSE, ED_COM_ATTACH_SIZE,  compose_attach_size, compose_attach_size_num },
  { -1, -1, NULL, NULL },
  // clang-format on
};

/**
 * ComposeRenderCallbacks2 - Callbacks for Compose Expandos
 *
 * @sa ComposeFormatDef, ExpandoDataCompose, ExpandoDataGlobal
 */
const struct ExpandoRenderCallback ComposeRenderCallbacks2[] = {
  // clang-format off
  { ED_GLOBAL,  ED_GLO_HOSTNAME,     global_hostname,     NULL },
  { ED_GLOBAL,  ED_GLO_VERSION,      global_version,      NULL },
  { -1, -1, NULL, NULL },
  // clang-format on
};
