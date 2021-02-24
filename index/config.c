/**
 * @file
 * Config used by libindex
 *
 * @authors
 * Copyright (C) 2021 Richard Russon <rich@flatcap.org>
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
 * @page index_config Config used by libindex
 *
 * Config used by libindex
 */

#include "config.h"
#include <stddef.h>
#include <config/lib.h>
#include <stdbool.h>
#include <stdint.h>
#include "mutt/lib.h"
#include "conn/lib.h"
#include "lib.h"
#include "init.h"

struct ConfigDef IndexVars[] = {
  // clang-format off
  { "change_folder_next", DT_BOOL, &C_ChangeFolderNext, false, 0, NULL,
    "Suggest the next folder, rather than the first when using '<change-folder>'"
  },
  { "collapse_all", DT_BOOL, &C_CollapseAll, false, 0, NULL,
    "Collapse all threads when entering a folder"
  },
  { "mark_macro_prefix", DT_STRING, &C_MarkMacroPrefix, IP "'", 0, NULL,
    "Prefix for macros using '<mark-message>'"
  },
  { "uncollapse_jump", DT_BOOL, &C_UncollapseJump, false, 0, NULL,
    "When opening a thread, jump to the next unread message"
  },
  { "uncollapse_new", DT_BOOL, &C_UncollapseNew, true, 0, NULL,
    "Open collapsed threads when new mail arrives"
  },

  { NULL, 0, NULL, 0, 0, NULL, NULL },
  // clang-format on
};

/**
 * config_init_index - Register index config variables - Implements ::module_init_config_t
 */
bool config_init_index(struct ConfigSet *cs)
{
  return cs_register_variables(cs, IndexVars, 0);
}
