/**
 * @file
 * Edit a string
 *
 * @authors
 * Copyright (C) 2022-2023 Richard Russon <rich@flatcap.org>
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
 * @page lib_editor Edit a string
 *
 * Edit a string
 *
 * | File                | Description                |
 * | :------------------ | :------------------------- |
 * | editor/enter.c      | @subpage editor_enter      |
 * | editor/functions.c  | @subpage editor_functions  |
 * | editor/state.c      | @subpage editor_state      |
 * | editor/window.c     | @subpage editor_window     |
 */

#ifndef MUTT_EDITOR_LIB_H
#define MUTT_EDITOR_LIB_H

#include <stddef.h>
#include "mutt.h"
// IWYU pragma: begin_keep
#include "enter.h"
#include "state.h"
#include "wdata.h"
// IWYU pragma: end_keep
#include "history/lib.h"

struct Buffer;
struct CompleteOps;

int mw_get_field(const char *prompt, struct Buffer *buf, CompletionFlags complete, enum HistoryClass hclass, const struct CompleteOps *comp_api, void *cdata);
int mw_get_field_notify(const char *field, struct Buffer *buf, void (*callback)(void *, const char*), void *data);
void replace_part(struct EnterState *es, size_t from, const char *buf);

#endif /* MUTT_EDITOR_LIB_H */
