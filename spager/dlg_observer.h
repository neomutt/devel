/**
 * @file
 * Simple Pager Dialog notification observers
 *
 * @authors
 * Copyright (C) 2024-2025 Richard Russon <rich@flatcap.org>
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

#ifndef MUTT_SPAGER_DLG_OBSERVER_H
#define MUTT_SPAGER_DLG_OBSERVER_H

struct MuttWindow;

void dlg_spager_add_observers   (struct MuttWindow *dlg);
void dlg_spager_remove_observers(struct MuttWindow *dlg);

#endif /* MUTT_SPAGER_DLG_OBSERVER_H */
