/**
 * @file
 * Read/write command history from/to a file
 *
 * @authors
 * Copyright (C) 1996-2000 Michael R. Elkins <me@mutt.org>
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

#ifndef _MUTT_HISTORY2_H
#define _MUTT_HISTORY2_H

#include <stdio.h>
#include "mutt/mutt.h"

void mutt_hist_complete(char *buf, size_t buflen, enum HistoryClass hclass);
bool mutt_hist_listener(const struct ConfigSet *cs, struct HashElem *he, const char *name, enum ConfigEvent ev);

#endif /* _MUTT_HISTORY2_H */

