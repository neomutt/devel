/**
 * @file
 * Colour Dump Command
 *
 * @authors
 * Copyright (C) 2023 Richard Russon <rich@flatcap.org>
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

#ifndef MUTT_COLOR_DUMP_H
#define MUTT_COLOR_DUMP_H

struct AttrColor;
struct Buffer;
struct ColorElement;
struct PagedFile;

void color_dump(struct PagedFile *pf);

const char *color_log_attrs_list (int attrs);
void        color_log_color_attrs(struct AttrColor *ac, struct Buffer *swatch);
const char *color_log_name       (char *buf, int buflen, struct ColorElement *elem);

#endif /* MUTT_COLOR_DUMP_H */

