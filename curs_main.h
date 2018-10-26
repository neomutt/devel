/**
 * @file
 * GUI manage the main index (list of emails)
 *
 * @authors
 * Copyright (C) 2018 Richard Russon <rich@flatcap.org>
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

#ifndef MUTT_CURS_MAIN_H
#define MUTT_CURS_MAIN_H

#include <stdbool.h>
#include <stdio.h>

struct Context;
struct Email;
struct Menu;

/* These Config Variables are only used in curs_main.c */
extern bool  ChangeFolderNext;
extern bool  CollapseAll;
extern bool  CollapseFlagged;
extern bool  CollapseUnread;
extern char *MarkMacroPrefix;
extern bool  PgpAutoDecode;
extern bool  UncollapseJump;
extern bool  UncollapseNew;

int  index_color(int line);
void index_make_entry(char *buf, size_t buflen, struct Menu *menu, int line);
void mutt_draw_statusline(int cols, const char *buf, size_t buflen);
int  mutt_index_menu(void);
void mutt_set_header_color(struct Context *ctx, struct Email *curhdr);
void update_index(struct Menu *menu, struct Context *ctx, int check, int oldcount, int index_hint);

#endif /* MUTT_CURS_MAIN_H */
