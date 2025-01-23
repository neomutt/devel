/**
 * @file
 * Shared Testing Code
 *
 * @authors
 * Copyright (C) 2018-2023 Richard Russon <rich@flatcap.org>
 * Copyright (C) 2023 Dennis Schön <mail@dennis-schoen.de>
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

#ifndef TEST_CONFIG_COMMON_H
#define TEST_CONFIG_COMMON_H

#include <stdbool.h>
#include <stdint.h>

struct Buffer;
struct ConfigDef;
struct ConfigSet;
struct NotifyCallback;

extern const char *divider_line;
extern bool dont_fail;

extern const struct ConfigSetType CstAddress;
extern const struct ConfigSetType CstBool;
extern const struct ConfigSetType CstEnum;
extern const struct ConfigSetType CstLong;
extern const struct ConfigSetType CstMbtable;
extern const struct ConfigSetType CstMyVar;
extern const struct ConfigSetType CstNumber;
extern const struct ConfigSetType CstPath;
extern const struct ConfigSetType CstQuad;
extern const struct ConfigSetType CstRegex;
extern const struct ConfigSetType CstSlist;
extern const struct ConfigSetType CstSort;
extern const struct ConfigSetType CstString;

int validator_succeed(const struct ConfigDef *cdef, intptr_t value, struct Buffer *result);
int validator_warn   (const struct ConfigDef *cdef, intptr_t value, struct Buffer *result);
int validator_fail   (const struct ConfigDef *cdef, intptr_t value, struct Buffer *result);

void log_line(const char *fn);
void short_line(void);
int log_observer(struct NotifyCallback *nc);
void set_list(const struct ConfigSet *cs);
void cs_dump_set(const struct ConfigSet *cs);

int      cs_str_delete             (const struct ConfigSet *cs, const char *name, struct Buffer *err);
intptr_t cs_str_native_get         (const struct ConfigSet *cs, const char *name, struct Buffer *err);
int      cs_str_string_get         (const struct ConfigSet *cs, const char *name, struct Buffer *result);
int      cs_str_string_minus_equals(const struct ConfigSet *cs, const char *name, const char *value, struct Buffer *err);
int      cs_str_string_plus_equals (const struct ConfigSet *cs, const char *name, const char *value, struct Buffer *err);

#endif /* TEST_CONFIG_COMMON_H */
