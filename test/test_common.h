/**
 * @file
 * Common code for file tests
 *
 * @authors
 * Copyright (C) 2020 Richard Russon <rich@flatcap.org>
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

#ifndef TEST_TEST_COMMON_H
#define TEST_TEST_COMMON_H

#include <stdio.h>
#include "mutt/lib.h"

void test_gen_path(char *buf, size_t buflen, const char *fmt);
void test_init(void);

#define TEST_CHECK_STR_EQ(expected, actual)                                    \
  do                                                                           \
  {                                                                            \
    if (!TEST_CHECK(mutt_str_strcmp(expected, actual) == 0))                   \
    {                                                                          \
      TEST_MSG("Expected: %s", expected);                                      \
      TEST_MSG("Actual  : %s", actual);                                        \
    }                                                                          \
  } while (false)

#define LONG_IS_64 (LONG_MAX == 9223372036854775807)

#endif /* TEST_TEST_COMMON_H */
