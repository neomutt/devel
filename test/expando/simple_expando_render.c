/**
 * @file
 * Test code for Simple Expando Render
 *
 * @authors
 * Copyright (C) 2023-2024 Tóth János <gomba007@gmail.com>
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

#define TEST_NO_MAIN
#include "config.h"
#include "acutest.h"
#include <stdio.h>
#include "mutt/lib.h"
#include "expando/lib.h"
#include "common.h" // IWYU pragma: keep
#include "test_common.h"

struct SimpleExpandoData
{
  const char *s;
  int d;
};

static void simple_s(const struct ExpandoNode *node, void *data,
                     MuttFormatFlags flags, struct Buffer *buf)
{
  ASSERT(node->type == ENT_EXPANDO);

  const struct SimpleExpandoData *sd = data;

  const char *s = NONULL(sd->s);
  buf_strcpy(buf, s);
}

static void simple_d(const struct ExpandoNode *node, void *data,
                     MuttFormatFlags flags, struct Buffer *buf)
{
  ASSERT(node->type == ENT_EXPANDO);

  const struct SimpleExpandoData *sd = data;

  const int num = sd->d;
  buf_printf(buf, "%d", num);
}

void test_expando_simple_expando_render(void)
{
  const char *input = "%s - %d"; // Second space is: U+2002 EN SPACE

  const struct ExpandoDefinition defs[] = {
    { "s", NULL, 1, 0, NULL },
    { "d", NULL, 1, 1, NULL },
    { NULL, NULL, 0, 0, NULL },
  };

  struct Buffer *err = buf_pool_get();
  struct Expando *exp = expando_parse(input, defs, err);
  TEST_CHECK(exp != NULL);
  TEST_CHECK(buf_is_empty(err));

  check_node_expando(node_get_child(exp->node, 0), NULL, NULL);
  check_node_text(node_get_child(exp->node, 1), " - ");
  check_node_expando(node_get_child(exp->node, 2), NULL, NULL);

  const char *expected = "Test - 1";

  const struct ExpandoRenderCallback TestCallbacks[] = {
    { 1, 0, simple_s },
    { 1, 1, simple_d },
    { -1, -1, NULL },
  };

  struct SimpleExpandoData data = {
    .s = "Test",
    .d = 1,
  };

  struct ExpandoRenderData TestRenderData[] = {
    // clang-format off
    { 1, TestCallbacks, &data, MUTT_FORMAT_NO_FLAGS },
    { -1, NULL, NULL, 0 },
    // clang-format on
  };

  struct Buffer *buf = buf_pool_get();
  expando_render(exp, TestRenderData, buf->dsize, buf);

  TEST_CHECK_STR_EQ(buf_string(buf), expected);

  expando_free(&exp);
  buf_pool_release(&err);
  buf_pool_release(&buf);
}
