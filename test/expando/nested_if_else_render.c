/**
 * @file
 * Test code for Nested if-else Rendering
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

struct NestedIfElseData
{
  int x;
  int y;
};

static void nested_x(const struct ExpandoNode *node, void *data,
                     MuttFormatFlags flags, struct Buffer *buf)
{
  const struct NestedIfElseData *sd = data;

  const int num = sd->x;
  if (num == 0)
    return;

  buf_printf(buf, "%d", num);
}

static void nested_y(const struct ExpandoNode *node, void *data,
                     MuttFormatFlags flags, struct Buffer *buf)
{
  const struct NestedIfElseData *sd = data;

  const int num = sd->y;
  if (num == 0)
    return;

  buf_printf(buf, "%d", num);
}

void test_expando_nested_if_else_render(void)
{
  const char *input = "%<x?%<y?XY&X>&%<y?Y&NONE>>";

  const struct ExpandoDefinition defs[] = {
    { "x", NULL, 1, 0, NULL },
    { "y", NULL, 1, 1, NULL },
    { NULL, NULL, 0, 0, NULL },
  };

  struct Buffer *err = buf_pool_get();
  struct Expando *exp = expando_parse(input, defs, err);
  TEST_CHECK(exp != NULL);
  TEST_CHECK(buf_is_empty(err));

  struct ExpandoNode *node_cond = node_get_child(exp->node, ENC_CONDITION);
  struct ExpandoNode *node_true = node_get_child(exp->node, ENC_TRUE);
  struct ExpandoNode *node_false = node_get_child(exp->node, ENC_FALSE);

  check_node_condbool(node_cond);

  struct ExpandoNode *t = node_true;
  check_node_cond(t);

  struct ExpandoNode *f = node_false;
  check_node_cond(f);

  node_cond = node_get_child(t, ENC_CONDITION);
  node_true = node_get_child(t, ENC_TRUE);
  node_false = node_get_child(t, ENC_FALSE);

  check_node_condbool(node_cond);
  check_node_text(node_true, "XY");
  check_node_text(node_false, "X");

  node_cond = node_get_child(f, ENC_CONDITION);
  node_true = node_get_child(f, ENC_TRUE);
  node_false = node_get_child(f, ENC_FALSE);

  check_node_condbool(node_cond);
  check_node_text(node_true, "Y");
  check_node_text(node_false, "NONE");

  const struct ExpandoRenderCallback TestCallbacks[] = {
    { 1, 0, nested_x },
    { 1, 1, nested_y },
    { -1, -1, NULL },
  };

  const char *expected_X = "X";
  struct NestedIfElseData data_X = {
    .x = 1,
    .y = 0,
  };

  struct ExpandoRenderData TestRenderDataX[] = {
    // clang-format off
    { 1, TestCallbacks, &data_X, MUTT_FORMAT_NO_FLAGS },
    { -1, NULL, NULL, 0 },
    // clang-format on
  };

  struct Buffer *buf = buf_pool_get();
  expando_render(exp, TestRenderDataX, buf->dsize, buf);

  TEST_CHECK_STR_EQ(buf_string(buf), expected_X);

  const char *expected_Y = "Y";
  struct NestedIfElseData data_Y = {
    .x = 0,
    .y = 1,
  };

  struct ExpandoRenderData TestRenderDataY[] = {
    // clang-format off
    { 1, TestCallbacks, &data_Y, MUTT_FORMAT_NO_FLAGS },
    { -1, NULL, NULL, 0 },
    // clang-format on
  };

  buf_reset(buf);
  expando_render(exp, TestRenderDataY, buf->dsize, buf);

  TEST_CHECK_STR_EQ(buf_string(buf), expected_Y);

  const char *expected_XY = "XY";
  struct NestedIfElseData data_XY = {
    .x = 1,
    .y = 1,
  };

  struct ExpandoRenderData TestRenderDataXY[] = {
    // clang-format off
    { 1, TestCallbacks, &data_XY, MUTT_FORMAT_NO_FLAGS },
    { -1, NULL, NULL, 0 },
    // clang-format on
  };

  buf_reset(buf);
  expando_render(exp, TestRenderDataXY, buf->dsize, buf);

  TEST_CHECK_STR_EQ(buf_string(buf), expected_XY);

  const char *expected_NONE = "NONE";
  struct NestedIfElseData data_NONE = {
    .x = 0,
    .y = 0,
  };

  struct ExpandoRenderData TestRenderData[] = {
    // clang-format off
    { 1, TestCallbacks, &data_NONE, MUTT_FORMAT_NO_FLAGS },
    { -1, NULL, NULL, 0 },
    // clang-format on
  };

  buf_reset(buf);
  expando_render(exp, TestRenderData, buf->dsize, buf);

  TEST_CHECK_STR_EQ(buf_string(buf), expected_NONE);

  expando_free(&exp);
  buf_pool_release(&err);
  buf_pool_release(&buf);
}
