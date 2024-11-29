/**
 * @file
 * Test code for Render if-else-false Expando
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

struct SimpleIfElseData
{
  int c;
  int t;
  int f;
};

static void simple_c(const struct ExpandoNode *node, void *data,
                     MuttFormatFlags flags, struct Buffer *buf)
{
  const struct SimpleIfElseData *sd = data;
  if (sd->c == 0)
    return;

  const int num = sd->c;
  buf_printf(buf, "%d", num);
}

static void simple_t(const struct ExpandoNode *node, void *data,
                     MuttFormatFlags flags, struct Buffer *buf)
{
  ASSERT(node->type == ENT_EXPANDO);

  const struct SimpleIfElseData *sd = data;

  const int num = sd->t;
  buf_printf(buf, "%d", num);
}

static void simple_f(const struct ExpandoNode *node, void *data,
                     MuttFormatFlags flags, struct Buffer *buf)
{
  ASSERT(node->type == ENT_EXPANDO);

  const struct SimpleIfElseData *sd = data;

  const int num = sd->f;
  buf_printf(buf, "%d", num);
}

void test_expando_if_else_false_render(void)
{
  const struct ExpandoDefinition defs[] = {
    { "c", NULL, 1, 0, NULL },
    { "t", NULL, 1, 1, NULL },
    { "f", NULL, 1, 2, NULL },
    { NULL, NULL, 0, 0, NULL },
  };

  const char *input = "%<c?%t>%<c?%t&%f>";
  struct Buffer *err = buf_pool_get();

  struct Expando *exp = expando_parse(input, defs, err);

  TEST_CHECK(exp != NULL);
  TEST_CHECK(buf_is_empty(err));
  {
    struct ExpandoNode *node = node_get_child(exp->node, 0);
    check_node_cond(node);

    struct ExpandoNode *node_cond = node_get_child(node, ENC_CONDITION);
    struct ExpandoNode *node_true = node_get_child(node, ENC_TRUE);
    struct ExpandoNode *node_false = node_get_child(node, ENC_FALSE);

    check_node_condbool(node_cond);
    check_node_expando(node_true, NULL, NULL);
    TEST_CHECK(node_false == NULL);
  }

  {
    struct ExpandoNode *node = node_get_child(exp->node, 1);
    check_node_cond(node);

    struct ExpandoNode *node_cond = node_get_child(node, ENC_CONDITION);
    struct ExpandoNode *node_true = node_get_child(node, ENC_TRUE);
    struct ExpandoNode *node_false = node_get_child(node, ENC_FALSE);

    check_node_condbool(node_cond);
    check_node_expando(node_true, NULL, NULL);
    check_node_expando(node_false, NULL, NULL);
  }

  const char *expected = "3";

  const struct ExpandoRenderCallback TestCallbacks[] = {
    { 1, 0, simple_c },
    { 1, 1, simple_t },
    { 1, 2, simple_f },
    { -1, -1, NULL },
  };

  struct Buffer *buf = buf_pool_get();

  {
    struct SimpleIfElseData data = {
      .c = 0,
      .t = 2,
      .f = 3,
    };

    struct ExpandoRenderData TestRenderData[] = {
      // clang-format off
      { 1, TestCallbacks, &data, MUTT_FORMAT_NO_FLAGS },
      { -1, NULL, NULL, 0 },
      // clang-format on
    };

    expando_render(exp, TestRenderData, buf->dsize, buf);

    TEST_CHECK_STR_EQ(buf_string(buf), expected);
  }

  expando_free(&exp);
  buf_pool_release(&err);
  buf_pool_release(&buf);
}
