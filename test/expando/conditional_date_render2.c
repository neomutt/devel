/**
 * @file
 * Test code for Conditional Date Expando Rendering 2
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
#include <time.h>
#include "mutt/lib.h"
#include "expando/lib.h"
#include "common.h" // IWYU pragma: keep
#include "test_common.h"

struct CondDateData
{
  time_t t;
};

static long cond_date_num(const struct ExpandoNode *node, void *data, MuttFormatFlags flags)
{
  const struct CondDateData *dd = data;
  return dd->t;
}

static void cond_date(const struct ExpandoNode *node, void *data,
                      MuttFormatFlags flags, struct Buffer *buf)
{
  ASSERT(node->type == ENT_EXPANDO || node->type == ENT_CONDDATE);

  const struct CondDateData *dd = data;
  struct tm tm = mutt_date_localtime(dd->t);

  char tmp[128] = { 0 };
  strftime(tmp, sizeof(tmp), node->text, &tm);
  buf_strcpy(buf, tmp);
}

void test_expando_conditional_date_render2(void)
{
  const char *input = "%<[1m?%[%d-%m-%Y]&%[%Y-%m-%d]>";

  const struct ExpandoDefinition defs[] = {
    { "[", NULL, 1, 2, parse_date },
    { NULL, NULL, 0, 0, NULL },
  };

  struct Buffer *err = buf_pool_get();

  struct Expando *exp = expando_parse(input, defs, err);
  TEST_CHECK(exp != NULL);
  TEST_CHECK(buf_is_empty(err));

  struct ExpandoNode *node_cond = node_get_child(exp->node, ENC_CONDITION);
  struct ExpandoNode *node_true = node_get_child(exp->node, ENC_TRUE);
  struct ExpandoNode *node_false = node_get_child(exp->node, ENC_FALSE);

  check_node_conddate(node_cond, 1, 'm');
  check_node_expando(node_true, "%d-%m-%Y", NULL);
  check_node_expando(node_false, "%Y-%m-%d", NULL);

  const struct ExpandoRenderCallback TestCallbacks[] = {
    { 1, 2, cond_date, cond_date_num },
    { -1, -1, NULL },
  };

  {
    struct CondDateData data = {
      .t = mutt_date_now(),
    };

    struct tm tm = mutt_date_localtime(data.t);
    char expected[32] = { 0 };
    strftime(expected, sizeof(expected), "%d-%m-%Y", &tm);

    struct ExpandoRenderData TestRenderData[] = {
      // clang-format off
      { 1, TestCallbacks, &data, MUTT_FORMAT_NO_FLAGS },
      { -1, NULL, NULL, 0 },
      // clang-format on
    };

    struct Buffer *buf = buf_pool_get();
    expando_render(exp, TestRenderData, buf->dsize, buf);

    TEST_CHECK_STR_EQ(buf_string(buf), expected);
    buf_pool_release(&buf);
  }

  {
    struct CondDateData data = {
      .t = mutt_date_now() - (60 * 60 * 24 * 365),
    };

    struct tm tm = mutt_date_localtime(data.t);
    char expected[32] = { 0 };
    strftime(expected, sizeof(expected), "%Y-%m-%d", &tm);

    struct ExpandoRenderData TestRenderData[] = {
      // clang-format off
      { 1, TestCallbacks, &data, MUTT_FORMAT_NO_FLAGS },
      { -1, NULL, NULL, 0 },
      // clang-format on
    };

    struct Buffer *buf = buf_pool_get();
    expando_render(exp, TestRenderData, buf->dsize, buf);

    TEST_CHECK_STR_EQ(buf_string(buf), expected);
    buf_pool_release(&buf);
  }

  expando_free(&exp);
  buf_pool_release(&err);
}
