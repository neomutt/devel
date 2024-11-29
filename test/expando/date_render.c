/**
 * @file
 * Test code for Expando Date Rendering
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

struct SimpleDateData
{
  time_t t;
};

static void simple_date(const struct ExpandoNode *node, void *data,
                        MuttFormatFlags flags, struct Buffer *buf)
{
  ASSERT(node->type == ENT_EXPANDO);

  const struct SimpleDateData *dd = data;
  struct tm tm = mutt_date_localtime(dd->t);

  char tmp[128] = { 0 };
  strftime(tmp, sizeof(tmp), node->text, &tm);
  buf_strcpy(buf, tmp);
}

void test_expando_date_render(void)
{
  struct SimpleDateData data = {
    .t = 1457341200,
  };

  {
    const char *input = "%[%Y-%m-%d] date";

    const struct ExpandoDefinition defs[] = {
      { "[", NULL, 1, 0, parse_date },
      { NULL, NULL, 0, 0, NULL },
    };

    struct Buffer *err = buf_pool_get();

    struct Expando *exp = expando_parse(input, defs, err);
    TEST_CHECK(exp != NULL);
    TEST_CHECK(buf_is_empty(err));

    check_node_expando(node_get_child(exp->node, 0), "%Y-%m-%d", NULL);
    check_node_text(node_get_child(exp->node, 1), " date");

    const char *expected = "2016-03-07 date";

    const struct ExpandoRenderCallback TestCallbacks[] = {
      { 1, 0, simple_date },
      { -1, -1, NULL },
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
    buf_pool_release(&buf);
    buf_pool_release(&err);
  }

  {
    const char *input = "%-12[%Y-%m-%d]";

    const struct ExpandoDefinition defs[] = {
      { "[", NULL, 1, 0, parse_date },
      { NULL, NULL, 0, 0, NULL },
    };

    struct Buffer *err = buf_pool_get();
    struct Expando *exp = expando_parse(input, defs, err);

    TEST_CHECK(exp != NULL);
    TEST_CHECK(buf_is_empty(err));

    struct ExpandoFormat fmt = { 0 };
    fmt.min_cols = 12;
    fmt.max_cols = -1;
    fmt.justification = JUSTIFY_LEFT;
    fmt.leader = ' ';

    check_node_expando(exp->node, "%Y-%m-%d", &fmt);

    const char *expected = "2016-03-07  ";

    const struct ExpandoRenderCallback TestCallbacks[] = {
      { 1, 0, simple_date },
      { -1, -1, NULL },
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
}
