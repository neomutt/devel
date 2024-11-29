/**
 * @file
 * Test CondDate Expando
 *
 * @authors
 * Copyright (C) 2024 Richard Russon <rich@flatcap.org>
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
#include <stddef.h>
#include <time.h>
#include "mutt/lib.h"
#include "expando/lib.h"
#include "common.h" // IWYU pragma: keep
#include "test_common.h"

struct NodeCondDatePrivate *node_conddate_private_new(int count, char period);
void node_conddate_private_free(void **ptr);
struct ExpandoNode *node_conddate_new(int count, char period, int did, int uid);
int node_conddate_render(const struct ExpandoNode *node,
                         const struct ExpandoRenderData *rdata, int max_cols,
                         struct Buffer *buf);

struct TestDates
{
  const char *str;
  time_t time;
};

static long test_d_num(const struct ExpandoNode *node, void *data, MuttFormatFlags flags)
{
  int test_date = *(int *) data;
  return test_date;
}

void test_expando_node_conddate(void)
{
  // struct NodeCondDatePrivate *node_conddate_private_new(int count, char period);
  // void node_conddate_private_free(void **ptr);
  {
    struct NodeCondDatePrivate *priv = node_conddate_private_new(4, 'y');
    TEST_CHECK(priv != NULL);
    node_conddate_private_free((void **) &priv);
    node_conddate_private_free(NULL);
  }

  // struct ExpandoNode *node_conddate_new(int count, char period, int did, int uid);
  {
    struct ExpandoNode *node = node_conddate_new(4, 'y', 1, 2);
    TEST_CHECK(node != NULL);
    node_free(&node);
  }

  // struct ExpandoNode *node_conddate_parse(const char *str, int did, int uid, const char **parsed_until, struct ExpandoParseError *err);
  // Degenerate
  {
    const char *parsed_until = NULL;
    struct ExpandoNode *node = NULL;
    struct ExpandoParseError err = { 0 };

    node = node_conddate_parse(NULL, 0, 0, &parsed_until, &err);
    TEST_CHECK(node == NULL);

    node = node_conddate_parse("", 0, 0, &parsed_until, &err);
    TEST_CHECK(node == NULL);

    node = node_conddate_parse("abc", 0, 0, NULL, &err);
    TEST_CHECK(node == NULL);

    node = node_conddate_parse("abc", 0, 0, &parsed_until, NULL);
    TEST_CHECK(node == NULL);
  }

  {
    const char *parsed_until = NULL;
    struct ExpandoParseError err = { 0 };

    const char *str = "%<[3d?aaa&bbb>";
    struct ExpandoNode *node = node_conddate_parse(str + 2, 1, 2, &parsed_until, &err);
    TEST_CHECK(node != NULL);
    TEST_MSG(err.message);
    node_free(&node);

    str = "%<[2H?aaa&bbb>";
    node = node_conddate_parse(str + 2, 1, 2, &parsed_until, &err);
    TEST_CHECK(node != NULL);
    TEST_MSG(err.message);
    node_free(&node);

    str = "%<[999999d?aaa&bbb>";
    node = node_conddate_parse(str + 2, 1, 2, &parsed_until, &err);
    TEST_CHECK(node == NULL);

    str = "%<[4Q?aaa&bbb>";
    node = node_conddate_parse(str + 2, 1, 2, &parsed_until, &err);
    TEST_CHECK(node == NULL);
  }

  // int node_conddate_render(const struct ExpandoNode *node, const struct ExpandoRenderData *rdata, int max_cols, struct Buffer *buf);
  {
    static const struct ExpandoRenderCallback TestCallbacks[] = {
      // clang-format off
      { 1, 2, NULL, test_d_num },
      { -1, -1, NULL, NULL },
      // clang-format on
    };

    static const struct TestDates test_dates[] = {
      // clang-format off
      { "%<[2y?aaa&bbb>", 2*365*24*60*60 },
      { "%<[1y?aaa&bbb>",   365*24*60*60 },
      { "%<[2m?aaa&bbb>",  2*30*24*60*60 },
      { "%<[1m?aaa&bbb>",    30*24*60*60 },
      { "%<[2w?aaa&bbb>",   2*7*24*60*60 },
      { "%<[1w?aaa&bbb>",     7*24*60*60 },
      { "%<[2d?aaa&bbb>",     2*24*60*60 },
      { "%<[1d?aaa&bbb>",       24*60*60 },
      { "%<[2H?aaa&bbb>",        2*60*60 },
      { "%<[1H?aaa&bbb>",          60*60 },
      { "%<[2M?aaa&bbb>",           2*60 },
      { "%<[1M?aaa&bbb>",             60 },
      // clang-format off
    };

    const time_t now = time(NULL);
    struct Buffer *buf = buf_pool_get();
    const char *parsed_until = NULL;
    struct ExpandoParseError err = { 0 };

    for (size_t i = 0; i < mutt_array_size(test_dates); i++)
    {
      TEST_CASE(test_dates[i].str);
      struct ExpandoNode *node = node_conddate_parse(test_dates[i].str + 2, 1, 2, &parsed_until, &err);
      TEST_CHECK(node != NULL);

      int test_date = now - ((test_dates[i].time * 9) / 10); // 10% newer

      struct ExpandoRenderData TestRenderData[] = {
        // clang-format off
        { 1, TestCallbacks, &test_date, MUTT_FORMAT_NO_FLAGS },
        { -1, NULL, NULL, 0 },
        // clang-format on
      };

      int rc = node_conddate_render(node, TestRenderData, 99, buf);
      TEST_CHECK_NUM_EQ(rc, 1);
      TEST_CHECK(buf_is_empty(buf));

      test_date = now - ((test_dates[i].time * 11) / 10); // 10% older

      rc = node_conddate_render(node, TestRenderData, 99, buf);
      TEST_CHECK_NUM_EQ(rc, 0);
      TEST_CHECK(buf_is_empty(buf));

      node_free(&node);
    }

    buf_pool_release(&buf);
  }

  // int node_conddate_render(const struct ExpandoNode *node, const struct ExpandoRenderData *rdata, int max_cols, struct Buffer *buf);
  {
    static const struct ExpandoRenderCallback TestCallbacks[] = {
      // clang-format off
      { 1, 2, NULL, test_d_num },
      { -1, -1, NULL, NULL },
      // clang-format on
    };

    static const struct TestDates test_dates[] = {
      // clang-format off
      { "%<[y?aaa&bbb>", 365*24*60*60 },
      { "%<[m?aaa&bbb>",  30*24*60*60 },
      { "%<[w?aaa&bbb>",   7*24*60*60 },
      { "%<[d?aaa&bbb>",     24*60*60 },
      { "%<[H?aaa&bbb>",        60*60 },
      { "%<[M?aaa&bbb>",           60 },
      // clang-format off
    };

    const time_t now = time(NULL);
    struct Buffer *buf = buf_pool_get();
    const char *parsed_until = NULL;
    struct ExpandoParseError err = { 0 };
    int test_date = 0;

    struct ExpandoRenderData TestRenderData[] = {
      // clang-format off
      { 1, TestCallbacks, &test_date, MUTT_FORMAT_NO_FLAGS },
      { -1, NULL, NULL, 0 },
      // clang-format on
    };

    for (size_t i = 0; i < mutt_array_size(test_dates); i++)
    {
      TEST_CASE(test_dates[i].str);
      struct ExpandoNode *node = node_conddate_parse(test_dates[i].str + 2, 1,
                                                     2, &parsed_until, &err);
      TEST_CHECK(node != NULL);

      test_date = now - ((test_dates[i].time * 11) / 10); // 10% older

      int rc = node_conddate_render(node, TestRenderData, 99, buf);
      TEST_CHECK_NUM_EQ(rc, 0);
      TEST_CHECK(buf_is_empty(buf));

      node_free(&node);
    }

    buf_pool_release(&buf);
  }
}
