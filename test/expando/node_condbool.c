/**
 * @file
 * Test CondBool Expando
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
#include <string.h>
#include "mutt/lib.h"
#include "expando/lib.h"
#include "common.h" // IWYU pragma: keep
#include "test_common.h"

struct ExpandoNode *node_conddate_new(int count, char period, int did, int uid);

static long test_y_num(const struct ExpandoNode *node, void *data, MuttFormatFlags flags)
{
  return 42;
}

static void test_y(const struct ExpandoNode *node, void *data,
                   MuttFormatFlags flags, struct Buffer *buf)
{
  buf_strcpy(buf, "hello");
}

static long test_n_num(const struct ExpandoNode *node, void *data, MuttFormatFlags flags)
{
  return 0;
}

static void test_n(const struct ExpandoNode *node, void *data,
                   MuttFormatFlags flags, struct Buffer *buf)
{
}

static struct ExpandoNode *node_condbool_new(const char *start, const char *end,
                                             int did, int uid)
{
  struct ExpandoNode *node = node_new();

  node->type = ENT_CONDBOOL;
  node->did = did;
  node->uid = uid;
  node->render = node_condbool_render;

  return node;
}

static struct ExpandoNode *parse_test(const char *str, struct ExpandoFormat *fmt,
                                      int did, int uid, ExpandoParserFlags flags,
                                      const char **parsed_until,
                                      struct ExpandoParseError *err)
{
  *parsed_until = str + 1;
  return node_condbool_new(str, str + 1, did, uid);
}

void test_expando_node_condbool(void)
{
  static const struct ExpandoDefinition TestFormatDef[] = {
    // clang-format off
    { "a",  "apple",  1, 2, NULL },
    { "b",  "banana", 1, 3, NULL },
    { "c",  "cherry", 1, 4, parse_test },
    { "d",  "damson", 1, 5, parse_test },
    { "e",  "endive", 1, 6, NULL },
    { NULL, NULL, 0, -1, NULL }
    // clang-format on
  };

  static const struct ExpandoRenderCallback TestCallbacks[] = {
    // clang-format off
    { 1, 2, test_y, test_y_num },
    { 1, 3, test_n, test_n_num },
    { 1, 4, test_y, NULL },
    { 1, 5, test_n, NULL },
    { 1, 6, NULL,   NULL },
    { -1, -1, NULL, NULL },
    // clang-format on
  };

  // int node_condbool_render(const struct ExpandoNode *node, const struct ExpandoRenderCallback *rdata, struct Buffer *buf, int max_cols, void *data, MuttFormatFlags flags);
  {
    struct Buffer *buf = buf_pool_get();
    struct ExpandoNode *node = NULL;
    struct ExpandoNode *node_cond = NULL;
    const char *str = NULL;
    int rc;

    const char *parsed_until = NULL;
    struct ExpandoParseError err = { 0 };

    struct ExpandoRenderData TestRenderData[] = {
      // clang-format off
      { 1, TestCallbacks, NULL, MUTT_FORMAT_NO_FLAGS },
      { -1, NULL, NULL, 0 },
      // clang-format on
    };

    str = "%<a?x&y>";
    node = node_parse_one(str, NTE_NO_FLAGS, TestFormatDef, &parsed_until, &err);
    TEST_CHECK(node != NULL);
    node_cond = node_get_child(node, ENC_CONDITION);
    TEST_CHECK(node_cond != NULL);
    rc = node_condbool_render(node_cond, TestRenderData, 99, buf);
    TEST_CHECK_NUM_EQ(rc, 1);
    node_free(&node);

    str = "%<b?x&y>";
    memset(&err, 0, sizeof(err));
    node = node_parse_one(str, NTE_NO_FLAGS, TestFormatDef, &parsed_until, &err);
    TEST_CHECK(node != NULL);
    node_cond = node_get_child(node, ENC_CONDITION);
    TEST_CHECK(node_cond != NULL);
    rc = node_condbool_render(node_cond, TestRenderData, 99, buf);
    TEST_CHECK_NUM_EQ(rc, 0);
    node_free(&node);

    str = "%<c?x&y>";
    memset(&err, 0, sizeof(err));
    node = node_parse_one(str, NTE_NO_FLAGS, TestFormatDef, &parsed_until, &err);
    TEST_CHECK(node != NULL);
    node_cond = node_get_child(node, ENC_CONDITION);
    TEST_CHECK(node_cond != NULL);
    rc = node_condbool_render(node_cond, TestRenderData, 99, buf);
    TEST_CHECK_NUM_EQ(rc, 1);
    node_free(&node);

    str = "%<d?x&y>";
    memset(&err, 0, sizeof(err));
    node = node_parse_one(str, NTE_NO_FLAGS, TestFormatDef, &parsed_until, &err);
    TEST_CHECK(node != NULL);
    node_cond = node_get_child(node, ENC_CONDITION);
    TEST_CHECK(node_cond != NULL);
    rc = node_condbool_render(node_cond, TestRenderData, 99, buf);
    TEST_CHECK_NUM_EQ(rc, 0);
    node_free(&node);

    str = "%<e?x&y>";
    memset(&err, 0, sizeof(err));
    node = node_parse_one(str, NTE_NO_FLAGS, TestFormatDef, &parsed_until, &err);
    TEST_CHECK(node != NULL);
    node_cond = node_get_child(node, ENC_CONDITION);
    TEST_CHECK(node_cond != NULL);
    rc = node_condbool_render(node_cond, TestRenderData, 99, buf);
    TEST_CHECK_NUM_EQ(rc, 0);
    node_free(&node);

    buf_pool_release(&buf);
  }
}
