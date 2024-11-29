/**
 * @file
 * Test code for Padding Expando Rendering
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
#include <stddef.h>
#include "mutt/lib.h"
#include "expando/lib.h"
#include "common.h" // IWYU pragma: keep
#include "test_common.h"

struct NullData
{
  int n;
};

void test_expando_padding_render(void)
{
  static const struct ExpandoDefinition FormatDef[] = {
    // clang-format off
    { "*", "padding-soft", ED_GLOBAL, ED_GLO_PADDING_SOFT, node_padding_parse },
    { ">", "padding-hard", ED_GLOBAL, ED_GLO_PADDING_HARD, node_padding_parse },
    { "|", "padding-eol",  ED_GLOBAL, ED_GLO_PADDING_EOL,  node_padding_parse },
    { NULL, NULL, 0, -1, NULL }
    // clang-format on
  };

  struct Buffer *err = buf_pool_get();

  {
    const char *input = "text1%|-text2";

    struct Expando *exp = expando_parse(input, FormatDef, err);
    TEST_CHECK(exp != NULL);
    TEST_CHECK(buf_is_empty(err));

    check_node_padding(exp->node, "-", EPT_FILL_EOL);

    struct ExpandoNode *left = node_get_child(exp->node, ENP_LEFT);
    struct ExpandoNode *right = node_get_child(exp->node, ENP_RIGHT);

    TEST_CHECK(left != NULL);
    TEST_CHECK(right != NULL);

    check_node_text(left, "text1");
    check_node_text(right, "text2");

    const struct ExpandoRenderCallback TestCallbacks[] = {
      { -1, -1, NULL },
    };

    struct NullData data = { 0 };

    struct ExpandoRenderData TestRenderData[] = {
      // clang-format off
      { 1, TestCallbacks, &data, MUTT_FORMAT_NO_FLAGS },
      { -1, NULL, NULL, 0 },
      // clang-format on
    };

    const char *expected = "text1---";
    struct Buffer *buf = buf_pool_get();
    expando_render(exp, TestRenderData, 8, buf);

    TEST_CHECK_STR_EQ(buf_string(buf), expected);

    expando_free(&exp);
    buf_pool_release(&err);
    buf_pool_release(&buf);
  }

  {
    const char *input = "text1%|-text2";

    struct Expando *exp = expando_parse(input, FormatDef, err);

    check_node_padding(exp->node, "-", EPT_FILL_EOL);

    struct ExpandoNode *left = node_get_child(exp->node, ENP_LEFT);
    struct ExpandoNode *right = node_get_child(exp->node, ENP_RIGHT);

    TEST_CHECK(left != NULL);
    TEST_CHECK(right != NULL);

    check_node_text(left, "text1");
    check_node_text(right, "text2");

    const struct ExpandoRenderCallback TestCallbacks[] = {
      { -1, -1, NULL },
    };

    struct NullData data = { 0 };

    struct ExpandoRenderData TestRenderData[] = {
      // clang-format off
      { 1, TestCallbacks, &data, MUTT_FORMAT_NO_FLAGS },
      { -1, NULL, NULL, 0 },
      // clang-format on
    };

    const char *expected = "text1--------";
    struct Buffer *buf = buf_pool_get();
    expando_render(exp, TestRenderData, 13, buf);

    TEST_CHECK_STR_EQ(buf_string(buf), expected);

    expando_free(&exp);
    buf_pool_release(&err);
    buf_pool_release(&buf);
  }

  {
    const char *input = "text1%>-text2";

    struct Expando *exp = expando_parse(input, FormatDef, err);
    TEST_CHECK(exp != NULL);
    TEST_CHECK(buf_is_empty(err));

    check_node_padding(exp->node, "-", EPT_HARD_FILL);

    struct ExpandoNode *left = node_get_child(exp->node, ENP_LEFT);
    struct ExpandoNode *right = node_get_child(exp->node, ENP_RIGHT);

    TEST_CHECK(left != NULL);
    TEST_CHECK(right != NULL);

    check_node_text(left, "text1");
    check_node_text(right, "text2");

    const struct ExpandoRenderCallback TestCallbacks[] = {
      { -1, -1, NULL },
    };

    struct NullData data = { 0 };

    struct ExpandoRenderData TestRenderData[] = {
      // clang-format off
      { 1, TestCallbacks, &data, MUTT_FORMAT_NO_FLAGS },
      { -1, NULL, NULL, 0 },
      // clang-format on
    };

    const char *expected = "text1tex";
    struct Buffer *buf = buf_pool_get();
    expando_render(exp, TestRenderData, 8, buf);
    TEST_CHECK_STR_EQ(buf_string(buf), expected);

    expando_free(&exp);
    buf_pool_release(&err);
    buf_pool_release(&buf);
  }

  {
    const char *input = "text1%>-text2";

    struct Expando *exp = expando_parse(input, FormatDef, err);
    TEST_CHECK(exp != NULL);
    TEST_CHECK(buf_is_empty(err));

    check_node_padding(exp->node, "-", EPT_HARD_FILL);

    struct ExpandoNode *left = node_get_child(exp->node, ENP_LEFT);
    struct ExpandoNode *right = node_get_child(exp->node, ENP_RIGHT);

    TEST_CHECK(left != NULL);
    TEST_CHECK(right != NULL);

    check_node_text(left, "text1");
    check_node_text(right, "text2");

    const struct ExpandoRenderCallback TestCallbacks[] = {
      { -1, -1, NULL },
    };

    struct NullData data = { 0 };

    struct ExpandoRenderData TestRenderData[] = {
      // clang-format off
      { 1, TestCallbacks, &data, MUTT_FORMAT_NO_FLAGS },
      { -1, NULL, NULL, 0 },
      // clang-format on
    };

    const char *expected = "text1---text2";
    struct Buffer *buf = buf_pool_get();
    expando_render(exp, TestRenderData, 13, buf);

    TEST_CHECK_STR_EQ(buf_string(buf), expected);

    expando_free(&exp);
    buf_pool_release(&err);
    buf_pool_release(&buf);
  }

  {
    const char *input = "text1%*-text2";

    struct Expando *exp = expando_parse(input, FormatDef, err);
    TEST_CHECK(exp != NULL);
    TEST_CHECK(buf_is_empty(err));

    check_node_padding(exp->node, "-", EPT_SOFT_FILL);

    struct ExpandoNode *left = node_get_child(exp->node, ENP_LEFT);
    struct ExpandoNode *right = node_get_child(exp->node, ENP_RIGHT);

    TEST_CHECK(left != NULL);
    TEST_CHECK(right != NULL);

    check_node_text(left, "text1");
    check_node_text(right, "text2");

    const struct ExpandoRenderCallback TestCallbacks[] = {
      { -1, -1, NULL },
    };

    struct NullData data = { 0 };

    struct ExpandoRenderData TestRenderData[] = {
      // clang-format off
      { 1, TestCallbacks, &data, MUTT_FORMAT_NO_FLAGS },
      { -1, NULL, NULL, 0 },
      // clang-format on
    };

    const char *expected = "textext2";
    struct Buffer *buf = buf_pool_get();
    expando_render(exp, TestRenderData, 8, buf);

    TEST_CHECK_STR_EQ(buf_string(buf), expected);

    expando_free(&exp);
    buf_pool_release(&err);
    buf_pool_release(&buf);
  }

  {
    const char *input = "text1%*-text2";

    struct Expando *exp = expando_parse(input, FormatDef, err);
    TEST_CHECK(exp != NULL);
    TEST_CHECK(buf_is_empty(err));

    check_node_padding(exp->node, "-", EPT_SOFT_FILL);

    struct ExpandoNode *left = node_get_child(exp->node, ENP_LEFT);
    struct ExpandoNode *right = node_get_child(exp->node, ENP_RIGHT);

    TEST_CHECK(left != NULL);
    TEST_CHECK(right != NULL);

    check_node_text(left, "text1");
    check_node_text(right, "text2");

    const struct ExpandoRenderCallback TestCallbacks[] = {
      { -1, -1, NULL },
    };

    struct NullData data = { 0 };

    struct ExpandoRenderData TestRenderData[] = {
      // clang-format off
      { 1, TestCallbacks, &data, MUTT_FORMAT_NO_FLAGS },
      { -1, NULL, NULL, 0 },
      // clang-format on
    };

    const char *expected = "text1---text2";
    struct Buffer *buf = buf_pool_get();
    expando_render(exp, TestRenderData, 13, buf);

    TEST_CHECK_STR_EQ(buf_string(buf), expected);

    expando_free(&exp);
    buf_pool_release(&err);
    buf_pool_release(&buf);
  }

  {
    const char *input = "text1%*-text2";

    struct Expando *exp = expando_parse(input, FormatDef, err);
    TEST_CHECK(exp != NULL);
    TEST_CHECK(buf_is_empty(err));

    check_node_padding(exp->node, "-", EPT_SOFT_FILL);

    struct ExpandoNode *left = node_get_child(exp->node, ENP_LEFT);
    struct ExpandoNode *right = node_get_child(exp->node, ENP_RIGHT);

    TEST_CHECK(left != NULL);
    TEST_CHECK(right != NULL);

    check_node_text(left, "text1");
    check_node_text(right, "text2");

    const struct ExpandoRenderCallback TestCallbacks[] = {
      { -1, -1, NULL },
    };

    struct NullData data = { 0 };

    struct ExpandoRenderData TestRenderData[] = {
      // clang-format off
      { 1, TestCallbacks, &data, MUTT_FORMAT_NO_FLAGS },
      { -1, NULL, NULL, 0 },
      // clang-format on
    };

    const char *expected = "text2";
    struct Buffer *buf = buf_pool_get();
    expando_render(exp, TestRenderData, 5, buf);

    TEST_CHECK_STR_EQ(buf_string(buf), expected);

    expando_free(&exp);
    buf_pool_release(&err);
    buf_pool_release(&buf);
  }
}
