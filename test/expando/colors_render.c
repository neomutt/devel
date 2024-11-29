/**
 * @file
 * Test code for Expando Colour Rendering
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
#include "gui/lib.h"
#include "color/lib.h"
#include "expando/lib.h"
#include "common.h" // IWYU pragma: keep
#include "mutt_thread.h"
#include "test_common.h"

struct SimpleExpandoData
{
  const char *s;
  int C;
};

static void simple_s(const struct ExpandoNode *node, void *data,
                     MuttFormatFlags flags, struct Buffer *buf)
{
  ASSERT(node->type == ENT_EXPANDO);

  const struct SimpleExpandoData *sd = data;
  struct NodeExpandoPrivate *priv = node->ndata;

  priv->color = MT_COLOR_INDEX_SUBJECT;

  const char *s = NONULL(sd->s);
  buf_strcpy(buf, s);
}

static void simple_C(const struct ExpandoNode *node, void *data,
                     MuttFormatFlags flags, struct Buffer *buf)
{
  ASSERT(node->type == ENT_EXPANDO);

  const struct SimpleExpandoData *sd = data;
  struct NodeExpandoPrivate *priv = node->ndata;

  priv->color = MT_COLOR_INDEX_NUMBER;

  const int num = sd->C;
  buf_printf(buf, "%d", num);
}

void test_expando_colors_render(void)
{
  {
    const struct ExpandoDefinition defs[] = {
      // clang-format off
      { "*", "padding-soft", ED_GLOBAL, ED_GLO_PADDING_SOFT, node_padding_parse },
      { ">", "padding-hard", ED_GLOBAL, ED_GLO_PADDING_HARD, node_padding_parse },
      { "|", "padding-eol",  ED_GLOBAL, ED_GLO_PADDING_EOL,  node_padding_parse },
      { "s", NULL, 1, 0, NULL },
      { "C", NULL, 1, 1, NULL },
      { NULL, NULL, 0, 0, NULL },
      // clang-format on
    };

    const char *input = "%C - %s";

    struct Buffer *err = buf_pool_get();

    struct Expando *exp = expando_parse(input, defs, err);

    TEST_CHECK(exp != NULL);
    TEST_CHECK(buf_is_empty(err));

    check_node_expando(node_get_child(exp->node, 0), NULL, NULL);
    check_node_text(node_get_child(exp->node, 1), " - ");
    check_node_expando(node_get_child(exp->node, 2), NULL, NULL);

    const struct ExpandoRenderCallback TestCallbacks[] = {
      { 1, 0, simple_s },
      { 1, 1, simple_C },
      { -1, -1, NULL },
    };

    struct SimpleExpandoData data = {
      .s = "Test",
      .C = 1,
    };

    char expected[] = "XX1XX - XXTestXX";
    expected[0] = MUTT_SPECIAL_INDEX;
    expected[1] = MT_COLOR_INDEX_NUMBER;
    expected[3] = MUTT_SPECIAL_INDEX;
    expected[4] = MT_COLOR_INDEX;
    expected[8] = MUTT_SPECIAL_INDEX;
    expected[9] = MT_COLOR_INDEX_SUBJECT;
    expected[14] = MUTT_SPECIAL_INDEX;
    expected[15] = MT_COLOR_INDEX;

    struct ExpandoRenderData TestRenderData[] = {
      // clang-format off
      { 1, TestCallbacks, &data, MUTT_FORMAT_INDEX },
      { -1, NULL, NULL, 0 },
      // clang-format on
    };

    struct Buffer *buf = buf_pool_get();
    expando_render(exp, TestRenderData, buf->dsize, buf);

    const int expected_width = mutt_str_len(expected) - 8;
    TEST_CHECK(mutt_strwidth(expected) == expected_width);
    TEST_CHECK_STR_EQ(buf_string(buf), expected);

    expando_free(&exp);
    buf_pool_release(&buf);
    buf_pool_release(&err);
  }

  {
    const struct ExpandoDefinition defs[] = {
      // clang-format off
      { "*", "padding-soft", ED_GLOBAL, ED_GLO_PADDING_SOFT, node_padding_parse },
      { ">", "padding-hard", ED_GLOBAL, ED_GLO_PADDING_HARD, node_padding_parse },
      { "|", "padding-eol",  ED_GLOBAL, ED_GLO_PADDING_EOL,  node_padding_parse },
      { "s", NULL, 1, 0, NULL },
      { "C", NULL, 1, 1, NULL },
      { NULL, NULL, 0, 0, NULL },
      // clang-format on
    };

    const char *input = "%C %* %s";

    struct Buffer *err = buf_pool_get();

    struct Expando *exp = expando_parse(input, defs, err);

    TEST_CHECK(exp != NULL);
    TEST_CHECK(buf_is_empty(err));
    check_node_padding(exp->node, " ", EPT_SOFT_FILL);

    struct ExpandoNode *left = node_get_child(exp->node, ENP_LEFT);
    TEST_CHECK(left != NULL);
    struct ExpandoNode *right = node_get_child(exp->node, ENP_RIGHT);
    TEST_CHECK(right != NULL);

    check_node_expando(node_get_child(left, 0), NULL, NULL);
    check_node_text(node_get_child(left, 1), " ");
    check_node_expando(right, NULL, NULL);

    const struct ExpandoRenderCallback TestCallbacks[] = {
      { 1, 0, simple_s },
      { 1, 1, simple_C },
      { -1, -1, NULL },
    };

    struct SimpleExpandoData data = {
      .s = "Test",
      .C = 1,
    };

    char expected[] = "XX1XX   XXTestXX";
    expected[0] = MUTT_SPECIAL_INDEX;
    expected[1] = MT_COLOR_INDEX_NUMBER;
    expected[3] = MUTT_SPECIAL_INDEX;
    expected[4] = MT_COLOR_INDEX;
    expected[8] = MUTT_SPECIAL_INDEX;
    expected[9] = MT_COLOR_INDEX_SUBJECT;
    expected[14] = MUTT_SPECIAL_INDEX;
    expected[15] = MT_COLOR_INDEX;

    struct ExpandoRenderData TestRenderData[] = {
      // clang-format off
      { 1, TestCallbacks, &data, MUTT_FORMAT_INDEX },
      { -1, NULL, NULL, 0 },
      // clang-format on
    };

    struct Buffer *buf = buf_pool_get();
    expando_render(exp, TestRenderData, 8, buf);

    const int expected_width = mutt_str_len(expected) - 8;
    TEST_CHECK(mutt_strwidth(expected) == expected_width);
    TEST_CHECK_STR_EQ(buf_string(buf), expected);

    char expected2[] = "XX1XX XXTestXX";
    expected2[0] = MUTT_SPECIAL_INDEX;
    expected2[1] = MT_COLOR_INDEX_NUMBER;
    expected2[3] = MUTT_SPECIAL_INDEX;
    expected2[4] = MT_COLOR_INDEX;
    expected2[6] = MUTT_SPECIAL_INDEX;
    expected2[7] = MT_COLOR_INDEX_SUBJECT;
    expected2[12] = MUTT_SPECIAL_INDEX;
    expected2[13] = MT_COLOR_INDEX;

    buf_reset(buf);
    expando_render(exp, TestRenderData, 6, buf);

    const int expected_width2 = mutt_str_len(expected2) - 8;
    TEST_CHECK(mutt_strwidth(expected2) == expected_width2);
    TEST_CHECK_STR_EQ(buf_string(buf), expected2);

    expando_free(&exp);
    buf_pool_release(&buf);
    buf_pool_release(&err);
  }

  {
    const struct ExpandoDefinition defs[] = {
      // clang-format off
      { "*", "padding-soft", ED_GLOBAL, ED_GLO_PADDING_SOFT, node_padding_parse },
      { ">", "padding-hard", ED_GLOBAL, ED_GLO_PADDING_HARD, node_padding_parse },
      { "|", "padding-eol",  ED_GLOBAL, ED_GLO_PADDING_EOL,  node_padding_parse },
      { "s", NULL, 1, 0, NULL },
      { "C", NULL, 1, 1, NULL },
      { NULL, NULL, 0, 0, NULL },
      // clang-format on
    };

    const char *input = "%s %* %s";

    struct Buffer *err = buf_pool_get();

    struct Expando *exp = expando_parse(input, defs, err);

    TEST_CHECK(exp != NULL);
    TEST_CHECK(buf_is_empty(err));
    check_node_padding(exp->node, " ", EPT_SOFT_FILL);

    struct ExpandoNode *left = node_get_child(exp->node, ENP_LEFT);
    struct ExpandoNode *right = node_get_child(exp->node, ENP_RIGHT);

    TEST_CHECK(left != NULL);
    TEST_CHECK(right != NULL);

    check_node_expando(node_get_child(left, 0), NULL, NULL);
    check_node_text(node_get_child(left, 1), " ");
    check_node_expando(right, NULL, NULL);

    const struct ExpandoRenderCallback TestCallbacks[] = {
      { 1, 0, simple_s },
      { 1, 1, simple_C },
      { -1, -1, NULL },
    };

    struct SimpleExpandoData data = {
      .s = "Test",
      .C = 1,
    };

    char expected[] = "XXTeXXXXTestXX";
    expected[0] = MUTT_SPECIAL_INDEX;
    expected[1] = MT_COLOR_INDEX_SUBJECT;
    expected[4] = MUTT_SPECIAL_INDEX;
    expected[5] = MT_COLOR_INDEX;
    expected[6] = MUTT_SPECIAL_INDEX;
    expected[7] = MT_COLOR_INDEX_SUBJECT;
    expected[12] = MUTT_SPECIAL_INDEX;
    expected[13] = MT_COLOR_INDEX;

    struct ExpandoRenderData TestRenderData[] = {
      // clang-format off
      { 1, TestCallbacks, &data, MUTT_FORMAT_INDEX },
      { -1, NULL, NULL, 0 },
      // clang-format on
    };

    struct Buffer *buf = buf_pool_get();
    expando_render(exp, TestRenderData, 6, buf);

    const int expected_width = mutt_str_len(expected) - 8;
    TEST_CHECK(mutt_strwidth(expected) == expected_width);
    // TEST_CHECK_STR_EQ(buf_string(buf), expected);

    expando_free(&exp);
    buf_pool_release(&buf);
    buf_pool_release(&err);
  }

  {
    const struct ExpandoDefinition defs[] = {
      // clang-format off
      { "*", "padding-soft", ED_GLOBAL, ED_GLO_PADDING_SOFT, node_padding_parse },
      { ">", "padding-hard", ED_GLOBAL, ED_GLO_PADDING_HARD, node_padding_parse },
      { "|", "padding-eol",  ED_GLOBAL, ED_GLO_PADDING_EOL,  node_padding_parse },
      { "s", NULL, 1, 0, NULL },
      { "C", NULL, 1, 1, NULL },
      { NULL, NULL, 0, 0, NULL },
      // clang-format on
    };

    const char *input = "%s %* %s";

    struct Buffer *err = buf_pool_get();

    struct Expando *exp = expando_parse(input, defs, err);

    TEST_CHECK(exp != NULL);
    TEST_CHECK(buf_is_empty(err));
    check_node_padding(exp->node, " ", EPT_SOFT_FILL);

    struct ExpandoNode *left = node_get_child(exp->node, ENP_LEFT);
    struct ExpandoNode *right = node_get_child(exp->node, ENP_RIGHT);

    TEST_CHECK(left != NULL);
    TEST_CHECK(right != NULL);

    check_node_expando(node_get_child(left, 0), NULL, NULL);
    check_node_text(node_get_child(left, 1), " ");
    check_node_expando(right, NULL, NULL);

    const struct ExpandoRenderCallback TestCallbacks[] = {
      { 1, 0, simple_s },
      { 1, 1, simple_C },
      { -1, -1, NULL },
    };

    struct SimpleExpandoData data = {
      .s = "Tá éí",
      .C = 1,
    };

    struct ExpandoRenderData TestRenderData[] = {
      // clang-format off
      { 1, TestCallbacks, &data, MUTT_FORMAT_INDEX },
      { -1, NULL, NULL, 0 },
      // clang-format on
    };

    char expected[] = "\x0e\x63Tá \x0e\x5b\x0e\x63Táéí\x0e\x5b";
    struct Buffer *buf = buf_pool_get();
    expando_render(exp, TestRenderData, 7, buf);

    TEST_CHECK_NUM_EQ(mutt_strwidth(expected), 7);
    // TEST_CHECK_STR_EQ(buf_string(buf), expected);

    expando_free(&exp);
    buf_pool_release(&buf);
    buf_pool_release(&err);
  }
}
