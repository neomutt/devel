/**
 * @file
 * Test Padding Expando
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
#include "mutt/lib.h"
#include "alias/gui.h" // IWYU pragma: keep
#include "alias/lib.h"
#include "expando/lib.h"
#include "common.h" // IWYU pragma: keep
#include "test_common.h"

struct NodePaddingPrivate *node_padding_private_new(enum ExpandoPadType pad_type);
void node_padding_private_free(void **ptr);
struct ExpandoNode *node_padding_new(enum ExpandoPadType pad_type,
                                     const char *start, const char *end);
int pad_string(const struct ExpandoNode *node, struct Buffer *buf, int max_cols);
void expando_serialise(const struct Expando *exp, struct Buffer *buf);
int node_padding_render_eol(const struct ExpandoNode *node,
                            const struct ExpandoRenderData *rdata, int max_cols,
                            struct Buffer *buf);
int node_padding_render_hard(const struct ExpandoNode *node,
                             const struct ExpandoRenderData *rdata,
                             int max_cols, struct Buffer *buf);
int node_padding_render_soft(const struct ExpandoNode *node,
                             const struct ExpandoRenderData *rdata,
                             int max_cols, struct Buffer *buf);

void test_expando_node_padding(void)
{
  static const struct ExpandoDefinition TestFormatDef[] = {
    // clang-format off
    { "*", "padding-soft", ED_GLOBAL, ED_GLO_PADDING_SOFT, node_padding_parse },
    { ">", "padding-hard", ED_GLOBAL, ED_GLO_PADDING_HARD, node_padding_parse },
    { "|", "padding-eol",  ED_GLOBAL, ED_GLO_PADDING_EOL,  node_padding_parse },
    { "a", "apple",        ED_ALIAS,  ED_ALI_ADDRESS,      NULL               },
    { "b", "banana",       ED_ALIAS,  ED_ALI_COMMENT,      NULL               },
    { "c", "cherry",       ED_ALIAS,  ED_ALI_FLAGS,        NULL               },
    { "d", "damson",       ED_ALIAS,  ED_ALI_NAME,         NULL               },
    { NULL, NULL, 0, -1, NULL }
    // clang-format on
  };

  static const struct ExpandoRenderCallback TestCallbacks[] = {
    // clang-format off
    { -1, -1, NULL, NULL },
    // clang-format on
  };

  // struct NodePaddingPrivate *node_padding_private_new(enum ExpandoPadType pad_type);
  // void node_padding_private_free(void **ptr);
  {
    struct NodePaddingPrivate *priv = node_padding_private_new(EPT_HARD_FILL);
    TEST_CHECK(priv != NULL);
    node_padding_private_free((void **) &priv);
    node_padding_private_free(NULL);
  }

  // struct ExpandoNode *node_padding_new(enum ExpandoPadType pad_type, const char *start, const char *end);
  {
    const char *str = NULL;
    struct ExpandoNode *node = NULL;

    str = "%|X";
    node = node_padding_new(EPT_FILL_EOL, str + 2, str + 3);
    TEST_CHECK(node != NULL);
    node_free(&node);

    str = "%>X";
    node = node_padding_new(EPT_HARD_FILL, str + 2, str + 3);
    TEST_CHECK(node != NULL);
    node_free(&node);

    str = "%*X";
    node = node_padding_new(EPT_SOFT_FILL, str + 2, str + 3);
    TEST_CHECK(node != NULL);
    node_free(&node);
  }

  // int pad_string(const struct ExpandoNode *node, struct Buffer *buf, int max_cols);
  {
    struct Buffer *buf = buf_pool_get();
    struct ExpandoNode node = { 0 };
    int rc;

    node.text = "a"; // Padding character
    buf_strcpy(buf, "apple");
    rc = pad_string(&node, buf, 15);
    TEST_CHECK_NUM_EQ(rc, 15);

    node.text = "é"; // Padding character
    buf_strcpy(buf, "apple");
    rc = pad_string(&node, buf, 15);
    TEST_CHECK_NUM_EQ(rc, 15);

    node.text = "本"; // Padding character
    buf_strcpy(buf, "apple");
    rc = pad_string(&node, buf, 15);
    TEST_CHECK_NUM_EQ(rc, 15);

    node.text = "🍓"; // Padding character
    buf_strcpy(buf, "apple");
    rc = pad_string(&node, buf, 15);
    TEST_CHECK_NUM_EQ(rc, 15);

    buf_pool_release(&buf);
  }

  // struct ExpandoNode *node_padding_parse(const char *str, struct ExpandoFormat *fmt, int did, int uid, ExpandoParserFlags flags, const char **parsed_until, struct ExpandoParseError *err);
  {
    struct ExpandoParseError err = { 0 };
    const char *str = NULL;
    const char *parsed_until = NULL;
    struct ExpandoNode *node = NULL;

    str = "?X";
    node = node_padding_parse(str, NULL, 1, 2, EP_NO_FLAGS, &parsed_until, &err);
    TEST_CHECK(node == NULL);

    str = "|X";
    node = node_padding_parse(str, NULL, 1, 2, EP_CONDITIONAL, &parsed_until, &err);
    TEST_CHECK(node == NULL);

    str = "|X";
    node = node_padding_parse(str, NULL, 1, 2, EP_NO_FLAGS, &parsed_until, &err);
    TEST_CHECK(node != NULL);
    node_free(&node);

    str = ">X";
    node = node_padding_parse(str, NULL, 1, 2, EP_NO_FLAGS, &parsed_until, &err);
    TEST_CHECK(node != NULL);
    node_free(&node);

    str = "*X";
    node = node_padding_parse(str, NULL, 1, 2, EP_NO_FLAGS, &parsed_until, &err);
    TEST_CHECK(node != NULL);
    node_free(&node);
  }

  // void node_padding_repad(struct ExpandoNode **parent);
  {
    static const char *TestStrings[][2] = {
      // clang-format off
      { "",                     "" },
      { "%a",                   "<EXP:(ALIAS,ADDRESS)>" },
      { "%a%b",                 "<CONT:<EXP:(ALIAS,ADDRESS)><EXP:(ALIAS,COMMENT)>>" },

      { "%|X",                  "<PAD:FILL_EOL:'X':|>" },
      { "%a%|X",                "<PAD:FILL_EOL:'X':<EXP:(ALIAS,ADDRESS)>|>" },
      { "%a%b%|X",              "<PAD:FILL_EOL:'X':<CONT:<EXP:(ALIAS,ADDRESS)><EXP:(ALIAS,COMMENT)>>|>" },
      { "%|X%c",                "<PAD:FILL_EOL:'X':|<EXP:(ALIAS,FLAGS)>>" },
      { "%|X%c%d",              "<PAD:FILL_EOL:'X':|<CONT:<EXP:(ALIAS,FLAGS)><EXP:(ALIAS,NAME)>>>" },
      { "%a%|X%c",              "<PAD:FILL_EOL:'X':<EXP:(ALIAS,ADDRESS)>|<EXP:(ALIAS,FLAGS)>>" },
      { "%a%b%|X%c%d",          "<PAD:FILL_EOL:'X':<CONT:<EXP:(ALIAS,ADDRESS)><EXP:(ALIAS,COMMENT)>>|<CONT:<EXP:(ALIAS,FLAGS)><EXP:(ALIAS,NAME)>>>" },
      { "%<a?%a%|X%b&%c%|X%d>", "<COND:<BOOL(ALIAS,ADDRESS)>|<PAD:FILL_EOL:'X':<EXP:(ALIAS,ADDRESS)>|<EXP:(ALIAS,COMMENT)>>|<PAD:FILL_EOL:'X':<EXP:(ALIAS,FLAGS)>|<EXP:(ALIAS,NAME)>>>" },

      { "%>X",                  "<PAD:HARD_FILL:'X':|>" },
      { "%a%>X",                "<PAD:HARD_FILL:'X':<EXP:(ALIAS,ADDRESS)>|>" },
      { "%a%b%>X",              "<PAD:HARD_FILL:'X':<CONT:<EXP:(ALIAS,ADDRESS)><EXP:(ALIAS,COMMENT)>>|>" },
      { "%>X%c",                "<PAD:HARD_FILL:'X':|<EXP:(ALIAS,FLAGS)>>" },
      { "%>X%c%d",              "<PAD:HARD_FILL:'X':|<CONT:<EXP:(ALIAS,FLAGS)><EXP:(ALIAS,NAME)>>>" },
      { "%a%>X%c",              "<PAD:HARD_FILL:'X':<EXP:(ALIAS,ADDRESS)>|<EXP:(ALIAS,FLAGS)>>" },
      { "%a%b%>X%c%d",          "<PAD:HARD_FILL:'X':<CONT:<EXP:(ALIAS,ADDRESS)><EXP:(ALIAS,COMMENT)>>|<CONT:<EXP:(ALIAS,FLAGS)><EXP:(ALIAS,NAME)>>>" },
      { "%<a?%a%>X%b&%c%>X%d>", "<COND:<BOOL(ALIAS,ADDRESS)>|<PAD:HARD_FILL:'X':<EXP:(ALIAS,ADDRESS)>|<EXP:(ALIAS,COMMENT)>>|<PAD:HARD_FILL:'X':<EXP:(ALIAS,FLAGS)>|<EXP:(ALIAS,NAME)>>>" },

      { "%*X",                  "<PAD:SOFT_FILL:'X':|>" },
      { "%a%*X",                "<PAD:SOFT_FILL:'X':<EXP:(ALIAS,ADDRESS)>|>" },
      { "%a%b%*X",              "<PAD:SOFT_FILL:'X':<CONT:<EXP:(ALIAS,ADDRESS)><EXP:(ALIAS,COMMENT)>>|>" },
      { "%*X%c",                "<PAD:SOFT_FILL:'X':|<EXP:(ALIAS,FLAGS)>>" },
      { "%*X%c%d",              "<PAD:SOFT_FILL:'X':|<CONT:<EXP:(ALIAS,FLAGS)><EXP:(ALIAS,NAME)>>>" },
      { "%a%*X%c",              "<PAD:SOFT_FILL:'X':<EXP:(ALIAS,ADDRESS)>|<EXP:(ALIAS,FLAGS)>>" },
      { "%a%b%*X%c%d",          "<PAD:SOFT_FILL:'X':<CONT:<EXP:(ALIAS,ADDRESS)><EXP:(ALIAS,COMMENT)>>|<CONT:<EXP:(ALIAS,FLAGS)><EXP:(ALIAS,NAME)>>>" },
      { "%<a?%a%*X%b&%c%*X%d>", "<COND:<BOOL(ALIAS,ADDRESS)>|<PAD:SOFT_FILL:'X':<EXP:(ALIAS,ADDRESS)>|<EXP:(ALIAS,COMMENT)>>|<PAD:SOFT_FILL:'X':<EXP:(ALIAS,FLAGS)>|<EXP:(ALIAS,NAME)>>>" },
      // clang-format off
    };

    node_padding_repad(NULL);

    struct Buffer *buf = buf_pool_get();
    struct Buffer *err = buf_pool_get();
    struct Expando *exp = NULL;

    for (int i = 0; i < mutt_array_size(TestStrings); i++)
    {
      buf_reset(buf);
      buf_reset(err);

      const char *format = TestStrings[i][0];
      const char *expected = TestStrings[i][1];
      TEST_CASE(format);

      exp = expando_parse(format, TestFormatDef, err);

      TEST_CHECK(buf_is_empty(err));
      TEST_MSG(buf_string(err));
      expando_serialise(exp, buf);
      TEST_CHECK_STR_EQ(buf_string(buf), expected);
      expando_free(&exp);
    }

    buf_pool_release(&buf);
    buf_pool_release(&err);
  }

  // int node_padding_render_eol(const struct ExpandoNode *node, const struct ExpandoRenderData *rdata, int max_cols, struct Buffer *buf);
  {
    char *EolTests[][2] = {
      // clang-format off
      { "%|X",        "XXXXXXXXXXXXXXXXXXX" },
      { "AAA%|X",     "AAAXXXXXXXXXXXXXXXX" },
      { "%|XBBB",     "XXXXXXXXXXXXXXXXXXX" },
      { "AAA%|XBBB",  "AAAXXXXXXXXXXXXXXXX" },
      { "%|本",       "本本本本本本本本本 " },
      { "AAA%|本",    "AAA本本本本本本本本" },
      { "%|本BBB",    "本本本本本本本本本 " },
      { "AAA%|本BBB", "AAA本本本本本本本本" },
      // clang-format off
    };

    struct Buffer *buf = buf_pool_get();
    struct Buffer *err = buf_pool_get();
    struct Expando *exp = NULL;
    int rc;

    struct ExpandoRenderData TestRenderData[] = {
      // clang-format off
      { 1, TestCallbacks, NULL, MUTT_FORMAT_NO_FLAGS },
      { -1, NULL, NULL, 0 },
      // clang-format on
    };

    for (int i = 0; i < mutt_array_size(EolTests); i++)
    {
      buf_reset(buf);
      buf_reset(err);

      const char *format = EolTests[i][0];
      const char *expected = EolTests[i][1];
      TEST_CASE(format);

      exp = expando_parse(format, TestFormatDef, err);
      TEST_CHECK(buf_is_empty(err));
      TEST_MSG(buf_string(err));
      rc = node_padding_render_eol(exp->node, TestRenderData, 19, buf);
      TEST_CHECK_NUM_EQ(rc, 19);
      TEST_CHECK_STR_EQ(buf_string(buf), expected);
      expando_free(&exp);
    }

    buf_pool_release(&buf);
    buf_pool_release(&err);
  }

  // int node_padding_render_hard(const struct ExpandoNode *node, const struct ExpandoRenderData *rdata, int max_cols, struct Buffer *buf);
  {
    char *HardTests[][2] = {
      // clang-format off
      { "%>X",                          "XXXXXXXXXXXXXXXXXXX" },
      { "AAA%>X",                       "AAAXXXXXXXXXXXXXXXX" },
      { "%>XBBB",                       "XXXXXXXXXXXXXXXXBBB" },
      { "AAA%>XBBB",                    "AAAXXXXXXXXXXXXXBBB" },

      { "ABCDEFGHIJKLMNOP%>.",          "ABCDEFGHIJKLMNOP..." },
      { "ABCDEFGHIJKLMNOPQ%>.",         "ABCDEFGHIJKLMNOPQ.." },
      { "ABCDEFGHIJKLMNOPQR%>.",        "ABCDEFGHIJKLMNOPQR." },
      { "ABCDEFGHIJKLMNOPQRS%>.",       "ABCDEFGHIJKLMNOPQRS" },
      { "ABCDEFGHIJKLMNOPQRST%>.",      "ABCDEFGHIJKLMNOPQRS" },
      { "ABCDEFGHIJKLMNOPQRSTU%>.",     "ABCDEFGHIJKLMNOPQRS" },
      { "ABCDEFGHIJKLMNOPQRSTUV%>.",    "ABCDEFGHIJKLMNOPQRS" },

      { "%>.abcdefghijklmnop",          "...abcdefghijklmnop" },
      { "%>.abcdefghijklmnopq",         "..abcdefghijklmnopq" },
      { "%>.abcdefghijklmnopqr",        ".abcdefghijklmnopqr" },
      { "%>.abcdefghijklmnopqrs",       "abcdefghijklmnopqrs" },
      { "%>.abcdefghijklmnopqrst",      "abcdefghijklmnopqrs" },
      { "%>.abcdefghijklmnopqrstu",     "abcdefghijklmnopqrs" },
      { "%>.abcdefghijklmnopqrstuv",    "abcdefghijklmnopqrs" },

      { "ABCDEFGHIJ%>.abcdefg",         "ABCDEFGHIJ..abcdefg" },
      { "ABCDEFGHIJ%>.abcdefgh",        "ABCDEFGHIJ.abcdefgh" },
      { "ABCDEFGHIJ%>.abcdefghi",       "ABCDEFGHIJabcdefghi" },
      { "ABCDEFGHIJ%>.abcdefghij",      "ABCDEFGHIJabcdefghi" },
      { "ABCDEFGHIJ%>.abcdefghijk",     "ABCDEFGHIJabcdefghi" },
      { "ABCDEFGHIJ%>.abcdefghijkl",    "ABCDEFGHIJabcdefghi" },
      { "ABCDEFGHIJ%>.abcdefghijklm",   "ABCDEFGHIJabcdefghi" },
      { "ABCDEFGHIJ%>.abcdefghijklmn",  "ABCDEFGHIJabcdefghi" },

      { "%>X",                          "XXXXXXXXXXXXXXXXXXX" },
      { "AAA%>X",                       "AAAXXXXXXXXXXXXXXXX" },
      { "%>XBBB",                       "XXXXXXXXXXXXXXXXBBB" },
      { "AAA%>XBBB",                    "AAAXXXXXXXXXXXXXBBB" },

      { "ABCDEFGHIJKLMNOP%>本",         "ABCDEFGHIJKLMNOP本 " },
      { "ABCDEFGHIJKLMNOPQ%>本",        "ABCDEFGHIJKLMNOPQ本" },
      { "ABCDEFGHIJKLMNOPQR%>本",       "ABCDEFGHIJKLMNOPQR " },
      { "ABCDEFGHIJKLMNOPQRS%>本",      "ABCDEFGHIJKLMNOPQRS" },
      { "ABCDEFGHIJKLMNOPQRST%>本",     "ABCDEFGHIJKLMNOPQRS" },
      { "ABCDEFGHIJKLMNOPQRSTU%>本",    "ABCDEFGHIJKLMNOPQRS" },
      { "ABCDEFGHIJKLMNOPQRSTUV%>本",   "ABCDEFGHIJKLMNOPQRS" },

      { "%>本abcdefghijklmnop",         "本 abcdefghijklmnop" },
      { "%>本abcdefghijklmnopq",        "本abcdefghijklmnopq" },
      { "%>本abcdefghijklmnopqr",       " abcdefghijklmnopqr" },
      { "%>本abcdefghijklmnopqrs",      "abcdefghijklmnopqrs" },
      { "%>本abcdefghijklmnopqrst",     "abcdefghijklmnopqrs" },
      { "%>本abcdefghijklmnopqrstu",    "abcdefghijklmnopqrs" },
      { "%>本abcdefghijklmnopqrstuv",   "abcdefghijklmnopqrs" },

      { "ABCDEFGHIJ%>本abcdefg",        "ABCDEFGHIJ本abcdefg" },
      { "ABCDEFGHIJ%>本abcdefgh",       "ABCDEFGHIJ abcdefgh" },
      { "ABCDEFGHIJ%>本abcdefghi",      "ABCDEFGHIJabcdefghi" },
      { "ABCDEFGHIJ%>本abcdefghij",     "ABCDEFGHIJabcdefghi" },
      { "ABCDEFGHIJ%>本abcdefghijk",    "ABCDEFGHIJabcdefghi" },
      { "ABCDEFGHIJ%>本abcdefghijkl",   "ABCDEFGHIJabcdefghi" },
      { "ABCDEFGHIJ%>本abcdefghijklm",  "ABCDEFGHIJabcdefghi" },
      { "ABCDEFGHIJ%>本abcdefghijklmn", "ABCDEFGHIJabcdefghi" },
      // clang-format off
    };

    struct Buffer *buf = buf_pool_get();
    struct Buffer *err = buf_pool_get();
    struct Expando *exp = NULL;
    int rc;

    struct ExpandoRenderData TestRenderData[] = {
      // clang-format off
      { 1, TestCallbacks, NULL, MUTT_FORMAT_NO_FLAGS },
      { -1, NULL, NULL, 0 },
      // clang-format on
    };

    for (int i = 0; i < mutt_array_size(HardTests); i++)
    {
      buf_reset(buf);
      buf_reset(err);

      const char *format = HardTests[i][0];
      const char *expected = HardTests[i][1];
      TEST_CASE(format);

      exp = expando_parse(format, TestFormatDef, err);
      TEST_CHECK(buf_is_empty(err));
      TEST_MSG(buf_string(err));
      rc = node_padding_render_hard(exp->node, TestRenderData, 19, buf);
      TEST_CHECK_NUM_EQ(rc, 19);
      TEST_CHECK_STR_EQ(buf_string(buf), expected);
      expando_free(&exp);
    }

    buf_pool_release(&buf);
    buf_pool_release(&err);
  }

  // int node_padding_render_soft(const struct ExpandoNode *node, const struct ExpandoRenderData *rdata, int max_cols, struct Buffer *buf);
  {
    char *SoftTests[][2] = {
      // clang-format off
      { "%>X",                          "XXXXXXXXXXXXXXXXXXX" },
      { "AAA%>X",                       "AAAXXXXXXXXXXXXXXXX" },
      { "%>XBBB",                       "XXXXXXXXXXXXXXXXBBB" },
      { "AAA%>XBBB",                    "AAAXXXXXXXXXXXXXBBB" },

      { "ABCDEFGHIJKLMNOP%>.",          "ABCDEFGHIJKLMNOP..." },
      { "ABCDEFGHIJKLMNOPQ%>.",         "ABCDEFGHIJKLMNOPQ.." },
      { "ABCDEFGHIJKLMNOPQR%>.",        "ABCDEFGHIJKLMNOPQR." },
      { "ABCDEFGHIJKLMNOPQRS%>.",       "ABCDEFGHIJKLMNOPQRS" },
      { "ABCDEFGHIJKLMNOPQRST%>.",      "ABCDEFGHIJKLMNOPQRS" },
      { "ABCDEFGHIJKLMNOPQRSTU%>.",     "ABCDEFGHIJKLMNOPQRS" },
      { "ABCDEFGHIJKLMNOPQRSTUV%>.",    "ABCDEFGHIJKLMNOPQRS" },

      { "%>.abcdefghijklmnop",          "...abcdefghijklmnop" },
      { "%>.abcdefghijklmnopq",         "..abcdefghijklmnopq" },
      { "%>.abcdefghijklmnopqr",        ".abcdefghijklmnopqr" },
      { "%>.abcdefghijklmnopqrs",       "abcdefghijklmnopqrs" },
      { "%>.abcdefghijklmnopqrst",      "abcdefghijklmnopqrs" },
      { "%>.abcdefghijklmnopqrstu",     "abcdefghijklmnopqrs" },
      { "%>.abcdefghijklmnopqrstuv",    "abcdefghijklmnopqrs" },

      { "ABCDEFGHIJ%>.abcdefg",         "ABCDEFGHIJ..abcdefg" },
      { "ABCDEFGHIJ%>.abcdefgh",        "ABCDEFGHIJ.abcdefgh" },
      { "ABCDEFGHIJ%>.abcdefghi",       "ABCDEFGHIJabcdefghi" },
      { "ABCDEFGHIJ%>.abcdefghij",      "ABCDEFGHIabcdefghij" },
      { "ABCDEFGHIJ%>.abcdefghijk",     "ABCDEFGHabcdefghijk" },
      { "ABCDEFGHIJ%>.abcdefghijkl",    "ABCDEFGabcdefghijkl" },
      { "ABCDEFGHIJ%>.abcdefghijklm",   "ABCDEFabcdefghijklm" },
      { "ABCDEFGHIJ%>.abcdefghijklmn",  "ABCDEabcdefghijklmn" },

      { "%>X",                          "XXXXXXXXXXXXXXXXXXX" },
      { "AAA%>X",                       "AAAXXXXXXXXXXXXXXXX" },
      { "%>XBBB",                       "XXXXXXXXXXXXXXXXBBB" },
      { "AAA%>XBBB",                    "AAAXXXXXXXXXXXXXBBB" },

      { "ABCDEFGHIJKLMNOP%>本",         "ABCDEFGHIJKLMNOP本 " },
      { "ABCDEFGHIJKLMNOPQ%>本",        "ABCDEFGHIJKLMNOPQ本" },
      { "ABCDEFGHIJKLMNOPQR%>本",       "ABCDEFGHIJKLMNOPQR " },
      { "ABCDEFGHIJKLMNOPQRS%>本",      "ABCDEFGHIJKLMNOPQRS" },
      { "ABCDEFGHIJKLMNOPQRST%>本",     "ABCDEFGHIJKLMNOPQRS" },
      { "ABCDEFGHIJKLMNOPQRSTU%>本",    "ABCDEFGHIJKLMNOPQRS" },
      { "ABCDEFGHIJKLMNOPQRSTUV%>本",   "ABCDEFGHIJKLMNOPQRS" },

      { "%>本abcdefghijklmnop",         "本 abcdefghijklmnop" },
      { "%>本abcdefghijklmnopq",        "本abcdefghijklmnopq" },
      { "%>本abcdefghijklmnopqr",       " abcdefghijklmnopqr" },
      { "%>本abcdefghijklmnopqrs",      "abcdefghijklmnopqrs" },
      { "%>本abcdefghijklmnopqrst",     "abcdefghijklmnopqrs" },
      { "%>本abcdefghijklmnopqrstu",    "abcdefghijklmnopqrs" },
      { "%>本abcdefghijklmnopqrstuv",   "abcdefghijklmnopqrs" },

      { "ABCDEFGHIJ%>本abcdefg",        "ABCDEFGHIJ本abcdefg" },
      { "ABCDEFGHIJ%>本abcdefgh",       "ABCDEFGHIJ abcdefgh" },
      { "ABCDEFGHIJ%>本abcdefghi",      "ABCDEFGHIJabcdefghi" },
      { "ABCDEFGHIJ%>本abcdefghij",     "ABCDEFGHIabcdefghij" },
      { "ABCDEFGHIJ%>本abcdefghijk",    "ABCDEFGHabcdefghijk" },
      { "ABCDEFGHIJ%>本abcdefghijkl",   "ABCDEFGabcdefghijkl" },
      { "ABCDEFGHIJ%>本abcdefghijklm",  "ABCDEFabcdefghijklm" },
      { "ABCDEFGHIJ%>本abcdefghijklmn", "ABCDEabcdefghijklmn" },
      // clang-format off
    };

    struct Buffer *buf = buf_pool_get();
    struct Buffer *err = buf_pool_get();
    struct Expando *exp = NULL;
    int rc;

    struct ExpandoRenderData TestRenderData[] = {
      // clang-format off
      { 1, TestCallbacks, NULL, MUTT_FORMAT_NO_FLAGS },
      { -1, NULL, NULL, 0 },
      // clang-format on
    };

    for (int i = 0; i < mutt_array_size(SoftTests); i++)
    {
      buf_reset(buf);
      buf_reset(err);

      const char *format = SoftTests[i][0];
      const char *expected = SoftTests[i][1];
      TEST_CASE(format);

      exp = expando_parse(format, TestFormatDef, err);
      TEST_CHECK(buf_is_empty(err));
      TEST_MSG(buf_string(err));
      rc = node_padding_render_soft(exp->node, TestRenderData, 19, buf);
      TEST_CHECK_NUM_EQ(rc, 19);
      TEST_CHECK_STR_EQ(buf_string(buf), expected);
      expando_free(&exp);
    }

    buf_pool_release(&buf);
    buf_pool_release(&err);
  }
}
