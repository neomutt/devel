/**
 * @file
 * Test Expando Expando
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
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "mutt/lib.h"
#include "color/lib.h"
#include "expando/lib.h"
#include "common.h" // IWYU pragma: keep
#include "mutt_thread.h"
#include "test_common.h"

struct NodeExpandoPrivate *node_expando_private_new(void);
void node_expando_private_free(void **ptr);
void add_color(struct Buffer *buf, enum ColorId cid);
struct ExpandoNode *node_expando_parse(const char *str, const struct ExpandoDefinition *defs,
                                       ExpandoParserFlags flags, const char **parsed_until,
                                       struct ExpandoParseError *err);
struct ExpandoFormat *parse_format(const char *str, const char **parsed_until,
                                   struct ExpandoParseError *err);

static long test_y_num(const struct ExpandoNode *node, void *data, MuttFormatFlags flags)
{
  return 42;
}

static void test_y(const struct ExpandoNode *node, void *data,
                   MuttFormatFlags flags, struct Buffer *buf)
{
  buf_strcpy(buf, "HELLO");
}

static long test_n_num(const struct ExpandoNode *node, void *data, MuttFormatFlags flags)
{
  return 0;
}

static void test_n(const struct ExpandoNode *node, void *data,
                   MuttFormatFlags flags, struct Buffer *buf)
{
}

static struct ExpandoNode *parse_test(const char *str, struct ExpandoFormat *fmt,
                                      int did, int uid, ExpandoParserFlags flags,
                                      const char **parsed_until,
                                      struct ExpandoParseError *err)
{
  *parsed_until = str + 1;
  return node_expando_new(fmt, did, uid);
}

void test_expando_node_expando(void)
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
    { 1, 5, NULL,   test_n_num },
    { 1, 6, NULL,   NULL },
    { -1, -1, NULL, NULL },
    // clang-format on
  };

  // struct NodeExpandoPrivate *node_expando_private_new(void);
  // void node_expando_private_free(void **ptr);
  {
    struct NodeExpandoPrivate *priv = node_expando_private_new();
    TEST_CHECK(priv != NULL);
    node_expando_private_free((void **) &priv);
    node_expando_private_free(NULL);
  }

  // struct ExpandoNode *node_expando_new(const char *start, const char *end, struct ExpandoFormat *fmt, int did, int uid);
  {
    struct ExpandoNode *node = node_expando_new(NULL, 1, 2);
    TEST_CHECK(node != NULL);
    node_free(&node);
  }

  // void node_expando_set_color(const struct ExpandoNode *node, int cid);
  // void node_expando_set_has_tree(const struct ExpandoNode *node, bool has_tree);
  {
    struct ExpandoNode *node = node_expando_new(NULL, 1, 2);
    TEST_CHECK(node != NULL);

    node_expando_set_color(NULL, 42);
    node_expando_set_has_tree(NULL, true);

    node_expando_set_color(node, 42);
    node_expando_set_has_tree(node, true);

    node_free(&node);
  }

  // void add_color(struct Buffer *buf, enum ColorId cid);
  {
    struct Buffer *buf = buf_pool_get();
    add_color(buf, 42);
    TEST_CHECK(!buf_is_empty(buf));
    buf_pool_release(&buf);
  }

  // struct ExpandoNode *node_expando_parse(const char *str, const struct ExpandoDefinition *defs, ExpandoParserFlags flags, const char **parsed_until, struct ExpandoParseError *err);
  {
    const char *str = "%a";
    const char *parsed_until = NULL;
    struct ExpandoParseError err = { 0 };

    struct ExpandoNode *node = node_expando_parse(str, TestFormatDef, EP_NO_FLAGS,
                                                  &parsed_until, &err);
    TEST_CHECK(node != NULL);
    node_free(&node);

    str = "%c";
    node = node_expando_parse(str, TestFormatDef, EP_NO_FLAGS, &parsed_until, &err);
    TEST_CHECK(node != NULL);
    node_free(&node);

    str = "%Q";
    node = node_expando_parse(str, TestFormatDef, EP_NO_FLAGS, &parsed_until, &err);
    TEST_CHECK(node == NULL);

    str = "%9999Q";
    node = node_expando_parse(str, TestFormatDef, EP_NO_FLAGS, &parsed_until, &err);
    TEST_CHECK(node == NULL);
  }

  // struct ExpandoNode *node_expando_parse_enclosure(const char *str, int did, int uid, char terminator, struct ExpandoFormat *fmt, const char **parsed_until, struct ExpandoParseError *err);
  {
    struct ExpandoParseError err = { 0 };
    struct ExpandoNode *node = NULL;
    const char *str = NULL;
    const char *parsed_until = NULL;
    const char terminator = ']';

    str = "[apple]";
    node = node_expando_parse_enclosure(str, 1, 2, terminator, NULL, &parsed_until, &err);
    TEST_CHECK(node != NULL);
    TEST_CHECK_STR_EQ(node->text, "apple");
    node_free(&node);

    str = "[ap\\]ple]";
    node = node_expando_parse_enclosure(str, 1, 2, terminator, NULL, &parsed_until, &err);
    TEST_CHECK(node != NULL);
    TEST_CHECK_STR_EQ(node->text, "ap]ple");
    node_free(&node);

    str = "[apple";
    node = node_expando_parse_enclosure(str, 1, 2, terminator, NULL, &parsed_until, &err);
    TEST_CHECK(node == NULL);
  }

  // int node_expando_render(const struct ExpandoNode *node, const struct ExpandoRenderCallback *rdata, struct Buffer *buf, int max_cols, void *data, MuttFormatFlags flags);
  {
    struct ExpandoParseError err = { 0 };
    struct Buffer *buf = buf_pool_get();
    const char *str = NULL;
    const char *parsed_until = NULL;
    struct ExpandoNode *node = NULL;
    int rc = 0;

    struct ExpandoRenderData TestRenderData[] = {
      // clang-format off
      { 1, TestCallbacks, NULL, MUTT_FORMAT_NO_FLAGS },
      { -1, NULL, NULL, 0 },
      // clang-format on
    };

    str = "%a";
    parsed_until = NULL;
    buf_reset(buf);
    node = node_expando_parse(str, TestFormatDef, EP_NO_FLAGS, &parsed_until, &err);
    TEST_CHECK(node != NULL);
    rc = node_expando_render(node, TestRenderData, 99, buf);
    TEST_CHECK_NUM_EQ(rc, 5);
    TEST_CHECK_STR_EQ(buf_string(buf), "HELLO");
    node_free(&node);

    str = "%20_a";
    parsed_until = NULL;
    buf_reset(buf);
    node = node_expando_parse(str, TestFormatDef, EP_NO_FLAGS, &parsed_until, &err);
    TEST_CHECK(node != NULL);
    rc = node_expando_render(node, TestRenderData, 99, buf);
    TEST_CHECK_NUM_EQ(rc, 20);
    TEST_CHECK_STR_EQ(buf_string(buf), "               hello");
    node_free(&node);

    str = "%_d";
    parsed_until = NULL;
    buf_reset(buf);
    node = node_expando_parse(str, TestFormatDef, EP_NO_FLAGS, &parsed_until, &err);
    TEST_CHECK(node != NULL);
    node_expando_set_color(node, 42);
    rc = node_expando_render(node, TestRenderData, 99, buf);
    TEST_CHECK_NUM_EQ(rc, 1);
    TEST_MSG("rc = %d", rc);
    node_free(&node);

    str = "%d";
    parsed_until = NULL;
    buf_reset(buf);
    node = node_expando_parse(str, TestFormatDef, EP_NO_FLAGS, &parsed_until, &err);
    TEST_CHECK(node != NULL);
    node_expando_set_color(node, 42);
    rc = node_expando_render(node, TestRenderData, 99, buf);
    TEST_CHECK_NUM_EQ(rc, 1);
    TEST_MSG("rc = %d", rc);
    node_free(&node);

    buf_pool_release(&buf);
  }

  // int format_string(struct Buffer *buf, int min_cols, int max_cols, enum FormatJustify justify, char pad_char, const char *str, size_t n, bool arboreal);
  {
    struct Buffer *buf = buf_pool_get();
    char str[32] = { 0 };
    size_t len = 0;
    int rc;

    strncpy(str, "\xe2\x28\xa1", sizeof(str)); // Illegal utf-8 sequence
    len = strlen(str);
    rc = format_string(buf, 0, 20, JUSTIFY_LEFT, '.', str, len, true);
    TEST_CHECK_NUM_EQ(rc, 3);

    memset(str, 0, sizeof(str));
    str[0] = MUTT_TREE_HLINE; // Tree chars
    str[1] = MUTT_TREE_VLINE;
    str[2] = MUTT_SPECIAL_INDEX; // Colour specifier
    str[3] = 42;
    len = strlen(str);
    rc = format_string(buf, 0, 20, JUSTIFY_LEFT, '.', str, len, true);
    TEST_CHECK_NUM_EQ(rc, 2);

    memset(str, 0, sizeof(str));
    str[0] = 15; // Unprintable character
    len = strlen(str);
    rc = format_string(buf, 0, 20, JUSTIFY_LEFT, '.', str, len, true);
    TEST_CHECK_NUM_EQ(rc, 1);

    buf_pool_release(&buf);
  }
}
