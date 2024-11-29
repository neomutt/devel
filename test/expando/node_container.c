/**
 * @file
 * Test Container Expando
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

void expando_serialise(const struct Expando *exp, struct Buffer *buf);
struct ExpandoFormat *parse_format(const char *str, const char **parsed_until,
                                   struct ExpandoParseError *err);
void node_container_collapse(struct ExpandoNode **ptr);

void test_one(const struct ExpandoNode *node, void *data, MuttFormatFlags flags,
              struct Buffer *buf)
{
  buf_addstr(buf, "ONE");
  buf_addch(buf, 'a' - 1 + node->uid);
  buf_addch(buf, 'a' - 1 + node->uid);
  buf_addch(buf, 'a' - 1 + node->uid);
}

void test_two(const struct ExpandoNode *node, void *data, MuttFormatFlags flags,
              struct Buffer *buf)
{
  buf_addstr(buf, "TWO");
  buf_addch(buf, 'a' - 1 + node->uid);
  buf_addch(buf, 'a' - 1 + node->uid);
  buf_addch(buf, 'a' - 1 + node->uid);
}

void test_three(const struct ExpandoNode *node, void *data,
                MuttFormatFlags flags, struct Buffer *buf)
{
  buf_addstr(buf, "THREE");
  buf_addch(buf, 'a' - 1 + node->uid);
  buf_addch(buf, 'a' - 1 + node->uid);
  buf_addch(buf, 'a' - 1 + node->uid);
}

struct ExpandoNode *make_children(char ch)
{
  struct ExpandoNode *cont = node_container_new();
  struct ExpandoNode *n1 = node_expando_new(NULL, (ch - 'a' + 1) * 10, 1);
  struct ExpandoNode *n2 = node_expando_new(NULL, (ch - 'a' + 1) * 10, 2);
  struct ExpandoNode *n3 = node_expando_new(NULL, (ch - 'a' + 1) * 10, 3);

  node_add_child(cont, n1);
  node_add_child(cont, n2);
  node_add_child(cont, n3);

  return cont;
}

void test_expando_node_container(void)
{
  const struct ExpandoRenderCallback TestCallbacks1[] = {
    // clang-format off
    { 10, 1, test_one, NULL },
    { 10, 2, test_one, NULL },
    { 10, 3, test_one, NULL },
    { -1, -1, NULL, NULL },
    // clang-format on
  };

  const struct ExpandoRenderCallback TestCallbacks2[] = {
    // clang-format off
    { 20, 1, test_two, NULL },
    { 20, 2, test_two, NULL },
    { 20, 3, test_two, NULL },
    { -1, -1, NULL, NULL },
    // clang-format on
  };

  const struct ExpandoRenderCallback TestCallbacks3[] = {
    // clang-format off
    { 30, 1, test_three, NULL },
    { 30, 2, test_three, NULL },
    { 30, 3, test_three, NULL },
    { -1, -1, NULL, NULL },
    // clang-format on
  };

  // struct ExpandoNode *node_container_new(void);
  {
    struct ExpandoNode *node = node_container_new();
    TEST_CHECK(node != NULL);
    node_free(&node);
  }

  // int node_container_render(const struct ExpandoNode *node, const struct ExpandoRenderData *rdata, int max_cols, struct Buffer *buf);
  {
    static const struct Mapping tests[] = {
      // clang-format off
      { "ONEaaaONEbbbONEcccTW", 25 },
      { "ONEaaaONEbbbONE", 15 },
      { "ONEaaaONEb", 10 },
      { "", 0 },
      // clang-format on
    };

    struct ExpandoParseError err = { 0 };
    const char *fmt_str = "-15.20x";
    struct ExpandoNode *cont = node_container_new();
    const char *parsed_until = NULL;
    cont->format = parse_format(fmt_str, &parsed_until, &err);

    ARRAY_ADD(&cont->children, make_children('a'));
    ARRAY_ADD(&cont->children, make_children('b'));
    ARRAY_ADD(&cont->children, make_children('c'));

    struct Buffer *buf = buf_pool_get();
    int rc;

    struct ExpandoRenderData TestRenderData[] = {
      // clang-format off
      { 10, TestCallbacks1, NULL, MUTT_FORMAT_NO_FLAGS },
      { 20, TestCallbacks2, NULL, MUTT_FORMAT_NO_FLAGS },
      { 30, TestCallbacks3, NULL, MUTT_FORMAT_NO_FLAGS },
      { -1, NULL, NULL, 0 },
      // clang-format on
    };

    for (size_t i = 0; i < mutt_array_size(tests); i++)
    {
      TEST_CASE_("%d", tests[i].value);
      buf_reset(buf);
      rc = node_render(cont, TestRenderData, tests[i].value, buf);
      TEST_CHECK(rc == strlen(tests[i].name));
      TEST_CHECK_STR_EQ(buf_string(buf), tests[i].name);
    }

    FREE(&cont->format);
    buf_reset(buf);
    rc = node_render(cont, TestRenderData, 50, buf);
    TEST_CHECK_NUM_EQ(rc, 50);
    TEST_CHECK_STR_EQ(buf_string(buf), "ONEaaaONEbbbONEcccTWOaaaTWObbbTWOcccTHREEaaaTHREEb");

    fmt_str = "-15.20_x";
    cont->format = parse_format(fmt_str, &parsed_until, &err);
    buf_reset(buf);
    rc = node_render(cont, TestRenderData, 20, buf);
    TEST_CHECK_NUM_EQ(rc, 20);
    TEST_CHECK_STR_EQ(buf_string(buf), "oneaaaonebbboneccctw");

    FREE(&cont->format);

    node_free(&cont);
    buf_pool_release(&buf);
  }

  // void node_container_collapse(struct ExpandoNode **ptr);
  {
    struct ExpandoNode *node = NULL;
    node_container_collapse(NULL);
    node_container_collapse(&node);

    node = node_new();
    node->type = ENT_EXPANDO;
    node_container_collapse(&node);
    node_free(&node);
  }

  {
    struct ExpandoNode *cont = node_container_new();
    node_container_collapse(&cont);
    TEST_CHECK(cont == NULL);
  }

  {
    struct ExpandoNode *cont = node_container_new();
    struct ExpandoNode *child = node_new();
    node_add_child(cont, child);
    node_container_collapse(&cont);
    TEST_CHECK(cont == child);
    node_free(&cont);
  }

  {
    struct ExpandoNode *cont = node_container_new();
    node_add_child(cont, node_new());
    node_add_child(cont, node_new());
    node_add_child(cont, node_new());
    node_container_collapse(&cont);
    TEST_CHECK(cont != NULL);
    node_free(&cont);
  }

  // void node_container_collapse_all(struct ExpandoNode **ptr);
  {
    struct ExpandoNode *node = NULL;
    node_container_collapse_all(NULL);
    node_container_collapse_all(&node);

    node = node_new();
    node_container_collapse_all(&node);
    node_free(&node);
  }

  {
    struct Expando exp = { 0 };
    struct ExpandoNode *cont1 = node_container_new();
    struct ExpandoNode *cont2 = node_container_new();
    struct ExpandoNode *cont3 = node_container_new();
    struct ExpandoNode *node = node_expando_new(NULL, ED_EMAIL, 1);
    struct Buffer *buf = buf_pool_get();

    node_add_child(cont1, cont2);
    node_add_child(cont2, cont3);
    node_add_child(cont3, node);

    node_container_collapse_all(&cont1);
    TEST_CHECK(cont1 == node);

    exp.node = cont1;
    expando_serialise(&exp, buf);
    TEST_CHECK_STR_EQ(buf_string(buf), "<EXP:(EMAIL,ATTACHMENT_COUNT)>");
    node_free(&cont1);

    buf_pool_release(&buf);
  }

  {
    struct ExpandoNode *cont1 = node_container_new();
    struct ExpandoNode *cont2 = node_container_new();
    struct ExpandoNode *cont3 = node_container_new();
    struct ExpandoNode *cont4 = node_container_new();

    node_add_child(cont1, cont2);
    node_add_child(cont1, cont3);
    node_add_child(cont1, cont4);

    node_container_collapse_all(&cont1);
    TEST_CHECK(cont1 == NULL);
  }
}
