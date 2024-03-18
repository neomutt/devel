/**
 * @file
 * Test code for Formatting Expandos
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
#include <limits.h>
#include "expando/lib.h"
#include "common.h" // IWYU pragma: keep

void test_expando_formatted_expando(void)
{
  static const struct ExpandoDefinition TestFormatDef[] = {
    // clang-format off
    { "X",  "xigua", 1, 1, E_TYPE_STRING, NULL },
    { NULL, NULL, 0, -1, -1, NULL }
    // clang-format on
  };
  const char *input = "%X %8X %-8X %08X %.8X %8.8X %-8.8X %=8X";
  struct ExpandoParseError error = { 0 };
  struct ExpandoNode *root = NULL;

  node_tree_parse(&root, input, TestFormatDef, &error);

  TEST_CHECK(error.position == NULL);
  check_node_expando(get_nth_node(root, 0), "X", NULL);
  check_node_test(get_nth_node(root, 1), " ");

  {
    struct ExpandoFormat fmt = { 0 };
    fmt.min_cols = 8;
    fmt.max_cols = INT_MAX;
    fmt.justification = JUSTIFY_RIGHT;
    fmt.leader = ' ';
    check_node_expando(get_nth_node(root, 2), "X", &fmt);
    check_node_test(get_nth_node(root, 3), " ");
  }

  {
    struct ExpandoFormat fmt = { 0 };
    fmt.min_cols = 8;
    fmt.max_cols = INT_MAX;
    fmt.justification = JUSTIFY_LEFT;
    fmt.leader = ' ';
    check_node_expando(get_nth_node(root, 4), "X", &fmt);
    check_node_test(get_nth_node(root, 5), " ");
  }

  {
    struct ExpandoFormat fmt = { 0 };
    fmt.min_cols = 8;
    fmt.max_cols = INT_MAX;
    fmt.justification = JUSTIFY_RIGHT;
    fmt.leader = '0';
    check_node_expando(get_nth_node(root, 6), "X", &fmt);
    check_node_test(get_nth_node(root, 7), " ");
  }

  {
    struct ExpandoFormat fmt = { 0 };
    fmt.min_cols = 0;
    fmt.max_cols = 8;
    fmt.justification = JUSTIFY_RIGHT;
    fmt.leader = ' ';
    check_node_expando(get_nth_node(root, 8), "X", &fmt);
    check_node_test(get_nth_node(root, 9), " ");
  }

  {
    struct ExpandoFormat fmt = { 0 };
    fmt.min_cols = 8;
    fmt.max_cols = 8;
    fmt.justification = JUSTIFY_RIGHT;
    fmt.leader = ' ';
    check_node_expando(get_nth_node(root, 10), "X", &fmt);
    check_node_test(get_nth_node(root, 11), " ");
  }

  {
    struct ExpandoFormat fmt = { 0 };
    fmt.min_cols = 8;
    fmt.max_cols = 8;
    fmt.justification = JUSTIFY_LEFT;
    fmt.leader = ' ';
    check_node_expando(get_nth_node(root, 12), "X", &fmt);
    check_node_test(get_nth_node(root, 13), " ");
  }

  {
    struct ExpandoFormat fmt = { 0 };
    fmt.min_cols = 8;
    fmt.max_cols = INT_MAX;
    fmt.justification = JUSTIFY_CENTER;
    fmt.leader = ' ';
    check_node_expando(get_nth_node(root, 14), "X", &fmt);
  }

  node_tree_free(&root);
}
