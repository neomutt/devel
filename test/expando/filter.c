/**
 * @file
 * Test Expando Filter
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
#include "mutt/lib.h"
#include "email/lib.h"
#include "expando/lib.h"
#include "common.h" // IWYU pragma: keep
#include "test_common.h"

extern char **EnvList;

bool check_for_pipe(struct ExpandoNode *root);
void filter_text(struct Buffer *buf);

static void test_a(const struct ExpandoNode *node, void *data,
                   MuttFormatFlags flags, struct Buffer *buf)
{
  buf_addstr(buf, "apple");
}

void test_expando_filter(void)
{
  // bool check_for_pipe(struct ExpandoNode *root);
  {
    static const struct Mapping tests[] = {
      // clang-format off
      { "|",           true  },
      { "\\|",         false }, // one   backslash
      { "\\\\|",       true  }, // two   backslashes
      { "\\\\\\|",     false }, // three backslashes
      { "\\\\\\\\|",   true  }, // four  backslashes
      { "\\\\\\\\\\|", false }, // five  backslashes
      // clang-format on
    };
    TEST_CHECK(!check_for_pipe(NULL));

    struct ExpandoNode *root = node_new();
    struct ExpandoNode *first = node_new();
    struct ExpandoNode *last = node_new();

    node_add_child(root, first);
    node_add_child(root, last);

    TEST_CHECK(!check_for_pipe(root));

    first->type = ENT_TEXT;
    TEST_CHECK(!check_for_pipe(root));

    last->type = ENT_TEXT;
    TEST_CHECK(!check_for_pipe(root));

    last->text = "";
    TEST_CHECK(!check_for_pipe(root));

    last->text = "hello";
    TEST_CHECK(!check_for_pipe(root));

    for (size_t i = 0; i < mutt_array_size(tests); i++)
    {
      TEST_CASE(tests[i].name);
      last->text = tests[i].name;
      TEST_CHECK(check_for_pipe(root) == tests[i].value);
    }

    last->text = NULL; // we own the string
    node_free(&root);
  }

  // void filter_text(struct Buffer *buf);
  {
    struct Buffer *buf = buf_pool_get();

    filter_text(NULL);
    filter_text(buf);

    // buf_strcpy(buf, "xyz-rst apple|"); // doesn't exist
    // filter_text(buf);

    buf_strcpy(buf, "false|");
    filter_text(buf);

    buf_strcpy(buf, "echo apple|");
    filter_text(buf);

    buf_pool_release(&buf);
  }

  // int expando_filter(const struct Expando *exp, const struct ExpandoRenderCallback *erc, void *data, MuttFormatFlags flags, int max_cols, char **env_list, struct Buffer *buf);
  {
    const struct ExpandoDefinition TestFormatDef[] = {
      // clang-format off
      { "a", "from", ED_ENVELOPE, ED_ENV_FROM, NULL },
      { NULL, NULL, 0, -1, NULL }
      // clang-format on
    };

    const struct ExpandoRenderCallback TestCallbacks[] = {
      // clang-format off
      { ED_ENVELOPE, ED_ENV_FROM, test_a, NULL },
      { -1, -1, NULL, NULL },
      // clang-format on
    };

    struct ExpandoRenderData TestRenderData[] = {
      // clang-format off
      { ED_ENVELOPE, TestCallbacks, NULL, MUTT_FORMAT_NO_FLAGS },
      { -1, NULL, NULL, 0 },
      // clang-format on
    };

    TEST_CHECK(expando_filter(NULL, NULL, 0, NULL, NULL) == 0);

    struct Buffer *err = buf_pool_get();
    struct Buffer *buf = buf_pool_get();
    struct Expando *exp = NULL;
    int rc;

    const char *str = ">%a<";
    exp = expando_parse(str, TestFormatDef, err);
    TEST_CHECK(exp != NULL);
    rc = expando_filter(exp, TestRenderData, -1, EnvList, buf);
    TEST_CHECK_NUM_EQ(rc, 7);
    TEST_MSG("rc = %d", rc);
    TEST_CHECK_STR_EQ(buf_string(buf), ">apple<");
    expando_free(&exp);

    str = "echo '>%a<'|";
    buf_reset(buf);
    exp = expando_parse(str, TestFormatDef, err);
    TEST_CHECK(exp != NULL);
    rc = expando_filter(exp, TestRenderData, -1, EnvList, buf);
    TEST_CHECK_NUM_EQ(rc, 7);
    TEST_MSG("rc = %d", rc);
    TEST_CHECK_STR_EQ(buf_string(buf), ">apple<");
    expando_free(&exp);

    buf_pool_release(&buf);
    buf_pool_release(&err);
  }

  TEST_CHECK(true);
}
