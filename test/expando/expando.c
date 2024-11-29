/**
 * @file
 * Test Expando
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
#include "email/lib.h"
#include "expando/lib.h"
#include "common.h" // IWYU pragma: keep
#include "test_common.h"

static void index_a(const struct ExpandoNode *node, void *data,
                    MuttFormatFlags flags, struct Buffer *buf)
{
  buf_addstr(buf, "apple");
}

void test_expando_expando(void)
{
  // void expando_free(struct Expando **ptr);
  // struct Expando *expando_new(const char *format);
  {
    struct Expando *exp = expando_new(NULL);
    TEST_CHECK(exp != NULL);
    expando_free(&exp);

    exp = expando_new("apple");
    TEST_CHECK(exp != NULL);
    expando_free(&exp);

    expando_free(NULL);
  }

  // bool expando_equal(const struct Expando *a, const struct Expando *b);
  {
    struct Expando *exp_a1 = expando_new("apple");
    TEST_CHECK(exp_a1 != NULL);
    struct Expando *exp_a2 = expando_new("apple");
    TEST_CHECK(exp_a2 != NULL);
    struct Expando *exp_b1 = expando_new("banana");
    TEST_CHECK(exp_b1 != NULL);

    TEST_CHECK(expando_equal(exp_a1, exp_a2));
    TEST_CHECK(!expando_equal(exp_a2, exp_b1));

    TEST_CHECK(expando_equal(NULL, NULL));
    TEST_CHECK(!expando_equal(exp_a1, NULL));
    TEST_CHECK(!expando_equal(NULL, exp_a2));

    expando_free(&exp_a1);
    expando_free(&exp_a2);
    expando_free(&exp_b1);
  }

  // struct Expando *expando_parse(const char *str, const struct ExpandoDefinition *defs, struct Buffer *err);
  {
    const struct ExpandoDefinition TestFormatDef[] = {
      // clang-format off
      { "a", "from", ED_ENVELOPE, ED_ENV_FROM, NULL },
      { NULL, NULL, 0, -1, NULL }
      // clang-format on
    };
    const char *str_good = "%a";
    const char *str_bad = "%z";

    struct Buffer *err = buf_pool_get();
    struct Expando *exp = NULL;

    exp = expando_parse(NULL, TestFormatDef, err);
    TEST_CHECK(exp == NULL);
    exp = expando_parse(str_good, NULL, err);
    TEST_CHECK(exp == NULL);

    exp = expando_parse(str_bad, TestFormatDef, err);
    TEST_CHECK(exp == NULL);

    exp = expando_parse(str_good, TestFormatDef, err);
    TEST_CHECK(exp != NULL);

    buf_pool_release(&err);
    expando_free(&exp);
  }

  // int expando_render(const struct Expando *exp, const struct ExpandoRenderCallback *rdata, void *data, MuttFormatFlags flags, int cols, struct Buffer *buf);
  {
    const struct ExpandoDefinition TestFormatDef[] = {
      // clang-format off
      { "a", "from", ED_ENVELOPE, ED_ENV_FROM, NULL },
      { NULL, NULL, 0, -1, NULL }
      // clang-format on
    };

    const struct ExpandoRenderCallback TestCallbacks[] = {
      // clang-format off
      { ED_ENVELOPE, ED_ENV_FROM, index_a, NULL },
      { -1, -1, NULL, NULL },
      // clang-format on
    };

    struct ExpandoRenderData TestRenderData[] = {
      // clang-format off
      { ED_ENVELOPE, TestCallbacks, NULL, MUTT_FORMAT_NO_FLAGS },
      { -1, NULL, NULL, 0 },
      // clang-format on
    };

    {
      const char *str = "%a";

      struct Buffer *err = buf_pool_get();
      struct Expando *exp = NULL;

      exp = expando_parse(str, TestFormatDef, err);
      TEST_CHECK(exp != NULL);

      int rc;

      struct Buffer *buf = buf_pool_get();

      rc = expando_render(NULL, TestRenderData, 80, buf);
      TEST_CHECK_NUM_EQ(rc, 0);

      rc = expando_render(exp, TestRenderData, -1, buf);
      TEST_CHECK_NUM_EQ(rc, 5);

      buf_pool_release(&buf);
      buf_pool_release(&err);
      expando_free(&exp);
    }

    {
      const char *str = "%=30.10_<a?BBB&CCC>";

      struct Buffer *err = buf_pool_get();
      struct Expando *exp = NULL;

      exp = expando_parse(str, TestFormatDef, err);
      TEST_CHECK(exp != NULL);

      int rc;

      struct Buffer *buf = buf_pool_get();

      rc = expando_render(exp, TestRenderData, -1, buf);
      TEST_CHECK_NUM_EQ(rc, 30);
      TEST_CHECK_STR_EQ(buf_string(buf), "             bbb              ");

      buf_pool_release(&buf);
      buf_pool_release(&err);
      expando_free(&exp);
    }

    {
      const char *str = "%=30<a?BBB&CCC>";

      struct Buffer *err = buf_pool_get();
      struct Expando *exp = NULL;

      exp = expando_parse(str, TestFormatDef, err);
      TEST_CHECK(exp != NULL);

      int rc;

      struct Buffer *buf = buf_pool_get();

      rc = expando_render(exp, TestRenderData, -1, buf);
      TEST_CHECK_NUM_EQ(rc, 30);
      TEST_CHECK_STR_EQ(buf_string(buf), "             BBB              ");

      buf_pool_release(&buf);
      buf_pool_release(&err);
      expando_free(&exp);
    }

    {
      const char *str = "%.10<a?BBB&CCC>";

      struct Buffer *err = buf_pool_get();
      struct Expando *exp = NULL;

      exp = expando_parse(str, TestFormatDef, err);
      TEST_CHECK(exp != NULL);

      int rc;

      struct Buffer *buf = buf_pool_get();

      rc = expando_render(exp, TestRenderData, -1, buf);
      TEST_CHECK_NUM_EQ(rc, 10);
      TEST_CHECK_STR_EQ(buf_string(buf), "       BBB");

      buf_pool_release(&buf);
      buf_pool_release(&err);
      expando_free(&exp);
    }

    {
      const char *str = "%a %a %a %a %-10.10a";

      struct Buffer *err = buf_pool_get();
      struct Expando *exp = NULL;

      exp = expando_parse(str, TestFormatDef, err);
      TEST_CHECK(exp != NULL);

      struct Buffer *buf = buf_pool_get();

      for (int width = 40; width >= 0; width--)
      {
        TEST_CASE_("%d", width);
        buf_reset(buf);
        int expected = MIN(34, width);

        int rc = expando_render(exp, TestRenderData, width, buf);
        TEST_CHECK(rc == expected);
        TEST_MSG("Actual:   %d", rc);
        TEST_MSG("Expected: %d", expected);
        TEST_MSG(">>%s<<", buf_string(buf));
      }

      expando_free(&exp);
      buf_pool_release(&buf);
      buf_pool_release(&err);
    }
  }
}
