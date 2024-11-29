/**
 * @file
 * Test code for Formatting Numbers
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

struct Test
{
  const char *format;
  const char *zero;
  const char *positive;
  const char *negative;
};

long test_d_num(const struct ExpandoNode *node, void *data, MuttFormatFlags flags)
{
  int num = *(int *) data;
  return num;
}

void test_expando_format_number(void)
{
  static const struct Test tests[] = {
    // clang-format off
    { "%d",            "0",            "42",            "-42"          },
    { "%0d",           "0",            "42",            "-42"          },
    { "%5d",           "    0",        "   42",         "  -42"        },
    { "%05d",          "00000",        "00042",         "-0042"        },
    { "%-5d",          "0    ",        "42   ",         "-42  "        },

    { "%.8d",          "00000000",     "00000042",      "-0000042"     },
    { "%5.8d",         "00000000",     "00000042",      "-0000042"     },
    { "%-5.8d",        "00000000",     "00000042",      "-0000042"     },

    { "%12.8d",        "    00000000", "    00000042",  "    -0000042" },
    { "%-12.8d",       "00000000    ", "00000042    ",  "-0000042    " },

    { "%=12.8d",       "  00000000  ", "  00000042  ",  "  -0000042  " },

    { "%.d",           "",             "42",            "-42"          },
    { "%-d",           "0",            "42",            "-42"          },
    { "%-.8d",         "00000000",     "00000042",      "-0000042"     },
    { "%-.d",          "",             "42",            "-42"          },
    { "%5.d",          "     ",        "   42",         "  -42"        },
    { "%-5.d",         "     ",        "42   ",         "-42  "        },

    { "%08d",          "00000000",     "00000042",      "-0000042"     },
    { "%8d",           "       0",     "      42",      "     -42"     },
    { "%-8d",          "0       ",     "42      ",      "-42     "     },

    { "%-0d",          "0",            "42",            "-42"          },
    { "%-05d",         "0    ",        "42   ",         "-42  "        },
    { "%-08d",         "0       ",     "42      ",      "-42     "     },

    { "%0.8d",         "00000000",     "00000042",      "-0000042"    },
    { "%05.8d",        "00000000",     "00000042",      "-0000042"    },
    { "%05.d",         "     ",        "   42",         "  -42"        },
    { "%0.d",          "",             "42",            "-42"          },

    { "%-0.8d",        "00000000",     "00000042",      "-0000042"    },
    { "%-05.8d",       "00000000",     "00000042",      "-0000042"    },
    { "%-05.d",        "     ",        "42   ",         "-42  "        },
    { "%-0.d",         "",             "42",            "-42"          },

    { "%5.0d",         "     ",         "   42",         "  -42"       },
    { "%.0d",          "",              "42",            "-42"         },
    { "%-5.0d",        "     ",         "42   ",         "-42  "       },
    { "%-.0d",         "",              "42",            "-42"         },

    { "%05.0d",        "     ",         "   42",         "  -42"       },
    { "%0.0d",         "",              "42",            "-42"         },

    { "%-05.0d",       "     ",         "42   ",         "-42  "       },
    { "%-0.0d",        "",              "42",            "-42"         },
    { NULL, NULL, NULL, NULL },
    // clang-format on
  };

  static const struct ExpandoDefinition TestFormatDef[] = {
    // clang-format off
    { "d", NULL, 1, 2, NULL },
    { NULL, NULL, 0, -1, NULL }
    // clang-format on
  };

  static const struct ExpandoRenderCallback TestCallbacks[] = {
    // clang-format off
    { 1, 2, NULL, test_d_num },
    { -1, -1, NULL, NULL },
    // clang-format on
  };

  int rc;
  int num;
  size_t len;
  struct Expando *exp = NULL;
  struct Buffer *buf = buf_pool_get();

  struct ExpandoRenderData TestRenderData[] = {
    // clang-format off
    { 1, TestCallbacks, &num, MUTT_FORMAT_NO_FLAGS },
    { -1, NULL, NULL, 0 },
    // clang-format on
  };

  for (int i = 0; tests[i].format; i++)
  {
    TEST_CASE_("%s", tests[i].format);

    exp = expando_parse(tests[i].format, TestFormatDef, buf);
    TEST_CHECK(exp != NULL);

    buf_reset(buf);
    num = 0;
    len = strlen(tests[i].zero);
    rc = expando_render(exp, TestRenderData, 80, buf);
    TEST_CHECK(rc == len);
    TEST_MSG("rc = %d", rc);
    TEST_CHECK_STR_EQ(buf_string(buf), tests[i].zero);

    buf_reset(buf);
    num = 42;
    len = strlen(tests[i].positive);
    rc = expando_render(exp, TestRenderData, 80, buf);
    TEST_CHECK(rc == len);
    TEST_MSG("rc = %d", rc);
    TEST_CHECK_STR_EQ(buf_string(buf), tests[i].positive);

    buf_reset(buf);
    num = -42;
    len = strlen(tests[i].negative);
    rc = expando_render(exp, TestRenderData, 80, buf);
    TEST_CHECK(rc == len);
    TEST_MSG("rc = %d", rc);
    TEST_CHECK_STR_EQ(buf_string(buf), tests[i].negative);

    expando_free(&exp);
  }

  buf_pool_release(&buf);
}
