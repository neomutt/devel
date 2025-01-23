/**
 * @file
 * Test code for the Expando object
 *
 * @authors
 * Copyright (C) 2024-2025 Richard Russon <rich@flatcap.org>
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
#include <stdint.h>
#include <stdio.h>
#include "mutt/lib.h"
#include "config/lib.h"
#include "core/lib.h"
#include "expando/lib.h"
#include "common.h" // IWYU pragma: keep
#include "test_common.h"

extern bool dont_fail;

int validator_fail(const struct ConfigDef *cdef, intptr_t value, struct Buffer *result);
int validator_warn(const struct ConfigDef *cdef, intptr_t value, struct Buffer *result);
int validator_succeed(const struct ConfigDef *cdef, intptr_t value, struct Buffer *result);
int log_observer(struct NotifyCallback *nc);
void set_list(const struct ConfigSet *cs);
void log_line(const char *fn);
void short_line(void);
int cs_str_string_get(const struct ConfigSet *cs, const char *name, struct Buffer *result);
intptr_t cs_str_native_get(const struct ConfigSet *cs, const char *name, struct Buffer *err);
int cs_str_string_plus_equals(const struct ConfigSet *cs, const char *name,
                              const char *value, struct Buffer *err);

static struct ExpandoDefinition TestFormatDef[] = {
  // clang-format off
  { "a", "aardvark", 1, 100, NULL },
  { "b", "badger",   1, 101, NULL },
  { "c", "cat",      1, 102, NULL },
  { NULL, NULL, 0, -1, NULL }
  // clang-format on
};

// clang-format off
static struct ConfigDef Vars[] = {
  { "Apple",      DT_EXPANDO,              IP "apple",      IP &TestFormatDef, NULL,              }, /* test_initial_values */
  { "Banana",     DT_EXPANDO,              IP "banana",     IP &TestFormatDef, NULL,              },
  { "Cherry",     DT_EXPANDO,              IP "cherry",     IP &TestFormatDef, NULL,              },
  { "Damson",     DT_EXPANDO,              0,               IP &TestFormatDef, NULL,              }, /* test_string_set */
  { "Elderberry", DT_EXPANDO,              IP "elderberry", IP &TestFormatDef, NULL,              },
  { "Fig",        DT_EXPANDO|D_NOT_EMPTY,  IP "fig",        IP &TestFormatDef, NULL,              },
  { "Guava",      DT_EXPANDO,              0,               IP &TestFormatDef, NULL,              }, /* test_string_get */
  { "Hawthorn",   DT_EXPANDO,              IP "hawthorn",   IP &TestFormatDef, NULL,              },
  { "Ilama",      DT_EXPANDO,              0,               IP &TestFormatDef, NULL,              },
  { "Jackfruit",  DT_EXPANDO,              0,               IP &TestFormatDef, NULL,              }, /* test_native_set */
  { "Kumquat",    DT_EXPANDO,              IP "kumquat",    IP &TestFormatDef, NULL,              },
  { "Lemon",      DT_EXPANDO|D_NOT_EMPTY,  IP "lemon",      IP &TestFormatDef, NULL,              },
  { "Mango",      DT_EXPANDO,              0,               IP &TestFormatDef, NULL,              }, /* test_native_get */
  { "Nectarine",  DT_EXPANDO,              IP "nectarine",  IP &TestFormatDef, NULL,              }, /* test_reset */
  { "Olive",      DT_EXPANDO,              IP "olive",      IP &TestFormatDef, validator_fail,    },
  { "Papaya",     DT_EXPANDO,              IP "papaya",     IP &TestFormatDef, validator_succeed, }, /* test_validator */
  { "Quince",     DT_EXPANDO,              IP "quince",     IP &TestFormatDef, validator_warn,    },
  { "Raspberry",  DT_EXPANDO,              IP "raspberry",  IP &TestFormatDef, validator_fail,    },
  { "Strawberry", DT_EXPANDO,              0,               IP &TestFormatDef, NULL,              }, /* test_inherit */
  { "Tangerine",  DT_EXPANDO,              IP "tangerine",  IP &TestFormatDef, NULL,              },
  { "Wolfberry",  DT_EXPANDO|D_ON_STARTUP, IP "wolfberry",  IP &TestFormatDef, NULL,              }, /* startup */
  { NULL },
};
// clang-format on

static bool test_initial_values(struct ConfigSubset *sub, struct Buffer *err)
{
  log_line(__func__);
  struct ConfigSet *cs = sub->cs;

  const struct Expando *VarApple = cs_subset_expando(sub, "Apple");
  const struct Expando *VarBanana = cs_subset_expando(sub, "Banana");

  TEST_MSG("Apple = %s", VarApple->string);
  TEST_MSG("Banana = %s", VarBanana->string);

  if (!TEST_CHECK_STR_EQ(VarApple->string, "apple"))
  {
    TEST_MSG("Error: initial values were wrong");
    return false;
  }

  if (!TEST_CHECK_STR_EQ(VarBanana->string, "banana"))
  {
    TEST_MSG("Error: initial values were wrong");
    return false;
  }

  cs_str_string_set(cs, "Apple", "car", err);
  cs_str_string_set(cs, "Banana", NULL, err);

  VarApple = cs_subset_expando(sub, "Apple");
  VarBanana = cs_subset_expando(sub, "Banana");

  struct Buffer *value = buf_pool_get();

  int rc;

  buf_reset(value);
  rc = cs_str_initial_get(cs, "Apple", value);
  if (!TEST_CHECK_NUM_EQ(CSR_RESULT(rc), CSR_SUCCESS))
  {
    TEST_MSG("%s", buf_string(value));
    return false;
  }

  VarApple = cs_subset_expando(sub, "Apple");
  if (!TEST_CHECK_STR_EQ(buf_string(value), "apple"))
  {
    TEST_MSG("Apple's initial value is wrong: '%s'", buf_string(value));
    return false;
  }
  TEST_MSG("Apple = '%s'", VarApple);
  TEST_MSG("Apple's initial value is '%s'", buf_string(value));

  buf_reset(value);
  rc = cs_str_initial_get(cs, "Banana", value);
  if (!TEST_CHECK_NUM_EQ(CSR_RESULT(rc), CSR_SUCCESS))
  {
    TEST_MSG("%s", buf_string(value));
    return false;
  }

  VarBanana = cs_subset_expando(sub, "Banana");
  if (!TEST_CHECK_STR_EQ(buf_string(value), "banana"))
  {
    TEST_MSG("Banana's initial value is wrong: '%s'", buf_string(value));
    return false;
  }
  TEST_MSG("Banana = '%s'", VarBanana);
  TEST_MSG("Banana's initial value is '%s'", buf_string(value));

  buf_reset(value);
  rc = cs_str_initial_set(cs, "Cherry", "train", value);
  if (!TEST_CHECK_NUM_EQ(CSR_RESULT(rc), CSR_SUCCESS))
  {
    TEST_MSG("%s", buf_string(value));
    return false;
  }

  buf_reset(value);
  rc = cs_str_initial_set(cs, "Cherry", "plane", value);
  if (!TEST_CHECK_NUM_EQ(CSR_RESULT(rc), CSR_SUCCESS))
  {
    TEST_MSG("%s", buf_string(value));
    return false;
  }

  buf_reset(value);
  rc = cs_str_initial_get(cs, "Cherry", value);
  if (!TEST_CHECK_NUM_EQ(CSR_RESULT(rc), CSR_SUCCESS))
  {
    TEST_MSG("%s", buf_string(value));
    return false;
  }

  const struct Expando *VarCherry = cs_subset_expando(sub, "Cherry");
  TEST_MSG("Cherry = '%s'", VarCherry->string);
  TEST_MSG("Cherry's initial value is '%s'", buf_string(value));

  buf_pool_release(&value);
  log_line(__func__);
  return true;
}

static bool test_string_set(struct ConfigSubset *sub, struct Buffer *err)
{
  log_line(__func__);
  struct ConfigSet *cs = sub->cs;

  const char *valid[] = { "hello", "world", "world", "", NULL };
  const char *name = "Damson";

  int rc;
  for (unsigned int i = 0; i < mutt_array_size(valid); i++)
  {
    buf_reset(err);
    rc = cs_str_string_set(cs, name, valid[i], err);
    if (!TEST_CHECK_NUM_EQ(CSR_RESULT(rc), CSR_SUCCESS))
    {
      TEST_MSG("%s", buf_string(err));
      return false;
    }

    if (rc & CSR_SUC_NO_CHANGE)
    {
      TEST_MSG("Value of %s wasn't changed", name);
      continue;
    }

    const struct Expando *VarDamson = cs_subset_expando(sub, "Damson");
    const char *str = VarDamson ? NONULL(VarDamson->string) : "";
    if (!TEST_CHECK_STR_EQ(str, valid[i]))
    {
      TEST_MSG("Value of %s wasn't changed", name);
      return false;
    }
    TEST_MSG("%s = '%s', set by '%s'", name, str, NONULL(valid[i]));
    short_line();
  }

  name = "Fig";
  buf_reset(err);
  rc = cs_str_string_set(cs, name, "", err);
  if (TEST_CHECK(CSR_RESULT(rc) != CSR_SUCCESS))
  {
    TEST_MSG("Expected error: %s", buf_string(err));
  }
  else
  {
    TEST_MSG("%s", buf_string(err));
    return false;
  }

  name = "Elderberry";
  for (unsigned int i = 0; i < mutt_array_size(valid); i++)
  {
    short_line();
    buf_reset(err);
    rc = cs_str_string_set(cs, name, valid[i], err);
    if (!TEST_CHECK_NUM_EQ(CSR_RESULT(rc), CSR_SUCCESS))
    {
      TEST_MSG("%s", buf_string(err));
      return false;
    }

    if (rc & CSR_SUC_NO_CHANGE)
    {
      TEST_MSG("Value of %s wasn't changed", name);
      continue;
    }

    const struct Expando *VarElderberry = cs_subset_expando(sub, "Elderberry");
    const char *str = VarElderberry ? NONULL(VarElderberry->string) : "";
    if (!TEST_CHECK_STR_EQ(str, valid[i]))
    {
      TEST_MSG("Value of %s wasn't changed", name);
      return false;
    }
    TEST_MSG("%s = '%s', set by '%s'", name, str, NONULL(valid[i]));
  }

  name = "Tangerine";
  rc = cs_str_string_set(cs, name, "%Q", err);
  TEST_CHECK(CSR_RESULT(rc) != CSR_SUCCESS);

  name = "Wolfberry";
  rc = cs_str_string_set(cs, name, "wolfberry", err);
  TEST_CHECK_NUM_EQ(CSR_RESULT(rc), CSR_SUCCESS);

  rc = cs_str_string_set(cs, name, "apple", err);
  TEST_CHECK(CSR_RESULT(rc) != CSR_SUCCESS);

  name = "Damson";
  TEST_CHECK(!cs_str_has_been_set(cs, name));

  log_line(__func__);
  return true;
}

static bool test_string_get(struct ConfigSubset *sub, struct Buffer *err)
{
  log_line(__func__);
  struct ConfigSet *cs = sub->cs;

  const char *name = "Damson";
  buf_reset(err);
  int rc = cs_str_string_get(cs, name, err);
  if (!TEST_CHECK_NUM_EQ(CSR_RESULT(rc), CSR_SUCCESS))
  {
    TEST_MSG("Get failed: %s", buf_string(err));
    return false;
  }

  name = "Guava";
  buf_reset(err);
  rc = cs_str_string_get(cs, name, err);
  if (!TEST_CHECK_NUM_EQ(CSR_RESULT(rc), CSR_SUCCESS))
  {
    TEST_MSG("Get failed: %s", buf_string(err));
    return false;
  }
  const struct Expando *VarGuava = cs_subset_expando(sub, "Guava");
  const char *str = VarGuava ? NONULL(VarGuava->string) : "";
  TEST_MSG("%s = '%s', '%s'", name, str, buf_string(err));

  name = "Hawthorn";
  buf_reset(err);
  rc = cs_str_string_get(cs, name, err);
  if (!TEST_CHECK_NUM_EQ(CSR_RESULT(rc), CSR_SUCCESS))
  {
    TEST_MSG("Get failed: %s", buf_string(err));
    return false;
  }
  const struct Expando *VarHawthorn = cs_subset_expando(sub, "Hawthorn");
  str = VarHawthorn ? NONULL(VarHawthorn->string) : "";
  TEST_MSG("%s = '%s', '%s'", name, str, buf_string(err));

  name = "Ilama";
  rc = cs_str_string_set(cs, name, "ilama", err);
  if (!TEST_CHECK_NUM_EQ(CSR_RESULT(rc), CSR_SUCCESS))
    return false;

  buf_reset(err);
  rc = cs_str_string_get(cs, name, err);
  if (!TEST_CHECK_NUM_EQ(CSR_RESULT(rc), CSR_SUCCESS))
  {
    TEST_MSG("Get failed: %s", buf_string(err));
    return false;
  }
  const struct Expando *VarIlama = cs_subset_expando(sub, "Ilama");
  str = VarIlama ? NONULL(VarIlama->string) : "";
  TEST_MSG("%s = '%s', '%s'", name, str, buf_string(err));

  log_line(__func__);
  return true;
}

static bool test_native_set(struct ConfigSubset *sub, struct Buffer *err)
{
  log_line(__func__);

  const char *valid[] = { "hello", "world", "world", "", NULL };
  const char *name = "Jackfruit";
  struct ConfigSet *cs = sub->cs;

  int rc;
  for (unsigned int i = 0; i < mutt_array_size(valid); i++)
  {
    buf_reset(err);
    struct Expando *exp = expando_parse(valid[i], TestFormatDef, NULL);
    rc = cs_str_native_set(cs, name, (intptr_t) exp, err);
    expando_free(&exp);
    if (!TEST_CHECK_NUM_EQ(CSR_RESULT(rc), CSR_SUCCESS))
    {
      TEST_MSG("%s", buf_string(err));
      return false;
    }

    if (rc & CSR_SUC_NO_CHANGE)
    {
      TEST_MSG("Value of %s wasn't changed", name);
      continue;
    }

    const struct Expando *VarJackfruit = cs_subset_expando(sub, "Jackfruit");
    const char *str = VarJackfruit ? NONULL(VarJackfruit->string) : "";
    if (!TEST_CHECK_STR_EQ(str, valid[i]))
    {
      TEST_MSG("Value of %s wasn't changed", name);
      return false;
    }
    TEST_MSG("%s = '%s', set by '%s'", name, str, NONULL(valid[i]));
    short_line();
  }

  name = "Lemon";
  buf_reset(err);
  rc = cs_str_native_set(cs, name, 0, err);
  if (TEST_CHECK(CSR_RESULT(rc) != CSR_SUCCESS))
  {
    TEST_MSG("Expected error: %s", buf_string(err));
  }
  else
  {
    TEST_MSG("%s", buf_string(err));
    return false;
  }

  name = "Kumquat";
  for (unsigned int i = 0; i < mutt_array_size(valid); i++)
  {
    short_line();
    buf_reset(err);
    struct Expando *exp = expando_parse(valid[i], TestFormatDef, NULL);
    rc = cs_str_native_set(cs, name, (intptr_t) exp, err);
    expando_free(&exp);
    if (!TEST_CHECK_NUM_EQ(CSR_RESULT(rc), CSR_SUCCESS))
    {
      TEST_MSG("%s", buf_string(err));
      return false;
    }

    if (rc & CSR_SUC_NO_CHANGE)
    {
      TEST_MSG("Value of %s wasn't changed", name);
      continue;
    }

    const struct Expando *VarKumquat = cs_subset_expando(sub, "Kumquat");
    const char *str = VarKumquat ? NONULL(VarKumquat->string) : "";
    if (!TEST_CHECK_STR_EQ(str, valid[i]))
    {
      TEST_MSG("Value of %s wasn't changed", name);
      return false;
    }
    TEST_MSG("%s = '%s', set by '%s'", name, str, NONULL(valid[i]));
  }

  name = "Wolfberry";
  struct Expando *exp = expando_parse("wolfberry", TestFormatDef, NULL);
  rc = cs_str_native_set(cs, name, (intptr_t) exp, err);
  expando_free(&exp);
  TEST_CHECK_NUM_EQ(CSR_RESULT(rc), CSR_SUCCESS);

  exp = expando_parse("apple", TestFormatDef, NULL);
  rc = cs_str_native_set(cs, name, (intptr_t) exp, err);
  expando_free(&exp);
  TEST_CHECK(CSR_RESULT(rc) != CSR_SUCCESS);

  log_line(__func__);
  return true;
}

static bool test_native_get(struct ConfigSubset *sub, struct Buffer *err)
{
  log_line(__func__);
  struct ConfigSet *cs = sub->cs;
  const char *name = "Mango";

  int rc = cs_str_string_set(cs, name, "mango", err);
  if (!TEST_CHECK_NUM_EQ(CSR_RESULT(rc), CSR_SUCCESS))
    return false;

  const struct Expando *VarMango = cs_subset_expando(sub, "Mango");
  buf_reset(err);
  intptr_t value = cs_str_native_get(cs, name, err);
  struct Expando *exp_value = (struct Expando *) value;
  if (!TEST_CHECK(expando_equal(exp_value, VarMango)))
  {
    TEST_MSG("Get failed: %s", buf_string(err));
    return false;
  }
  TEST_MSG("%s = '%s', '%s'", name, VarMango->string, exp_value->string);

  log_line(__func__);
  return true;
}

static bool test_string_plus_equals(struct ConfigSubset *sub, struct Buffer *err)
{
  log_line(__func__);
  struct ConfigSet *cs = sub->cs;

  const char *name = "Tangerine";
  static char *PlusTests[][3] = {
    // clang-format off
    // Initial,        Plus,     Result
    { "",              "",       ""         }, // Add nothing to various strings
    { "%a",            "",       "%a"       },
    { "%a %b",         "",       "%a %b"    },
    { "%a %b %c",      "",       "%a %b %c" },

    { "",              "%c",     "%c"             }, // Add an item to various strings
    { "%a",            " %c",    "%a %c"          },
    { "%a %b",         " %c",    "%a %b %c"       },
    { "%a %b three",   " %c",    "%a %b three %c" },
    // clang-format on
  };

  int rc;
  for (unsigned int i = 0; i < mutt_array_size(PlusTests); i++)
  {
    buf_reset(err);
    rc = cs_str_string_set(cs, name, PlusTests[i][0], err);
    if (!TEST_CHECK_NUM_EQ(CSR_RESULT(rc), CSR_SUCCESS))
    {
      TEST_MSG("Set failed: %s", buf_string(err));
      return false;
    }

    rc = cs_str_string_plus_equals(cs, name, PlusTests[i][1], err);
    if (!TEST_CHECK_NUM_EQ(CSR_RESULT(rc), CSR_SUCCESS))
    {
      TEST_MSG("PlusEquals failed: %s", buf_string(err));
      return false;
    }

    rc = cs_str_string_get(cs, name, err);
    if (!TEST_CHECK_NUM_EQ(CSR_RESULT(rc), CSR_SUCCESS))
    {
      TEST_MSG("Get failed: %s", buf_string(err));
      return false;
    }

    if (!TEST_CHECK_STR_EQ(buf_string(err), PlusTests[i][2]))
      return false;
  }

  rc = cs_str_string_plus_equals(cs, name, "%Q", err);
  TEST_CHECK(CSR_RESULT(rc) != CSR_SUCCESS);

  name = "Wolfberry";
  rc = cs_str_string_plus_equals(cs, name, "apple", err);
  TEST_CHECK(CSR_RESULT(rc) != CSR_SUCCESS);

  log_line(__func__);
  return true;
}

static bool test_reset(struct ConfigSubset *sub, struct Buffer *err)
{
  log_line(__func__);
  struct ConfigSet *cs = sub->cs;

  const char *name = "Nectarine";
  buf_reset(err);

  const struct Expando *VarNectarine = cs_subset_expando(sub, "Nectarine");
  TEST_MSG("Initial: %s = '%s'", name, VarNectarine);
  int rc = cs_str_string_set(cs, name, "hello", err);
  if (!TEST_CHECK_NUM_EQ(CSR_RESULT(rc), CSR_SUCCESS))
    return false;
  VarNectarine = cs_subset_expando(sub, "Nectarine");
  TEST_MSG("Set: %s = '%s'", name, VarNectarine);

  rc = cs_str_reset(cs, name, err);
  if (!TEST_CHECK_NUM_EQ(CSR_RESULT(rc), CSR_SUCCESS))
  {
    TEST_MSG("%s", buf_string(err));
    return false;
  }

  VarNectarine = cs_subset_expando(sub, "Nectarine");
  const char *str = VarNectarine ? NONULL(VarNectarine->string) : "";
  if (!TEST_CHECK_STR_EQ(str, "nectarine"))
  {
    TEST_MSG("Value of %s wasn't changed", name);
    return false;
  }

  TEST_MSG("Reset: %s = '%s'", name, VarNectarine);

  rc = cs_str_reset(cs, name, err);
  if (!TEST_CHECK_NUM_EQ(CSR_RESULT(rc), CSR_SUCCESS))
  {
    TEST_MSG("%s", buf_string(err));
    return false;
  }

  name = "Olive";
  buf_reset(err);

  const struct Expando *VarOlive = cs_subset_expando(sub, "Olive");
  str = VarOlive ? NONULL(VarOlive->string) : "";
  TEST_MSG("Initial: %s = '%s'", name, VarOlive);
  dont_fail = true;
  rc = cs_str_string_set(cs, name, "hello", err);
  if (!TEST_CHECK_NUM_EQ(CSR_RESULT(rc), CSR_SUCCESS))
    return false;
  VarOlive = cs_subset_expando(sub, "Olive");
  TEST_MSG("Set: %s = '%s'", name, VarOlive);
  dont_fail = false;

  rc = cs_str_reset(cs, name, err);
  if (TEST_CHECK(CSR_RESULT(rc) != CSR_SUCCESS))
  {
    TEST_MSG("Expected error: %s", buf_string(err));
  }
  else
  {
    TEST_MSG("%s", buf_string(err));
    return false;
  }

  VarOlive = cs_subset_expando(sub, "Olive");
  str = VarOlive ? NONULL(VarOlive->string) : "";
  if (!TEST_CHECK_STR_EQ(str, "hello"))
  {
    TEST_MSG("Value of %s changed", name);
    return false;
  }

  TEST_MSG("Reset: %s = '%s'", name, VarOlive);

  name = "Wolfberry";
  rc = cs_str_reset(cs, name, err);
  TEST_CHECK_NUM_EQ(CSR_RESULT(rc), CSR_SUCCESS);

  StartupComplete = false;
  struct Expando *exp = expando_parse("apple", TestFormatDef, NULL);
  rc = cs_str_native_set(cs, name, (intptr_t) exp, err);
  expando_free(&exp);
  TEST_CHECK_NUM_EQ(CSR_RESULT(rc), CSR_SUCCESS);
  StartupComplete = true;

  rc = cs_str_reset(cs, name, err);
  TEST_CHECK(CSR_RESULT(rc) != CSR_SUCCESS);

  log_line(__func__);
  return true;
}

static bool test_validator(struct ConfigSubset *sub, struct Buffer *err)
{
  log_line(__func__);
  struct ConfigSet *cs = sub->cs;

  const char *name = "Papaya";
  buf_reset(err);
  int rc = cs_str_string_set(cs, name, "hello", err);
  if (TEST_CHECK_NUM_EQ(CSR_RESULT(rc), CSR_SUCCESS))
  {
    TEST_MSG("%s", buf_string(err));
  }
  else
  {
    TEST_MSG("%s", buf_string(err));
    return false;
  }
  const struct Expando *VarPapaya = cs_subset_expando(sub, "Papaya");
  const char *str = VarPapaya ? NONULL(VarPapaya->string) : "";
  TEST_MSG("Expando: %s = %s", name, str);

  buf_reset(err);
  struct Expando *exp = expando_parse("world", TestFormatDef, NULL);
  rc = cs_str_native_set(cs, name, (intptr_t) exp, err);
  expando_free(&exp);
  if (TEST_CHECK_NUM_EQ(CSR_RESULT(rc), CSR_SUCCESS))
  {
    TEST_MSG("%s", buf_string(err));
  }
  else
  {
    TEST_MSG("%s", buf_string(err));
    return false;
  }
  VarPapaya = cs_subset_expando(sub, "Papaya");
  str = VarPapaya ? NONULL(VarPapaya->string) : "";
  TEST_MSG("Native: %s = %s", name, str);

  name = "Quince";
  buf_reset(err);
  rc = cs_str_string_set(cs, name, "hello", err);
  if (TEST_CHECK_NUM_EQ(CSR_RESULT(rc), CSR_SUCCESS))
  {
    TEST_MSG("%s", buf_string(err));
  }
  else
  {
    TEST_MSG("%s", buf_string(err));
    return false;
  }
  const struct Expando *VarQuince = cs_subset_expando(sub, "Quince");
  str = VarQuince ? NONULL(VarQuince->string) : "";
  TEST_MSG("Expando: %s = %s", name, str);

  buf_reset(err);
  exp = expando_parse("world", TestFormatDef, NULL);
  rc = cs_str_native_set(cs, name, (intptr_t) exp, err);
  expando_free(&exp);
  if (TEST_CHECK_NUM_EQ(CSR_RESULT(rc), CSR_SUCCESS))
  {
    TEST_MSG("%s", buf_string(err));
  }
  else
  {
    TEST_MSG("%s", buf_string(err));
    return false;
  }
  VarQuince = cs_subset_expando(sub, "Quince");
  str = VarQuince ? NONULL(VarQuince->string) : "";
  TEST_MSG("Native: %s = %s", name, str);

  name = "Raspberry";
  buf_reset(err);
  rc = cs_str_string_set(cs, name, "hello", err);
  if (TEST_CHECK(CSR_RESULT(rc) != CSR_SUCCESS))
  {
    TEST_MSG("Expected error: %s", buf_string(err));
  }
  else
  {
    TEST_MSG("%s", buf_string(err));
    return false;
  }
  const struct Expando *VarRaspberry = cs_subset_expando(sub, "Raspberry");
  str = VarRaspberry ? NONULL(VarRaspberry->string) : "";
  TEST_MSG("Expando: %s = %s", name, str);

  buf_reset(err);
  exp = expando_parse("world", TestFormatDef, NULL);
  rc = cs_str_native_set(cs, name, (intptr_t) exp, err);
  expando_free(&exp);
  if (TEST_CHECK(CSR_RESULT(rc) != CSR_SUCCESS))
  {
    TEST_MSG("Expected error: %s", buf_string(err));
  }
  else
  {
    TEST_MSG("%s", buf_string(err));
    return false;
  }
  VarRaspberry = cs_subset_expando(sub, "Raspberry");
  str = VarRaspberry ? NONULL(VarRaspberry->string) : "";
  TEST_MSG("Native: %s = %s", name, str);

  name = "Olive";
  buf_reset(err);
  rc = cs_str_string_plus_equals(cs, name, "hello", err);
  if (TEST_CHECK(CSR_RESULT(rc) != CSR_SUCCESS))
  {
    TEST_MSG("Expected error: %s", buf_string(err));
  }
  else
  {
    TEST_MSG("%s", buf_string(err));
    return false;
  }
  const struct Expando *VarOlive = cs_subset_expando(sub, "Olive");
  str = VarOlive ? NONULL(VarOlive->string) : "";
  TEST_MSG("Expando: %s = %s", name, str);

  log_line(__func__);
  return true;
}

static void dump_native(struct ConfigSet *cs, const char *parent, const char *child)
{
  intptr_t pval = cs_str_native_get(cs, parent, NULL);
  intptr_t cval = cs_str_native_get(cs, child, NULL);

  TEST_MSG("%15s = %s", parent, (char *) pval);
  TEST_MSG("%15s = %s", child, (char *) cval);
}

static bool test_inherit(struct ConfigSet *cs, struct Buffer *err)
{
  log_line(__func__);
  bool result = false;

  const char *account = "fruit";
  const char *parent = "Strawberry";
  char child[128];
  snprintf(child, sizeof(child), "%s:%s", account, parent);

  struct ConfigSubset *sub = cs_subset_new(NULL, NULL, NeoMutt->notify);
  sub->cs = cs;
  struct Account *a = account_new(account, sub);

  struct HashElem *he = cs_subset_create_inheritance(a->sub, parent);
  if (!he)
  {
    TEST_MSG("Error: %s", buf_string(err));
    goto ti_out;
  }

  // set parent
  buf_reset(err);
  int rc = cs_str_string_set(cs, parent, "hello", err);
  if (CSR_RESULT(rc) != CSR_SUCCESS)
  {
    TEST_MSG("Error: %s", buf_string(err));
    goto ti_out;
  }
  dump_native(cs, parent, child);

  // set child
  buf_reset(err);
  rc = cs_str_string_set(cs, child, "world", err);
  if (CSR_RESULT(rc) != CSR_SUCCESS)
  {
    TEST_MSG("Error: %s", buf_string(err));
    goto ti_out;
  }
  dump_native(cs, parent, child);

  // reset child
  buf_reset(err);
  rc = cs_str_reset(cs, child, err);
  if (CSR_RESULT(rc) != CSR_SUCCESS)
  {
    TEST_MSG("Error: %s", buf_string(err));
    goto ti_out;
  }
  dump_native(cs, parent, child);

  // reset parent
  buf_reset(err);
  rc = cs_str_reset(cs, parent, err);
  if (CSR_RESULT(rc) != CSR_SUCCESS)
  {
    TEST_MSG("Error: %s", buf_string(err));
    goto ti_out;
  }
  dump_native(cs, parent, child);

  log_line(__func__);
  result = true;
ti_out:
  account_free(&a);
  cs_subset_free(&sub);
  return result;
}

void test_expando_config(void)
{
  struct ConfigSubset *sub = NeoMutt->sub;
  struct ConfigSet *cs = sub->cs;

  StartupComplete = false;
  dont_fail = true;
  if (!TEST_CHECK(cs_register_variables(cs, Vars)))
    return;
  dont_fail = false;
  StartupComplete = true;

  notify_observer_add(NeoMutt->notify, NT_CONFIG, log_observer, 0);

  set_list(cs);

  struct Buffer *err = buf_pool_get();
  TEST_CHECK(test_initial_values(sub, err));
  TEST_CHECK(test_string_set(sub, err));
  TEST_CHECK(test_string_get(sub, err));
  TEST_CHECK(test_native_set(sub, err));
  TEST_CHECK(test_native_get(sub, err));
  TEST_CHECK(test_string_plus_equals(sub, err));
  TEST_CHECK(test_reset(sub, err));
  TEST_CHECK(test_validator(sub, err));
  TEST_CHECK(test_inherit(cs, err));
  buf_pool_release(&err);
}
