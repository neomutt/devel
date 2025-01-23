/**
 * @file
 * Test code for the ConfigSet object
 *
 * @authors
 * Copyright (C) 2018-2025 Richard Russon <rich@flatcap.org>
 * Copyright (C) 2020 Jakub Jindra <jakub.jindra@socialbakers.com>
 * Copyright (C) 2023 наб <nabijaczleweli@nabijaczleweli.xyz>
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
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include "mutt/lib.h"
#include "config/lib.h"
#include "common.h"      // IWYU pragma: keep
#include "test_common.h" // IWYU pragma: keep

// clang-format off
static struct ConfigDef Vars[] = {
  { "Apple",  DT_NUMBER,  0, 0, NULL, },
  { "Banana", DT_BOOL,    1, 0, NULL, },
  { NULL },
};
// clang-format on

static int dummy_string_set(void *var, struct ConfigDef *cdef,
                            const char *value, struct Buffer *err)
{
  return CSR_ERR_CODE;
}

static int dummy_string_get(void *var, const struct ConfigDef *cdef, struct Buffer *result)
{
  return CSR_ERR_CODE;
}

static int dummy_native_set(void *var, const struct ConfigDef *cdef,
                            intptr_t value, struct Buffer *err)
{
  return CSR_ERR_CODE;
}

static intptr_t dummy_native_get(void *var, const struct ConfigDef *cdef, struct Buffer *err)
{
  return INT_MIN;
}

int dummy_plus_equals(void *var, const struct ConfigDef *cdef,
                      const char *value, struct Buffer *err)
{
  return CSR_ERR_CODE;
}

int dummy_minus_equals(void *var, const struct ConfigDef *cdef,
                       const char *value, struct Buffer *err)
{
  return CSR_ERR_CODE;
}

static bool dummy_has_been_set(void *var, const struct ConfigDef *cdef)
{
  return false;
}

static int dummy_reset(void *var, const struct ConfigDef *cdef, struct Buffer *err)
{
  return CSR_ERR_CODE;
}

void dummy_destroy(void *var, const struct ConfigDef *cdef)
{
}

bool degenerate_tests(struct ConfigSet *cs)
{
  const struct ConfigSetType CstDummy = {
    DT_REGEX, "dummy", NULL, NULL, NULL, NULL, NULL, NULL,
  };

  struct HashElem *he = cs_get_elem(cs, "Banana");

  cs_free(NULL);
  TEST_CHECK_(1, "cs_free(NULL)");

  if (!TEST_CHECK(cs_register_type(NULL, &CstDummy) == false))
    return false;
  if (!TEST_CHECK(cs_register_type(cs, NULL) == false))
    return false;
  if (!TEST_CHECK(cs_register_variables(cs, NULL) == false))
    return false;
  if (!TEST_CHECK(cs_register_variables(NULL, Vars) == false))
    return false;

  if (!TEST_CHECK(cs_str_native_get(NULL, "apple", NULL) == INT_MIN))
    return false;
  if (!TEST_CHECK(cs_str_native_get(cs, NULL, NULL) == INT_MIN))
    return false;

  if (!TEST_CHECK(cs_get_elem(NULL, "apple") == NULL))
    return false;
  if (!TEST_CHECK(cs_get_elem(cs, NULL) == NULL))
    return false;
  if (!TEST_CHECK(cs_get_type_def(NULL, DT_NUMBER) == NULL))
    return false;
  if (!TEST_CHECK(cs_get_type_def(cs, 30) == NULL))
    return false;
  if (!TEST_CHECK(cs_inherit_variable(NULL, he, "apple") == NULL))
    return false;
  if (!TEST_CHECK(cs_inherit_variable(cs, NULL, "apple") == NULL))
    return false;
  struct ConfigSet cs2 = { 0 };
  if (!TEST_CHECK(cs_inherit_variable(&cs2, he, "apple") == NULL))
    return false;

  cs_uninherit_variable(NULL, "apple");
  cs_uninherit_variable(cs, NULL);

  if (!TEST_CHECK(cs_str_native_set(NULL, "apple", IP "hello", NULL) != CSR_SUCCESS))
    return false;
  if (!TEST_CHECK(cs_str_native_set(cs, NULL, IP "hello", NULL) != CSR_SUCCESS))
    return false;
  if (!TEST_CHECK(cs_he_reset(NULL, he, NULL) != CSR_SUCCESS))
    return false;
  if (!TEST_CHECK(cs_he_reset(cs, NULL, NULL) != CSR_SUCCESS))
    return false;
  if (!TEST_CHECK(cs_str_reset(NULL, "apple", NULL) != CSR_SUCCESS))
    return false;
  if (!TEST_CHECK(cs_str_reset(cs, NULL, NULL) != CSR_SUCCESS))
    return false;
  if (!TEST_CHECK(!cs_he_has_been_set(NULL, he)))
    return false;
  if (!TEST_CHECK(!cs_he_has_been_set(cs, NULL)))
    return false;
  if (!TEST_CHECK(!cs_str_has_been_set(NULL, "apple")))
    return false;
  if (!TEST_CHECK(!cs_str_has_been_set(cs, NULL)))
    return false;
  if (!TEST_CHECK(!cs_str_has_been_set(cs, "apple")))
    return false;
  if (!TEST_CHECK(cs_he_initial_set(NULL, he, "42", NULL) != CSR_SUCCESS))
    return false;
  if (!TEST_CHECK(cs_he_initial_set(cs, NULL, "42", NULL) != CSR_SUCCESS))
    return false;
  if (!TEST_CHECK(cs_he_initial_set(cs, he, "42", NULL) != CSR_SUCCESS))
    return false;
  if (!TEST_CHECK(cs_str_initial_set(NULL, "apple", "42", NULL) != CSR_SUCCESS))
    return false;
  if (!TEST_CHECK(cs_str_initial_set(cs, NULL, "42", NULL) != CSR_SUCCESS))
    return false;
  if (!TEST_CHECK(cs_str_initial_set(cs, "unknown", "42", NULL) != CSR_SUCCESS))
    return false;
  if (!TEST_CHECK(cs_str_initial_get(NULL, "apple", NULL) != CSR_SUCCESS))
    return false;
  if (!TEST_CHECK(cs_str_initial_get(cs, NULL, NULL) != CSR_SUCCESS))
    return false;
  if (!TEST_CHECK(cs_str_initial_get(cs, "unknown", NULL) != CSR_SUCCESS))
    return false;
  if (!TEST_CHECK(cs_he_initial_get(NULL, he, NULL) != CSR_SUCCESS))
    return false;
  if (!TEST_CHECK(cs_he_initial_get(cs, NULL, NULL) != CSR_SUCCESS))
    return false;
  if (!TEST_CHECK(cs_he_string_set(NULL, he, "42", NULL) != CSR_SUCCESS))
    return false;
  if (!TEST_CHECK(cs_he_string_set(cs, NULL, "42", NULL) != CSR_SUCCESS))
    return false;
  if (!TEST_CHECK(cs_str_string_set(NULL, "apple", "42", NULL) != CSR_SUCCESS))
    return false;
  if (!TEST_CHECK(cs_str_string_set(cs, NULL, "42", NULL) != CSR_SUCCESS))
    return false;
  if (!TEST_CHECK(cs_he_string_plus_equals(NULL, he, "42", NULL) != CSR_SUCCESS))
    return false;
  if (!TEST_CHECK(cs_he_string_plus_equals(cs, NULL, "42", NULL) != CSR_SUCCESS))
    return false;
  if (!TEST_CHECK(cs_str_string_plus_equals(NULL, "apple", "42", NULL) != CSR_SUCCESS))
    return false;
  if (!TEST_CHECK(cs_str_string_plus_equals(cs, NULL, "42", NULL) != CSR_SUCCESS))
    return false;
  if (!TEST_CHECK(cs_he_string_minus_equals(NULL, he, "42", NULL) != CSR_SUCCESS))
    return false;
  if (!TEST_CHECK(cs_he_string_minus_equals(cs, NULL, "42", NULL) != CSR_SUCCESS))
    return false;
  if (!TEST_CHECK(cs_str_string_minus_equals(NULL, "apple", "42", NULL) != CSR_SUCCESS))
    return false;
  if (!TEST_CHECK(cs_str_string_minus_equals(cs, NULL, "42", NULL) != CSR_SUCCESS))
    return false;
  if (!TEST_CHECK(cs_he_string_get(NULL, he, NULL) != CSR_SUCCESS))
    return false;
  if (!TEST_CHECK(cs_he_string_get(cs, NULL, NULL) != CSR_SUCCESS))
    return false;
  if (!TEST_CHECK(cs_str_string_get(NULL, "apple", NULL) != CSR_SUCCESS))
    return false;
  if (!TEST_CHECK(cs_str_string_get(cs, NULL, NULL) != CSR_SUCCESS))
    return false;
  if (!TEST_CHECK(cs_he_native_set(NULL, he, 42, NULL) != CSR_SUCCESS))
    return false;
  if (!TEST_CHECK(cs_he_native_set(cs, NULL, 42, NULL) != CSR_SUCCESS))
    return false;
  if (!TEST_CHECK(cs_str_native_set(NULL, "apple", 42, NULL) != CSR_SUCCESS))
    return false;
  if (!TEST_CHECK(cs_str_native_set(cs, NULL, 42, NULL) != CSR_SUCCESS))
    return false;

  return true;
}

bool invalid_tests(struct ConfigSet *cs)
{
  struct HashElem *he = cs_get_elem(cs, "Banana");

  // Boolean doesn't support +=/-=
  if (!TEST_CHECK(cs_he_string_plus_equals(cs, he, "42", NULL) != CSR_SUCCESS))
    return false;
  if (!TEST_CHECK(cs_he_string_minus_equals(cs, he, "42", NULL) != CSR_SUCCESS))
    return false;

  he->type = 30;

  // Unknown type
  if (!TEST_CHECK(cs_he_initial_set(cs, he, "42", NULL) != CSR_SUCCESS))
    return false;
  if (!TEST_CHECK(cs_he_initial_get(cs, he, NULL) != CSR_SUCCESS))
    return false;
  if (!TEST_CHECK(cs_he_string_set(cs, he, "42", NULL) != CSR_SUCCESS))
    return false;
  if (!TEST_CHECK(cs_he_string_get(cs, he, NULL) != CSR_SUCCESS))
    return false;
  if (!TEST_CHECK(cs_he_native_set(cs, he, 42, NULL) != CSR_SUCCESS))
    return false;
  if (!TEST_CHECK(cs_he_native_get(cs, he, NULL) != CSR_SUCCESS))
    return false;
  if (!TEST_CHECK(cs_str_native_set(cs, "apple", 42, NULL) != CSR_SUCCESS))
    return false;
  if (!TEST_CHECK(cs_he_string_plus_equals(cs, he, "42", NULL) != CSR_SUCCESS))
    return false;
  if (!TEST_CHECK(cs_he_string_minus_equals(cs, he, "42", NULL) != CSR_SUCCESS))
    return false;

  he->type = DT_BOOL;

  return true;
}

bool creation_and_deletion_tests(struct ConfigSet *cs, struct Buffer *err)
{
  struct ConfigDef cherryDef = {
    "Cherry", DT_BOOL, 1, 0, NULL,
  };
  struct ConfigDef damsonDef = {
    "Damson", DT_BOOL, 1, 0, NULL,
  };

  {
    buf_reset(err);
    struct HashElem *cherry = cs_register_variable(cs, &cherryDef, err);
    if (!TEST_CHECK(cherry != NULL))
    {
      TEST_MSG("Variable registration failed: %s", buf_string(err));
      return false;
    }

    buf_reset(err);
    struct HashElem *damson = cs_register_variable(cs, &damsonDef, err);
    if (!TEST_CHECK(damson != NULL))
    {
      TEST_MSG("Variable registration failed: %s", buf_string(err));
      return false;
    }
  }

  {
    struct ConfigDef my_cdef = { 0 };
    struct HashElem *he = cs_create_variable(NULL, &my_cdef, err);
    TEST_CHECK(he == NULL);

    int rc = cs_he_delete(NULL, NULL, err);
    TEST_CHECK(CSR_RESULT(rc) != CSR_SUCCESS);

    rc = cs_str_delete(NULL, NULL, err);
    TEST_CHECK(CSR_RESULT(rc) != CSR_SUCCESS);
  }

  /* Dynamically created variables */
  {
    struct HashElem *cherry = cs_get_elem(cs, "Cherry");
    buf_reset(err);
    if (!TEST_CHECK(cs_he_delete(cs, cherry, err) == CSR_SUCCESS))
    {
      TEST_MSG("HashElem deletion failed: %s", buf_string(err));
      return false;
    }
    cherry = cs_get_elem(cs, "Cherry");
    if (!TEST_CHECK(cherry == NULL))
    {
      TEST_MSG("Cherry not deleted.");
      return false;
    }

    buf_reset(err);
    if (!TEST_CHECK(cs_str_delete(cs, "Damson", err) == CSR_SUCCESS))
    {
      TEST_MSG("String deletion failed: %s", buf_string(err));
      return false;
    }
    struct HashElem *damson = cs_get_elem(cs, "Damson");
    if (!TEST_CHECK(damson == NULL))
    {
      TEST_MSG("Damson not deleted.");
      return false;
    }
  }

  /* Delete unknown variable must fail */
  if (!TEST_CHECK(cs_str_delete(cs, "does-not-exist", err) == CSR_ERR_UNKNOWN))
  {
    TEST_MSG("Deletion of non-existent variable succeeded but should have failed: %s",
             buf_string(err));
    return false;
  }

  /* Delete a variable from a global ConfigDef struct */
  {
    struct HashElem *banana = cs_get_elem(cs, "Banana");
    buf_reset(err);
    if (!TEST_CHECK(cs_he_delete(cs, banana, NULL) == CSR_SUCCESS))
    {
      TEST_MSG("HashElem deletion failed: %s", buf_string(err));
      return false;
    }
    struct HashElem *banana_after = cs_get_elem(cs, "Banana");
    if (!TEST_CHECK(banana_after == NULL))
    {
      TEST_MSG("Banana not deleted.");
      return false;
    }
  }

  return true;
}

void test_config_set(void)
{
  log_line(__func__);

  struct Buffer *err = buf_pool_get();

  struct ConfigSet *cs = cs_new(30);
  if (!TEST_CHECK(cs != NULL))
    return;

  const struct ConfigSetType CstDummy = {
    DT_STRING, "dummy", NULL, NULL, NULL, NULL, NULL, NULL,
  };

  if (TEST_CHECK(!cs_register_type(cs, &CstDummy)))
  {
    TEST_MSG("Expected error");
  }
  else
  {
    TEST_MSG("This test should have failed");
    return;
  }

  const struct ConfigSetType CstDummy2 = {
    25,
    "dummy2",
    dummy_string_set,
    dummy_string_get,
    dummy_native_set,
    dummy_native_get,
    dummy_plus_equals,
    dummy_minus_equals,
    dummy_has_been_set,
    dummy_reset,
    dummy_destroy,
  };

  if (TEST_CHECK(!cs_register_type(cs, &CstDummy2)))
  {
    TEST_MSG("Expected error");
  }
  else
  {
    TEST_MSG("This test should have failed");
    return;
  }

  cs_register_type(cs, &CstBool);
  cs_register_type(cs, &CstBool); /* second one should fail */

  if (TEST_CHECK(!cs_register_variables(cs, Vars)))
  {
    TEST_MSG("Expected error");
  }
  else
  {
    TEST_MSG("This test should have failed");
    return;
  }

  if (!degenerate_tests(cs))
    return;

  if (!invalid_tests(cs))
    return;

  const char *name = "Unknown";
  int result = cs_str_string_set(cs, name, "hello", err);
  if (TEST_CHECK_NUM_EQ(CSR_RESULT(result), CSR_ERR_UNKNOWN))
  {
    TEST_MSG("Expected error: Unknown var '%s'", name);
  }
  else
  {
    TEST_MSG("This should have failed 1");
    return;
  }

  result = cs_str_string_plus_equals(cs, name, "42", err);
  if (TEST_CHECK_NUM_EQ(CSR_RESULT(result), CSR_ERR_UNKNOWN))
  {
    TEST_MSG("Expected error: Unknown var '%s'", name);
  }
  else
  {
    TEST_MSG("This should have failed 1");
    return;
  }

  result = cs_str_string_minus_equals(cs, name, "42", err);
  if (TEST_CHECK_NUM_EQ(CSR_RESULT(result), CSR_ERR_UNKNOWN))
  {
    TEST_MSG("Expected error: Unknown var '%s'", name);
  }
  else
  {
    TEST_MSG("This should have failed 1");
    return;
  }

  result = cs_str_string_get(cs, name, err);
  if (TEST_CHECK_NUM_EQ(CSR_RESULT(result), CSR_ERR_UNKNOWN))
  {
    TEST_MSG("Expected error: Unknown var '%s'", name);
  }
  else
  {
    TEST_MSG("This should have failed 2");
    return;
  }

  result = cs_str_native_set(cs, name, IP "hello", err);
  if (TEST_CHECK_NUM_EQ(CSR_RESULT(result), CSR_ERR_UNKNOWN))
  {
    TEST_MSG("Expected error: Unknown var '%s'", name);
  }
  else
  {
    TEST_MSG("This should have failed 3");
    return;
  }

  intptr_t native = cs_str_native_get(cs, name, err);
  if (TEST_CHECK_NUM_EQ(native, INT_MIN))
  {
    TEST_MSG("Expected error: Unknown var '%s'", name);
  }
  else
  {
    TEST_MSG("This should have failed 4");
    return;
  }

  struct HashElem *he = cs_get_elem(cs, "Banana");
  if (!TEST_CHECK(he != NULL))
    return;

  set_list(cs);

  const struct ConfigSetType *cst = cs_get_type_def(cs, 15);
  if (!TEST_CHECK(!cst))
    return;

  /* Test deleting elements.  This deletes Banana from cs! */
  if (!creation_and_deletion_tests(cs, err))
    return;

  cs_free(&cs);
  buf_pool_release(&err);
  log_line(__func__);
}
