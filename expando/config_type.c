/**
 * @file
 * Type representing an Expando
 *
 * @authors
 * Copyright (C) 2023-2024 Tóth János <gomba007@gmail.com>
 * Copyright (C) 2023-2025 Richard Russon <rich@flatcap.org>
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

/**
 * @page expando_config_type Type: Expando
 *
 * Config type representing an Expando.
 *
 * - Backed by `struct Expando`
 * - Empty Expando is stored as `NULL`
 * - Validator is passed `struct Expando *`, which may be `NULL`
 * - Data is freed when `ConfigSet` is freed
 * - Implementation: #CstExpando
 */

#include "config.h"
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "mutt/lib.h"
#include "config/lib.h"
#include "expando.h"

/**
 * expando_destroy - Destroy an Expando object - Implements ConfigSetType::destroy() - @ingroup cfg_type_destroy
 */
static void expando_destroy(void *var, const struct ConfigDef *cdef)
{
  struct Expando **a = var;
  if (!*a)
    return;

  expando_free(a);
}

/**
 * expando_string_set - Set an Expando by string - Implements ConfigSetType::string_set() - @ingroup cfg_type_string_set
 */
static int expando_string_set(void *var, struct ConfigDef *cdef,
                              const char *value, struct Buffer *err)
{
  /* Store empty string list as NULL */
  if (value && (value[0] == '\0'))
    value = NULL;

  if (!value && (cdef->type & D_NOT_EMPTY))
  {
    buf_printf(err, _("Option %s may not be empty"), cdef->name);
    return CSR_ERR_INVALID | CSR_INV_VALIDATOR;
  }

  int rc = CSR_SUCCESS;

  if (var)
  {
    const struct ExpandoDefinition *defs = (const struct ExpandoDefinition *)
                                               cdef->data;
    struct Expando *exp = expando_parse(value, defs, err);
    if (!exp && !buf_is_empty(err))
    {
      char opt[128] = { 0 };
      // L10N: e.g. "Option index_format:" plus an error message
      snprintf(opt, sizeof(opt), _("Option %s: "), cdef->name);
      buf_insert(err, 0, opt);
      return CSR_ERR_INVALID;
    }

    if (expando_equal(exp, *(struct Expando **) var))
    {
      expando_free(&exp);
      return CSR_SUCCESS | CSR_SUC_NO_CHANGE;
    }

    if (startup_only(cdef, err))
    {
      expando_free(&exp);
      return CSR_ERR_INVALID | CSR_INV_VALIDATOR;
    }

    if (cdef->validator)
    {
      rc = cdef->validator(cdef, (intptr_t) exp, err);

      if (CSR_RESULT(rc) != CSR_SUCCESS)
      {
        expando_free(&exp);
        return rc | CSR_INV_VALIDATOR;
      }
    }

    expando_destroy(var, cdef);

    *(struct Expando **) var = exp;

    if (!exp)
      rc |= CSR_SUC_EMPTY;
  }
  else
  {
    if (cdef->type & D_INTERNAL_INITIAL_SET)
      FREE(&cdef->initial);

    cdef->type |= D_INTERNAL_INITIAL_SET;
    cdef->initial = (intptr_t) mutt_str_dup(value);
  }

  return rc;
}

/**
 * expando_string_get - Get an Expando as a string - Implements ConfigSetType::string_get() - @ingroup cfg_type_string_get
 */
static int expando_string_get(void *var, const struct ConfigDef *cdef, struct Buffer *result)
{
  const char *str = NULL;

  if (var)
  {
    struct Expando *exp = *(struct Expando **) var;
    if (exp)
      str = exp->string;
  }
  else
  {
    str = (char *) cdef->initial;
  }

  if (!str)
    return CSR_SUCCESS | CSR_SUC_EMPTY; /* empty string */

  buf_addstr(result, str);
  return CSR_SUCCESS;
}

/**
 * expando_native_set - Set an Expando object from an Expando config item - Implements ConfigSetType::native_get() - @ingroup cfg_type_native_get
 */
static int expando_native_set(void *var, const struct ConfigDef *cdef,
                              intptr_t value, struct Buffer *err)
{
  int rc;

  struct Expando *exp_value = (struct Expando *) value;
  if (!exp_value && (cdef->type & D_NOT_EMPTY))
  {
    buf_printf(err, _("Option %s may not be empty"), cdef->name);
    return CSR_ERR_INVALID | CSR_INV_VALIDATOR;
  }

  struct Expando *exp_old = *(struct Expando **) var;
  if (expando_equal(exp_value, exp_old))
    return CSR_SUCCESS | CSR_SUC_NO_CHANGE;

  if (startup_only(cdef, err))
    return CSR_ERR_INVALID | CSR_INV_VALIDATOR;

  if (cdef->validator)
  {
    rc = cdef->validator(cdef, value, err);

    if (CSR_RESULT(rc) != CSR_SUCCESS)
      return rc | CSR_INV_VALIDATOR;
  }

  expando_free(var);

  struct Expando *exp_copy = NULL;

  if (exp_value)
  {
    const struct ExpandoDefinition *defs = (const struct ExpandoDefinition *)
                                               cdef->data;
    exp_copy = expando_parse(exp_value->string, defs, err);
  }

  rc = CSR_SUCCESS;
  if (!exp_copy)
    rc |= CSR_SUC_EMPTY;

  *(struct Expando **) var = exp_copy;
  return rc;
}

/**
 * expando_native_get - Get an Expando object from an Expando config item - Implements ConfigSetType::native_get() - @ingroup cfg_type_native_get
 */
static intptr_t expando_native_get(void *var, const struct ConfigDef *cdef, struct Buffer *err)
{
  struct Expando *exp = *(struct Expando **) var;

  return (intptr_t) exp;
}

/**
 * expando_string_plus_equals - Add to an Expando by string - Implements ConfigSetType::string_plus_equals() - @ingroup cfg_type_string_plus_equals
 */
static int expando_string_plus_equals(void *var, const struct ConfigDef *cdef,
                                      const char *value, struct Buffer *err)
{
  /* Skip if the value is missing or empty string*/
  if (!value || (value[0] == '\0'))
    return CSR_SUCCESS | CSR_SUC_NO_CHANGE;

  if (value && startup_only(cdef, err))
    return CSR_ERR_INVALID | CSR_INV_VALIDATOR;

  int rc = CSR_SUCCESS;

  char *str = NULL;
  struct Expando *exp_old = *(struct Expando **) var;

  if (exp_old && exp_old->string)
    mutt_str_asprintf(&str, "%s%s", exp_old->string, value);
  else
    str = mutt_str_dup(value);

  const struct ExpandoDefinition *defs = (const struct ExpandoDefinition *) cdef->data;
  struct Expando *exp_new = expando_parse(str, defs, err);
  FREE(&str);

  if (!exp_new && !buf_is_empty(err))
  {
    char opt[128] = { 0 };
    // L10N: e.g. "Option index_format:" plus an error message
    snprintf(opt, sizeof(opt), _("Option %s: "), cdef->name);
    buf_insert(err, 0, opt);
    return CSR_ERR_INVALID;
  }

  if (expando_equal(exp_new, exp_old))
  {
    expando_free(&exp_new);                 // LCOV_EXCL_LINE
    return CSR_SUCCESS | CSR_SUC_NO_CHANGE; // LCOV_EXCL_LINE
  }

  if (cdef->validator)
  {
    rc = cdef->validator(cdef, (intptr_t) exp_new, err);

    if (CSR_RESULT(rc) != CSR_SUCCESS)
    {
      expando_free(&exp_new);
      return rc | CSR_INV_VALIDATOR;
    }
  }

  expando_destroy(var, cdef);
  *(struct Expando **) var = exp_new;

  return rc;
}

/**
 * expando_has_been_set - Is the config value different to its initial value? - Implements ConfigSetType::has_been_set() - @ingroup cfg_type_has_been_set
 */
static bool expando_has_been_set(void *var, const struct ConfigDef *cdef)
{
  const char *initial = (const char *) cdef->initial;

  struct Expando *exp = *(struct Expando **) var;
  const char *exp_str = exp ? exp->string : NULL;

  return !mutt_str_equal(initial, exp_str);
}

/**
 * expando_reset - Reset an Expando to its initial value - Implements ConfigSetType::reset() - @ingroup cfg_type_reset
 */
static int expando_reset(void *var, const struct ConfigDef *cdef, struct Buffer *err)
{
  struct Expando *exp = NULL;
  const char *initial = (const char *) cdef->initial;

  if (initial)
  {
    const struct ExpandoDefinition *defs = (const struct ExpandoDefinition *)
                                               cdef->data;
    exp = expando_parse(initial, defs, err);
  }

  if (expando_equal(exp, *(struct Expando **) var))
  {
    expando_free(&exp);
    return CSR_SUCCESS | CSR_SUC_NO_CHANGE;
  }

  if (startup_only(cdef, err))
  {
    expando_free(&exp);
    return CSR_ERR_INVALID | CSR_INV_VALIDATOR;
  }

  int rc = CSR_SUCCESS;

  if (cdef->validator)
  {
    rc = cdef->validator(cdef, (intptr_t) exp, err);

    if (CSR_RESULT(rc) != CSR_SUCCESS)
    {
      expando_destroy(&exp, cdef);
      return rc | CSR_INV_VALIDATOR;
    }
  }

  if (!exp)
    rc |= CSR_SUC_EMPTY;

  expando_destroy(var, cdef);

  *(struct Expando **) var = exp;
  return rc;
}

/**
 * CstExpando - Config type representing an Expando
 */
const struct ConfigSetType CstExpando = {
  DT_EXPANDO,
  "expando",
  expando_string_set,
  expando_string_get,
  expando_native_set,
  expando_native_get,
  expando_string_plus_equals,
  NULL, // string_minus_equals
  expando_has_been_set,
  expando_reset,
  expando_destroy,
};

/**
 * cs_subset_expando - Get an Expando config item by name
 * @param sub   Config Subset
 * @param name  Name of config item
 * @retval ptr  Expando
 * @retval NULL Empty Expando
 */
const struct Expando *cs_subset_expando(const struct ConfigSubset *sub, const char *name)
{
  ASSERT(sub && name);

  struct HashElem *he = cs_subset_create_inheritance(sub, name);
  ASSERT(he);

#ifndef NDEBUG
  struct HashElem *he_base = cs_get_base(he);
  ASSERT(CONFIG_TYPE(he_base->type) == DT_EXPANDO);
#endif

  intptr_t value = cs_subset_he_native_get(sub, he, NULL);
  ASSERT(value != INT_MIN);

  return (const struct Expando *) value;
}
