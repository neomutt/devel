/**
 * @file
 * Type representing a string
 *
 * @authors
 * Copyright (C) 2017-2025 Richard Russon <rich@flatcap.org>
 * Copyright (C) 2020 Jakub Jindra <jakub.jindra@socialbakers.com>
 * Copyright (C) 2020 Pietro Cerutti <gahr@gahr.ch>
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
 * @page config_string Type: String
 *
 * Config type representing a string.
 *
 * - Backed by `char *`
 * - Empty string is stored as `NULL`
 * - Validator is passed `char *`, which may be `NULL`
 * - Data is freed when `ConfigSet` is freed
 * - Implementation: #CstString
 */

#include "config.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "mutt/lib.h"
#include "set.h"
#include "types.h"

/**
 * string_destroy - Destroy a String - Implements ConfigSetType::destroy() - @ingroup cfg_type_destroy
 */
static void string_destroy(void *var, const struct ConfigDef *cdef)
{
  const char **str = (const char **) var;
  if (!*str)
    return;

  FREE(var);
}

/**
 * string_string_set - Set a String by string - Implements ConfigSetType::string_set() - @ingroup cfg_type_string_set
 */
static int string_string_set(void *var, struct ConfigDef *cdef,
                             const char *value, struct Buffer *err)
{
  /* Store empty strings as NULL */
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
    if (mutt_str_equal(value, (*(char **) var)))
      return CSR_SUCCESS | CSR_SUC_NO_CHANGE;

    if (startup_only(cdef, err))
      return CSR_ERR_INVALID | CSR_INV_VALIDATOR;

    if (cdef->validator)
    {
      rc = cdef->validator(cdef, (intptr_t) value, err);

      if (CSR_RESULT(rc) != CSR_SUCCESS)
        return rc | CSR_INV_VALIDATOR;
    }

    string_destroy(var, cdef);

    const char *str = mutt_str_dup(value);
    if (!str)
      rc |= CSR_SUC_EMPTY;

    *(const char **) var = str;
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
 * string_string_get - Get a String as a string - Implements ConfigSetType::string_get() - @ingroup cfg_type_string_get
 */
static int string_string_get(void *var, const struct ConfigDef *cdef, struct Buffer *result)
{
  const char *str = NULL;

  if (var)
    str = *(const char **) var;
  else
    str = (char *) cdef->initial;

  if (!str)
    return CSR_SUCCESS | CSR_SUC_EMPTY; /* empty string */

  buf_addstr(result, str);
  return CSR_SUCCESS;
}

/**
 * string_native_set - Set a String config item by string - Implements ConfigSetType::native_set() - @ingroup cfg_type_native_set
 */
static int string_native_set(void *var, const struct ConfigDef *cdef,
                             intptr_t value, struct Buffer *err)
{
  const char *str = (const char *) value;

  /* Store empty strings as NULL */
  if (str && (str[0] == '\0'))
    value = 0;

  if ((value == 0) && (cdef->type & D_NOT_EMPTY))
  {
    buf_printf(err, _("Option %s may not be empty"), cdef->name);
    return CSR_ERR_INVALID | CSR_INV_VALIDATOR;
  }

  if (mutt_str_equal((const char *) value, (*(char **) var)))
    return CSR_SUCCESS | CSR_SUC_NO_CHANGE;

  int rc;

  if (startup_only(cdef, err))
    return CSR_ERR_INVALID | CSR_INV_VALIDATOR;

  if (cdef->validator)
  {
    rc = cdef->validator(cdef, value, err);

    if (CSR_RESULT(rc) != CSR_SUCCESS)
      return rc | CSR_INV_VALIDATOR;
  }

  string_destroy(var, cdef);

  str = mutt_str_dup(str);
  rc = CSR_SUCCESS;
  if (!str)
    rc |= CSR_SUC_EMPTY;

  *(const char **) var = str;
  return rc;
}

/**
 * string_native_get - Get a string from a String config item - Implements ConfigSetType::native_get() - @ingroup cfg_type_native_get
 */
static intptr_t string_native_get(void *var, const struct ConfigDef *cdef, struct Buffer *err)
{
  const char *str = *(const char **) var;

  return (intptr_t) str;
}

/**
 * string_string_plus_equals - Add to a String by string - Implements ConfigSetType::string_plus_equals() - @ingroup cfg_type_string_plus_equals
 */
static int string_string_plus_equals(void *var, const struct ConfigDef *cdef,
                                     const char *value, struct Buffer *err)
{
  /* Skip if the value is missing or empty string*/
  if (!value || (value[0] == '\0'))
    return CSR_SUCCESS | CSR_SUC_NO_CHANGE;

  if (value && startup_only(cdef, err))
    return CSR_ERR_INVALID | CSR_INV_VALIDATOR;

  int rc = CSR_SUCCESS;

  char *str = NULL;
  const char **var_str = (const char **) var;

  if (*var_str)
    mutt_str_asprintf(&str, "%s%s", *var_str, value);
  else
    str = mutt_str_dup(value);

  if (cdef->validator)
  {
    rc = cdef->validator(cdef, (intptr_t) str, err);

    if (CSR_RESULT(rc) != CSR_SUCCESS)
    {
      FREE(&str);
      return rc | CSR_INV_VALIDATOR;
    }
  }

  string_destroy(var, cdef);
  *var_str = str;

  return rc;
}

/**
 * string_has_been_set - Is the config value different to its initial value? - Implements ConfigSetType::has_been_set() - @ingroup cfg_type_has_been_set
 */
static bool string_has_been_set(void *var, const struct ConfigDef *cdef)
{
  const char *initial = (const char *) cdef->initial;
  const char *value = *(const char **) var;

  return !mutt_str_equal(initial, value);
}

/**
 * string_reset - Reset a String to its initial value - Implements ConfigSetType::reset() - @ingroup cfg_type_reset
 */
static int string_reset(void *var, const struct ConfigDef *cdef, struct Buffer *err)
{
  int rc = CSR_SUCCESS;

  const char *str = mutt_str_dup((const char *) cdef->initial);
  if (!str)
    rc |= CSR_SUC_EMPTY;

  if (mutt_str_equal(str, (*(char **) var)))
  {
    FREE(&str);
    return rc | CSR_SUC_NO_CHANGE;
  }

  if (startup_only(cdef, err))
  {
    FREE(&str);
    return CSR_ERR_INVALID | CSR_INV_VALIDATOR;
  }

  if (cdef->validator)
  {
    rc = cdef->validator(cdef, cdef->initial, err);

    if (CSR_RESULT(rc) != CSR_SUCCESS)
    {
      FREE(&str);
      return rc | CSR_INV_VALIDATOR;
    }
  }

  string_destroy(var, cdef);

  if (!str)
    rc |= CSR_SUC_EMPTY;

  *(const char **) var = str;
  return rc;
}

/**
 * CstString - Config type representing a string
 */
const struct ConfigSetType CstString = {
  DT_STRING,
  "string",
  string_string_set,
  string_string_get,
  string_native_set,
  string_native_get,
  string_string_plus_equals,
  NULL, // string_minus_equals
  string_has_been_set,
  string_reset,
  string_destroy,
};
