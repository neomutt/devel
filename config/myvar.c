/**
 * @file
 * Type representing a user-defined variable "my_var"
 *
 * @authors
 * Copyright (C) 2023-2025 Richard Russon <rich@flatcap.org>
 * Copyright (C) 2023 Rayford Shireman
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
 * @page config_myvar Type: MyVar
 *
 * Config type representing a user-defined variable "my_var".
 *
 * - Backed by `char *`
 * - Empty variable is stored as `NULL`
 * - Data is freed when `ConfigSet` is freed
 * - Implementation: #CstMyVar
 */

#include "config.h"
#include <stddef.h>
#include <stdint.h>
#include "mutt/lib.h"
#include "set.h"
#include "types.h"

/**
 * myvar_destroy - Destroy a MyVar - Implements ConfigSetType::destroy() - @ingroup cfg_type_destroy
 */
static void myvar_destroy(void *var, const struct ConfigDef *cdef)
{
  const char **str = (const char **) var;
  if (!*str)
    return;

  FREE(var);
}

/**
 * myvar_string_set - Set a MyVar by string - Implements ConfigSetType::string_set() - @ingroup cfg_type_string_set
 */
static int myvar_string_set(void *var, struct ConfigDef *cdef,
                            const char *value, struct Buffer *err)
{
  /* Store empty myvars as NULL */
  if (value && (value[0] == '\0'))
    value = NULL;

  int rc = CSR_SUCCESS;

  if (var)
  {
    if (mutt_str_equal(value, (*(char **) var)))
      return CSR_SUCCESS | CSR_SUC_NO_CHANGE;

    myvar_destroy(var, cdef);

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
 * myvar_string_get - Get a MyVar as a string - Implements ConfigSetType::string_get() - @ingroup cfg_type_string_get
 */
static int myvar_string_get(void *var, const struct ConfigDef *cdef, struct Buffer *result)
{
  const char *str = NULL;

  if (var)
    str = *(const char **) var;
  else
    str = (char *) cdef->initial;

  if (!str)
    return CSR_SUCCESS | CSR_SUC_EMPTY; /* empty myvar */

  buf_addstr(result, str);
  return CSR_SUCCESS;
}

/**
 * myvar_native_set - Set a MyVar config item by string - Implements ConfigSetType::native_set() - @ingroup cfg_type_native_set
 */
static int myvar_native_set(void *var, const struct ConfigDef *cdef,
                            intptr_t value, struct Buffer *err)
{
  const char *str = (const char *) value;

  /* Store empty myvars as NULL */
  if (str && (str[0] == '\0'))
    value = 0;

  if (mutt_str_equal((const char *) value, (*(char **) var)))
    return CSR_SUCCESS | CSR_SUC_NO_CHANGE;

  int rc;

  myvar_destroy(var, cdef);

  str = mutt_str_dup(str);
  rc = CSR_SUCCESS;
  if (!str)
    rc |= CSR_SUC_EMPTY;

  *(const char **) var = str;
  return rc;
}

/**
 * myvar_native_get - Get a string from a MyVar config item - Implements ConfigSetType::native_get() - @ingroup cfg_type_native_get
 */
static intptr_t myvar_native_get(void *var, const struct ConfigDef *cdef, struct Buffer *err)
{
  const char *str = *(const char **) var;

  return (intptr_t) str;
}

/**
 * myvar_string_plus_equals - Add to a MyVar by string - Implements ConfigSetType::string_plus_equals() - @ingroup cfg_type_string_plus_equals
 */
static int myvar_string_plus_equals(void *var, const struct ConfigDef *cdef,
                                    const char *value, struct Buffer *err)
{
  /* Skip if the value is missing or empty string*/
  if (!value || (value[0] == '\0'))
    return CSR_SUCCESS | CSR_SUC_NO_CHANGE;

  int rc = CSR_SUCCESS;

  char *str = NULL;
  const char **var_str = (const char **) var;

  if (*var_str)
    mutt_str_asprintf(&str, "%s%s", *var_str, value);
  else
    str = mutt_str_dup(value);

  myvar_destroy(var, cdef);
  *var_str = str;

  return rc;
}

/**
 * myvar_reset - Reset a MyVar to its initial value - Implements ConfigSetType::reset() - @ingroup cfg_type_reset
 */
static int myvar_reset(void *var, const struct ConfigDef *cdef, struct Buffer *err)
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

  myvar_destroy(var, cdef);

  if (!str)
    rc |= CSR_SUC_EMPTY;

  *(const char **) var = str;
  return rc;
}

/**
 * CstMyVar - Config type representing a MyVar
 */
const struct ConfigSetType CstMyVar = {
  DT_MYVAR,
  "myvar",
  myvar_string_set,
  myvar_string_get,
  myvar_native_set,
  myvar_native_get,
  myvar_string_plus_equals,
  NULL, // string_minus_equals
  NULL, // has_been_set
  myvar_reset,
  myvar_destroy,
};
