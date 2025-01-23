/**
 * @file
 * Type representing a boolean
 *
 * @authors
 * Copyright (C) 2017-2025 Richard Russon <rich@flatcap.org>
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
 * @page config_bool Type: Boolean
 *
 * Config type representing a boolean.
 *
 * - Backed by `bool`
 * - Validator is passed `bool`
 * - Valid user entry: #BoolValues
 * - Implementation: #CstBool
 */

#include "config.h"
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "mutt/lib.h"
#include "bool.h"
#include "set.h"
#include "subset.h"
#include "types.h"

/**
 * BoolValues - Valid strings for creating a Bool
 *
 * These strings are case-insensitive.
 */
const char *BoolValues[] = {
  "no", "yes", "n", "y", "false", "true", "0", "1", "off", "on", NULL,
};

/**
 * bool_string_set - Set a Bool by string - Implements ConfigSetType::string_set() - @ingroup cfg_type_string_set
 */
static int bool_string_set(void *var, struct ConfigDef *cdef, const char *value,
                           struct Buffer *err)
{
  if (!value)
    return CSR_ERR_CODE; /* LCOV_EXCL_LINE */

  int num = -1;
  for (size_t i = 0; BoolValues[i]; i++)
  {
    if (mutt_istr_equal(BoolValues[i], value))
    {
      num = i % 2;
      break;
    }
  }

  if (num < 0)
  {
    buf_printf(err, _("Invalid boolean value: %s"), value);
    return CSR_ERR_INVALID | CSR_INV_TYPE;
  }

  if (var)
  {
    if (num == (*(bool *) var))
      return CSR_SUCCESS | CSR_SUC_NO_CHANGE;

    if (startup_only(cdef, err))
      return CSR_ERR_INVALID | CSR_INV_VALIDATOR;

    if (cdef->validator)
    {
      int rc = cdef->validator(cdef, (intptr_t) num, err);

      if (CSR_RESULT(rc) != CSR_SUCCESS)
        return rc | CSR_INV_VALIDATOR;
    }

    *(bool *) var = num;
  }
  else
  {
    cdef->initial = num;
  }

  return CSR_SUCCESS;
}

/**
 * bool_string_get - Get a Bool as a string - Implements ConfigSetType::string_get() - @ingroup cfg_type_string_get
 */
static int bool_string_get(void *var, const struct ConfigDef *cdef, struct Buffer *result)
{
  int index;

  if (var)
    index = *(bool *) var;
  else
    index = (int) cdef->initial;

  if (index > 1)
    return CSR_ERR_INVALID | CSR_INV_TYPE; /* LCOV_EXCL_LINE */

  buf_addstr(result, BoolValues[index]);
  return CSR_SUCCESS;
}

/**
 * bool_native_set - Set a Bool config item by bool - Implements ConfigSetType::native_set() - @ingroup cfg_type_native_set
 */
static int bool_native_set(void *var, const struct ConfigDef *cdef,
                           intptr_t value, struct Buffer *err)
{
  if ((value < 0) || (value > 1))
  {
    buf_printf(err, _("Invalid boolean value: %ld"), (long) value);
    return CSR_ERR_INVALID | CSR_INV_TYPE;
  }

  if (value == (*(bool *) var))
    return CSR_SUCCESS | CSR_SUC_NO_CHANGE;

  if (startup_only(cdef, err))
    return CSR_ERR_INVALID | CSR_INV_VALIDATOR;

  if (cdef->validator)
  {
    int rc = cdef->validator(cdef, value, err);

    if (CSR_RESULT(rc) != CSR_SUCCESS)
      return rc | CSR_INV_VALIDATOR;
  }

  *(bool *) var = value;
  return CSR_SUCCESS;
}

/**
 * bool_native_get - Get a bool from a Bool config item - Implements ConfigSetType::native_get() - @ingroup cfg_type_native_get
 */
static intptr_t bool_native_get(void *var, const struct ConfigDef *cdef, struct Buffer *err)
{
  return *(bool *) var;
}

/**
 * bool_has_been_set - Is the config value different to its initial value? - Implements ConfigSetType::has_been_set() - @ingroup cfg_type_has_been_set
 */
static bool bool_has_been_set(void *var, const struct ConfigDef *cdef)
{
  return (cdef->initial != (*(bool *) var));
}

/**
 * bool_reset - Reset a Bool to its initial value - Implements ConfigSetType::reset() - @ingroup cfg_type_reset
 */
static int bool_reset(void *var, const struct ConfigDef *cdef, struct Buffer *err)
{
  if (cdef->initial == (*(bool *) var))
    return CSR_SUCCESS | CSR_SUC_NO_CHANGE;

  if (startup_only(cdef, err))
    return CSR_ERR_INVALID | CSR_INV_VALIDATOR;

  if (cdef->validator)
  {
    int rc = cdef->validator(cdef, cdef->initial, err);

    if (CSR_RESULT(rc) != CSR_SUCCESS)
      return rc | CSR_INV_VALIDATOR;
  }

  *(bool *) var = cdef->initial;
  return CSR_SUCCESS;
}

/**
 * bool_he_toggle - Toggle the value of a bool
 * @param sub Config Subset
 * @param he  HashElem representing config item
 * @param err Buffer for error messages
 * @retval num Result, e.g. #CSR_SUCCESS
 */
int bool_he_toggle(struct ConfigSubset *sub, struct HashElem *he, struct Buffer *err)
{
  if (!sub || !he || !he->data)
    return CSR_ERR_CODE;

  struct HashElem *he_base = cs_get_base(he);
  if (CONFIG_TYPE(he_base->type) != DT_BOOL)
    return CSR_ERR_CODE;

  intptr_t value = cs_he_native_get(sub->cs, he, err);
  if (value == INT_MIN)
    return CSR_ERR_CODE;

  int rc = cs_he_native_set(sub->cs, he, !value, err);

  if ((CSR_RESULT(rc) == CSR_SUCCESS) && !(rc & CSR_SUC_NO_CHANGE))
    cs_subset_notify_observers(sub, he, NT_CONFIG_SET);

  return rc;
}

/**
 * bool_str_toggle - Toggle the value of a bool
 * @param sub  Config Subset
 * @param name Name of config item
 * @param err  Buffer for error messages
 * @retval num Result, e.g. #CSR_SUCCESS
 */
int bool_str_toggle(struct ConfigSubset *sub, const char *name, struct Buffer *err)
{
  struct HashElem *he = cs_subset_create_inheritance(sub, name);

  return bool_he_toggle(sub, he, err);
}

/**
 * CstBool - Config type representing an boolean
 */
const struct ConfigSetType CstBool = {
  DT_BOOL,
  "boolean",
  bool_string_set,
  bool_string_get,
  bool_native_set,
  bool_native_get,
  NULL, // string_plus_equals
  NULL, // string_minus_equals
  bool_has_been_set,
  bool_reset,
  NULL, // destroy
};
