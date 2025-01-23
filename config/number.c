/**
 * @file
 * Type representing a number
 *
 * @authors
 * Copyright (C) 2017-2025 Richard Russon <rich@flatcap.org>
 * Copyright (C) 2020 Jakub Jindra <jakub.jindra@socialbakers.com>
 * Copyright (C) 2021 Pietro Cerutti <gahr@gahr.ch>
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

/**
 * @page config_number Type: Number
 *
 * Config type representing a number.
 *
 * - Backed by `short`
 * - Validator is passed `short`
 * - Implementation: #CstNumber
 */

#include "config.h"
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "mutt/lib.h"
#include "number.h"
#include "set.h"
#include "subset.h"
#include "types.h"

#define TOGGLE_BIT ((SHRT_MAX + 1) << 1)
/**
 * native_get - Get an int from a Number config item
 */
static intptr_t native_get(void *var)
{
  // take care of endianess and always read intptr_t value
  intptr_t v = *(intptr_t *) var;
  return (v & TOGGLE_BIT) ? 0 : (short) v;
}

/**
 * native_set - Set an int into a Number config item
 */
static void native_set(void *var, intptr_t val)
{
  // cast to unsigned short to clear any pending toggle status bits
  val = (unsigned short) val;
  *(intptr_t *) var = val;
}

/**
 * native_toggle - Toggle a Number config item
 */
static void native_toggle(void *var)
{
  *(intptr_t *) var = *(uintptr_t *) var ^ TOGGLE_BIT;
}

/**
 * number_string_set - Set a Number by string - Implements ConfigSetType::string_set() - @ingroup cfg_type_string_set
 */
static int number_string_set(void *var, struct ConfigDef *cdef,
                             const char *value, struct Buffer *err)
{
  int num = 0;
  if (value && *value && !mutt_str_atoi_full(value, &num))
  {
    buf_printf(err, _("Invalid number: %s"), value);
    return CSR_ERR_INVALID | CSR_INV_TYPE;
  }

  if ((num < SHRT_MIN) || (num > SHRT_MAX))
  {
    buf_printf(err, _("Number is too big: %s"), value);
    return CSR_ERR_INVALID | CSR_INV_TYPE;
  }

  if ((num < 0) && (cdef->type & D_INTEGER_NOT_NEGATIVE))
  {
    buf_printf(err, _("Option %s may not be negative"), cdef->name);
    return CSR_ERR_INVALID | CSR_INV_VALIDATOR;
  }

  if (var)
  {
    if (num == native_get(var))
      return CSR_SUCCESS | CSR_SUC_NO_CHANGE;

    if (cdef->validator)
    {
      int rc = cdef->validator(cdef, (intptr_t) num, err);

      if (CSR_RESULT(rc) != CSR_SUCCESS)
        return rc | CSR_INV_VALIDATOR;
    }

    if (startup_only(cdef, err))
      return CSR_ERR_INVALID | CSR_INV_VALIDATOR;

    native_set(var, num);
  }
  else
  {
    cdef->initial = num;
  }

  return CSR_SUCCESS;
}

/**
 * number_string_get - Get a Number as a string - Implements ConfigSetType::string_get() - @ingroup cfg_type_string_get
 */
static int number_string_get(void *var, const struct ConfigDef *cdef, struct Buffer *result)
{
  int value;

  if (var)
    value = native_get(var);
  else
    value = (int) cdef->initial;

  buf_printf(result, "%d", value);
  return CSR_SUCCESS;
}

/**
 * number_native_set - Set a Number config item by int - Implements ConfigSetType::native_set() - @ingroup cfg_type_native_set
 */
static int number_native_set(void *var, const struct ConfigDef *cdef,
                             intptr_t value, struct Buffer *err)
{
  if ((value < SHRT_MIN) || (value > SHRT_MAX))
  {
    buf_printf(err, _("Invalid number: %ld"), (long) value);
    return CSR_ERR_INVALID | CSR_INV_TYPE;
  }

  if ((value < 0) && (cdef->type & D_INTEGER_NOT_NEGATIVE))
  {
    buf_printf(err, _("Option %s may not be negative"), cdef->name);
    return CSR_ERR_INVALID | CSR_INV_VALIDATOR;
  }

  if (value == native_get(var))
    return CSR_SUCCESS | CSR_SUC_NO_CHANGE;

  if (cdef->validator)
  {
    int rc = cdef->validator(cdef, value, err);

    if (CSR_RESULT(rc) != CSR_SUCCESS)
      return rc | CSR_INV_VALIDATOR;
  }

  if (startup_only(cdef, err))
    return CSR_ERR_INVALID | CSR_INV_VALIDATOR;

  native_set(var, value);
  return CSR_SUCCESS;
}

/**
 * number_native_get - Get an int from a Number config item - Implements ConfigSetType::native_get() - @ingroup cfg_type_native_get
 */
static intptr_t number_native_get(void *var, const struct ConfigDef *cdef, struct Buffer *err)
{
  return native_get(var);
}

/**
 * number_string_plus_equals - Add to a Number by string - Implements ConfigSetType::string_plus_equals() - @ingroup cfg_type_string_plus_equals
 */
static int number_string_plus_equals(void *var, const struct ConfigDef *cdef,
                                     const char *value, struct Buffer *err)
{
  int num = 0;
  if (!mutt_str_atoi_full(value, &num))
  {
    buf_printf(err, _("Invalid number: %s"), NONULL(value));
    return CSR_ERR_INVALID | CSR_INV_TYPE;
  }

  int result = number_native_get(var, NULL, NULL) + num;
  if ((result < SHRT_MIN) || (result > SHRT_MAX))
  {
    buf_printf(err, _("Number is too big: %s"), value);
    return CSR_ERR_INVALID | CSR_INV_TYPE;
  }

  if ((result < 0) && (cdef->type & D_INTEGER_NOT_NEGATIVE))
  {
    buf_printf(err, _("Option %s may not be negative"), cdef->name);
    return CSR_ERR_INVALID | CSR_INV_VALIDATOR;
  }

  if (cdef->validator)
  {
    int rc = cdef->validator(cdef, (intptr_t) result, err);

    if (CSR_RESULT(rc) != CSR_SUCCESS)
      return rc | CSR_INV_VALIDATOR;
  }

  if (startup_only(cdef, err))
    return CSR_ERR_INVALID | CSR_INV_VALIDATOR;

  native_set(var, result);
  return CSR_SUCCESS;
}

/**
 * number_string_minus_equals - Subtract from a Number by string - Implements ConfigSetType::string_minus_equals() - @ingroup cfg_type_string_minus_equals
 */
static int number_string_minus_equals(void *var, const struct ConfigDef *cdef,
                                      const char *value, struct Buffer *err)
{
  int num = 0;
  if (!mutt_str_atoi(value, &num))
  {
    buf_printf(err, _("Invalid number: %s"), NONULL(value));
    return CSR_ERR_INVALID | CSR_INV_TYPE;
  }

  int result = native_get(var) - num;
  if ((result < SHRT_MIN) || (result > SHRT_MAX))
  {
    buf_printf(err, _("Number is too big: %s"), value);
    return CSR_ERR_INVALID | CSR_INV_TYPE;
  }

  if ((result < 0) && (cdef->type & D_INTEGER_NOT_NEGATIVE))
  {
    buf_printf(err, _("Option %s may not be negative"), cdef->name);
    return CSR_ERR_INVALID | CSR_INV_VALIDATOR;
  }

  if (cdef->validator)
  {
    int rc = cdef->validator(cdef, (intptr_t) result, err);

    if (CSR_RESULT(rc) != CSR_SUCCESS)
      return rc | CSR_INV_VALIDATOR;
  }

  if (startup_only(cdef, err))
    return CSR_ERR_INVALID | CSR_INV_VALIDATOR;

  native_set(var, result);
  return CSR_SUCCESS;
}

/**
 * number_has_been_set - Is the config value different to its initial value? - Implements ConfigSetType::has_been_set() - @ingroup cfg_type_has_been_set
 */
static bool number_has_been_set(void *var, const struct ConfigDef *cdef)
{
  return (cdef->initial != native_get(var));
}

/**
 * number_reset - Reset a Number to its initial value - Implements ConfigSetType::reset() - @ingroup cfg_type_reset
 */
static int number_reset(void *var, const struct ConfigDef *cdef, struct Buffer *err)
{
  if (cdef->initial == native_get(var))
    return CSR_SUCCESS | CSR_SUC_NO_CHANGE;

  if (cdef->validator)
  {
    int rc = cdef->validator(cdef, cdef->initial, err);

    if (CSR_RESULT(rc) != CSR_SUCCESS)
      return rc | CSR_INV_VALIDATOR;
  }

  if (startup_only(cdef, err))
    return CSR_ERR_INVALID | CSR_INV_VALIDATOR;

  native_set(var, cdef->initial);
  return CSR_SUCCESS;
}

/**
 * number_he_toggle - Toggle the value of a number (value <-> 0)
 * @param sub Config Subset
 * @param he  HashElem representing config item
 * @param err Buffer for error messages
 * @retval num Result, e.g. #CSR_SUCCESS
 */
int number_he_toggle(struct ConfigSubset *sub, struct HashElem *he, struct Buffer *err)
{
  if (!sub || !he || !he->data)
    return CSR_ERR_CODE;

  struct HashElem *he_base = cs_get_base(he);
  if (CONFIG_TYPE(he_base->type) != DT_NUMBER)
    return CSR_ERR_CODE;

  struct ConfigDef *cdef = he_base->data;
  native_toggle(&cdef->var);

  cs_subset_notify_observers(sub, he, NT_CONFIG_SET);

  return CSR_SUCCESS;
}

/**
 * CstNumber - Config type representing a number
 */
const struct ConfigSetType CstNumber = {
  DT_NUMBER,
  "number",
  number_string_set,
  number_string_get,
  number_native_set,
  number_native_get,
  number_string_plus_equals,
  number_string_minus_equals,
  number_has_been_set,
  number_reset,
  NULL, // destroy
};
