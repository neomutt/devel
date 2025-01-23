/**
 * @file
 * Type representing a quad-option
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
 * @page config_quad Type: Quad-option
 *
 * Config type representing a quad-option.
 *
 * - Backed by `unsigned char`
 * - Validator is passed `unsigned char`
 * - Valid user entry: #QuadValues
 * - Implementation: #CstQuad
 *
 * The following unused functions were removed:
 * - quad_str_toggle()
 */

#include "config.h"
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "mutt/lib.h"
#include "quad.h"
#include "set.h"
#include "subset.h"
#include "types.h"

/**
 * QuadValues - Valid strings for creating a QuadValue
 *
 * These strings are case-insensitive.
 */
const char *QuadValues[] = {
  "no", "yes", "ask-no", "ask-yes", NULL,
};

/**
 * quad_string_set - Set a Quad-option by string - Implements ConfigSetType::string_set() - @ingroup cfg_type_string_set
 */
static int quad_string_set(void *var, struct ConfigDef *cdef, const char *value,
                           struct Buffer *err)
{
  if (!value)
    return CSR_ERR_CODE; /* LCOV_EXCL_LINE */

  int num = -1;
  for (size_t i = 0; QuadValues[i]; i++)
  {
    if (mutt_istr_equal(QuadValues[i], value))
    {
      num = i;
      break;
    }
  }

  if (num < 0)
  {
    buf_printf(err, _("Invalid quad value: %s"), value);
    return CSR_ERR_INVALID | CSR_INV_TYPE;
  }

  if (var)
  {
    if (num == (*(char *) var))
      return CSR_SUCCESS | CSR_SUC_NO_CHANGE;

    if (startup_only(cdef, err))
      return CSR_ERR_INVALID | CSR_INV_VALIDATOR;

    if (cdef->validator)
    {
      int rc = cdef->validator(cdef, (intptr_t) num, err);

      if (CSR_RESULT(rc) != CSR_SUCCESS)
        return rc | CSR_INV_VALIDATOR;
    }

    *(char *) var = num;
  }
  else
  {
    cdef->initial = num;
  }

  return CSR_SUCCESS;
}

/**
 * quad_string_get - Get a Quad-option as a string - Implements ConfigSetType::string_get() - @ingroup cfg_type_string_get
 */
static int quad_string_get(void *var, const struct ConfigDef *cdef, struct Buffer *result)
{
  unsigned int value;

  if (var)
    value = *(char *) var;
  else
    value = (int) cdef->initial;

  if (value >= (mutt_array_size(QuadValues) - 1))
  {
    mutt_debug(LL_DEBUG1, "Variable has an invalid value: %d\n", value); /* LCOV_EXCL_LINE */
    return CSR_ERR_INVALID | CSR_INV_TYPE; /* LCOV_EXCL_LINE */
  }

  buf_addstr(result, QuadValues[value]);
  return CSR_SUCCESS;
}

/**
 * quad_native_set - Set a Quad-option config item by int - Implements ConfigSetType::native_set() - @ingroup cfg_type_native_set
 */
static int quad_native_set(void *var, const struct ConfigDef *cdef,
                           intptr_t value, struct Buffer *err)
{
  if ((value < 0) || (value >= (mutt_array_size(QuadValues) - 1)))
  {
    buf_printf(err, _("Invalid quad value: %ld"), (long) value);
    return CSR_ERR_INVALID | CSR_INV_TYPE;
  }

  if (value == (*(char *) var))
    return CSR_SUCCESS | CSR_SUC_NO_CHANGE;

  if (startup_only(cdef, err))
    return CSR_ERR_INVALID | CSR_INV_VALIDATOR;

  if (cdef->validator)
  {
    int rc = cdef->validator(cdef, value, err);

    if (CSR_RESULT(rc) != CSR_SUCCESS)
      return rc | CSR_INV_VALIDATOR;
  }

  *(char *) var = value;
  return CSR_SUCCESS;
}

/**
 * quad_native_get - Get an int object from a Quad-option config item - Implements ConfigSetType::native_get() - @ingroup cfg_type_native_get
 */
static intptr_t quad_native_get(void *var, const struct ConfigDef *cdef, struct Buffer *err)
{
  return *(char *) var;
}

/**
 * quad_has_been_set - Is the config value different to its initial value? - Implements ConfigSetType::has_been_set() - @ingroup cfg_type_has_been_set
 */
static bool quad_has_been_set(void *var, const struct ConfigDef *cdef)
{
  return (cdef->initial != (*(char *) var));
}

/**
 * quad_reset - Reset a Quad-option to its initial value - Implements ConfigSetType::reset() - @ingroup cfg_type_reset
 */
static int quad_reset(void *var, const struct ConfigDef *cdef, struct Buffer *err)
{
  if (cdef->initial == (*(char *) var))
    return CSR_SUCCESS | CSR_SUC_NO_CHANGE;

  if (startup_only(cdef, err))
    return CSR_ERR_INVALID | CSR_INV_VALIDATOR;

  if (cdef->validator)
  {
    int rc = cdef->validator(cdef, cdef->initial, err);

    if (CSR_RESULT(rc) != CSR_SUCCESS)
      return rc | CSR_INV_VALIDATOR;
  }

  *(char *) var = cdef->initial;
  return CSR_SUCCESS;
}

/**
 * quad_toggle - Toggle (invert) the value of a quad option
 * @param opt Value to toggle
 * @retval num New value
 *
 * By toggling the low bit, the following are swapped:
 * - #MUTT_NO    <--> #MUTT_YES
 * - #MUTT_ASKNO <--> #MUTT_ASKYES
 */
static int quad_toggle(int opt)
{
  return opt ^ 1;
}

/**
 * quad_he_toggle - Toggle the value of a quad
 * @param sub Config subset
 * @param he  HashElem representing config item
 * @param err Buffer for error messages
 * @retval num Result, e.g. #CSR_SUCCESS
 *
 * @sa quad_toggle()
 */
int quad_he_toggle(struct ConfigSubset *sub, struct HashElem *he, struct Buffer *err)
{
  if (!sub || !he || !he->data)
    return CSR_ERR_CODE;

  struct HashElem *he_base = cs_get_base(he);
  if (CONFIG_TYPE(he_base->type) != DT_QUAD)
    return CSR_ERR_CODE;

  intptr_t value = cs_he_native_get(sub->cs, he, err);
  if (value == INT_MIN)
    return CSR_ERR_CODE;

  value = quad_toggle(value);
  int rc = cs_he_native_set(sub->cs, he, value, err);

  if ((CSR_RESULT(rc) == CSR_SUCCESS) && !(rc & CSR_SUC_NO_CHANGE))
    cs_subset_notify_observers(sub, he, NT_CONFIG_SET);

  return rc;
}

/**
 * CstQuad - Config type representing a quad-option
 */
const struct ConfigSetType CstQuad = {
  DT_QUAD,
  "quad",
  quad_string_set,
  quad_string_get,
  quad_native_set,
  quad_native_get,
  NULL, // string_plus_equals
  NULL, // string_minus_equals
  quad_has_been_set,
  quad_reset,
  NULL, // destroy
};
