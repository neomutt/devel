/**
 * @file
 * Type representing an enumeration
 *
 * @authors
 * Copyright (C) 2019-2025 Richard Russon <rich@flatcap.org>
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
 * @page config_enum Type: Enumeration
 *
 * Config type representing an enumeration.
 *
 * - Backed by `unsigned char`
 * - Validator is passed `unsigned char`
 * - Implementation: #CstEnum
 */

#include "config.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "mutt/lib.h"
#include "enum.h"
#include "set.h"
#include "types.h"

/**
 * enum_string_set - Set an Enumeration by string - Implements ConfigSetType::string_set() - @ingroup cfg_type_string_set
 */
static int enum_string_set(void *var, struct ConfigDef *cdef, const char *value,
                           struct Buffer *err)
{
  if (!value)
    return CSR_ERR_CODE; /* LCOV_EXCL_LINE */

  struct EnumDef *ed = (struct EnumDef *) cdef->data;
  if (!ed || !ed->lookup)
    return CSR_ERR_CODE;

  int num = mutt_map_get_value(value, ed->lookup);
  if (num < 0)
  {
    buf_printf(err, _("Invalid enum value: %s"), value);
    return CSR_ERR_INVALID | CSR_INV_TYPE;
  }

  if (var)
  {
    if (num == (*(unsigned char *) var))
      return CSR_SUCCESS | CSR_SUC_NO_CHANGE;

    if (startup_only(cdef, err))
      return CSR_ERR_INVALID | CSR_INV_VALIDATOR;

    if (cdef->validator)
    {
      int rc = cdef->validator(cdef, (intptr_t) num, err);

      if (CSR_RESULT(rc) != CSR_SUCCESS)
        return rc | CSR_INV_VALIDATOR;
    }

    *(unsigned char *) var = num;
  }
  else
  {
    cdef->initial = num;
  }

  return CSR_SUCCESS;
}

/**
 * enum_string_get - Get an Enumeration as a string - Implements ConfigSetType::string_get() - @ingroup cfg_type_string_get
 */
static int enum_string_get(void *var, const struct ConfigDef *cdef, struct Buffer *result)
{
  unsigned int value;

  if (var)
    value = *(unsigned char *) var;
  else
    value = (int) cdef->initial;

  struct EnumDef *ed = (struct EnumDef *) cdef->data;
  if (!ed || !ed->lookup)
    return CSR_ERR_CODE;

  const char *name = mutt_map_get_name(value, ed->lookup);
  if (!name)
  {
    mutt_debug(LL_DEBUG1, "Variable has an invalid value: %d\n", value);
    return CSR_ERR_INVALID | CSR_INV_TYPE;
  }

  buf_addstr(result, name);
  return CSR_SUCCESS;
}

/**
 * enum_native_set - Set an Enumeration config item by int - Implements ConfigSetType::native_set() - @ingroup cfg_type_native_set
 */
static int enum_native_set(void *var, const struct ConfigDef *cdef,
                           intptr_t value, struct Buffer *err)
{
  struct EnumDef *ed = (struct EnumDef *) cdef->data;
  if (!ed || !ed->lookup)
    return CSR_ERR_CODE;

  const char *name = mutt_map_get_name(value, ed->lookup);
  if (!name)
  {
    buf_printf(err, _("Invalid enum value: %ld"), (long) value);
    return CSR_ERR_INVALID | CSR_INV_TYPE;
  }

  if (value == (*(unsigned char *) var))
    return CSR_SUCCESS | CSR_SUC_NO_CHANGE;

  if (startup_only(cdef, err))
    return CSR_ERR_INVALID | CSR_INV_VALIDATOR;

  if (cdef->validator)
  {
    int rc = cdef->validator(cdef, value, err);

    if (CSR_RESULT(rc) != CSR_SUCCESS)
      return rc | CSR_INV_VALIDATOR;
  }

  *(unsigned char *) var = value;
  return CSR_SUCCESS;
}

/**
 * enum_native_get - Get an int object from an Enumeration config item - Implements ConfigSetType::native_get() - @ingroup cfg_type_native_get
 */
static intptr_t enum_native_get(void *var, const struct ConfigDef *cdef, struct Buffer *err)
{
  return *(unsigned char *) var;
}

/**
 * enum_has_been_set - Is the config value different to its initial value? - Implements ConfigSetType::has_been_set() - @ingroup cfg_type_has_been_set
 */
static bool enum_has_been_set(void *var, const struct ConfigDef *cdef)
{
  return (cdef->initial != (*(unsigned char *) var));
}

/**
 * enum_reset - Reset an Enumeration to its initial value - Implements ConfigSetType::reset() - @ingroup cfg_type_reset
 */
static int enum_reset(void *var, const struct ConfigDef *cdef, struct Buffer *err)
{
  if (cdef->initial == (*(unsigned char *) var))
    return CSR_SUCCESS | CSR_SUC_NO_CHANGE;

  if (startup_only(cdef, err))
    return CSR_ERR_INVALID | CSR_INV_VALIDATOR;

  if (cdef->validator)
  {
    int rc = cdef->validator(cdef, cdef->initial, err);

    if (CSR_RESULT(rc) != CSR_SUCCESS)
      return rc | CSR_INV_VALIDATOR;
  }

  *(unsigned char *) var = cdef->initial;
  return CSR_SUCCESS;
}

/**
 * CstEnum - Config type representing an enumeration
 */
const struct ConfigSetType CstEnum = {
  DT_ENUM,
  "enum",
  enum_string_set,
  enum_string_get,
  enum_native_set,
  enum_native_get,
  NULL, // string_plus_equals
  NULL, // string_minus_equals
  enum_has_been_set,
  enum_reset,
  NULL, // destroy
};
