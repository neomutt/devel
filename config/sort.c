/**
 * @file
 * Type representing a sort option
 *
 * @authors
 * Copyright (C) 2017-2025 Richard Russon <rich@flatcap.org>
 * Copyright (C) 2018 Pietro Cerutti <gahr@gahr.ch>
 * Copyright (C) 2020 Aditya De Saha <adityadesaha@gmail.com>
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
 * @page config_sort Type: Sorting
 *
 * Config type representing a sort option.
 *
 * - Backed by `short`
 * - Validator is passed `short`
 * - Implementation: #CstSort
 */

#include "config.h"
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "mutt/lib.h"
#include "sort.h"
#include "set.h"
#include "types.h"

#define PREFIX_REVERSE "reverse-"
#define PREFIX_LAST "last-"

/**
 * sort_string_set - Set a Sort by string - Implements ConfigSetType::string_set() - @ingroup cfg_type_string_set
 */
static int sort_string_set(void *var, struct ConfigDef *cdef, const char *value,
                           struct Buffer *err)
{
  intptr_t id = -1;
  uint16_t flags = 0;

  if (!value || (value[0] == '\0'))
  {
    buf_printf(err, _("Option %s may not be empty"), cdef->name);
    return CSR_ERR_INVALID | CSR_INV_TYPE;
  }

  size_t plen = 0;

  if (cdef->type & D_SORT_REVERSE)
  {
    plen = mutt_str_startswith(value, PREFIX_REVERSE);
    if (plen != 0)
    {
      flags |= SORT_REVERSE;
      value += plen;
    }
  }

  if (cdef->type & D_SORT_LAST)
  {
    plen = mutt_str_startswith(value, PREFIX_LAST);
    if (plen != 0)
    {
      flags |= SORT_LAST;
      value += plen;
    }
  }

  id = mutt_map_get_value(value, (struct Mapping *) cdef->data);

  if (id < 0)
  {
    buf_printf(err, _("Invalid sort name: %s"), value);
    return CSR_ERR_INVALID | CSR_INV_TYPE;
  }

  id |= flags;

  if (var)
  {
    if (id == (*(short *) var))
      return CSR_SUCCESS | CSR_SUC_NO_CHANGE;

    if (startup_only(cdef, err))
      return CSR_ERR_INVALID | CSR_INV_VALIDATOR;

    if (cdef->validator)
    {
      int rc = cdef->validator(cdef, (intptr_t) id, err);

      if (CSR_RESULT(rc) != CSR_SUCCESS)
        return rc | CSR_INV_VALIDATOR;
    }

    *(short *) var = id;
  }
  else
  {
    cdef->initial = id;
  }

  return CSR_SUCCESS;
}

/**
 * sort_string_get - Get a Sort as a string - Implements ConfigSetType::string_get() - @ingroup cfg_type_string_get
 */
static int sort_string_get(void *var, const struct ConfigDef *cdef, struct Buffer *result)
{
  int sort;

  if (var)
    sort = *(short *) var;
  else
    sort = (int) cdef->initial;

  if (sort & SORT_REVERSE)
    buf_addstr(result, PREFIX_REVERSE);
  if (sort & SORT_LAST)
    buf_addstr(result, PREFIX_LAST);

  sort &= SORT_MASK;

  const char *str = NULL;

  str = mutt_map_get_name(sort, (struct Mapping *) cdef->data);

  if (!str)
  {
    mutt_debug(LL_DEBUG1, "Variable has an invalid value: %d/%d\n", cdef->type, sort);
    return CSR_ERR_INVALID | CSR_INV_TYPE;
  }

  buf_addstr(result, str);
  return CSR_SUCCESS;
}

/**
 * sort_native_set - Set a Sort config item by int - Implements ConfigSetType::native_set() - @ingroup cfg_type_native_set
 */
static int sort_native_set(void *var, const struct ConfigDef *cdef,
                           intptr_t value, struct Buffer *err)
{
  const char *str = NULL;

  str = mutt_map_get_name((value & SORT_MASK), (struct Mapping *) cdef->data);

  if (!str)
  {
    buf_printf(err, _("Invalid sort type: %ld"), (long) value);
    return CSR_ERR_INVALID | CSR_INV_TYPE;
  }

  if (value == (*(short *) var))
    return CSR_SUCCESS | CSR_SUC_NO_CHANGE;

  if (startup_only(cdef, err))
    return CSR_ERR_INVALID | CSR_INV_VALIDATOR;

  if (cdef->validator)
  {
    int rc = cdef->validator(cdef, value, err);

    if (CSR_RESULT(rc) != CSR_SUCCESS)
      return rc | CSR_INV_VALIDATOR;
  }

  *(short *) var = value;
  return CSR_SUCCESS;
}

/**
 * sort_native_get - Get an int from a Sort config item - Implements ConfigSetType::native_get() - @ingroup cfg_type_native_get
 */
static intptr_t sort_native_get(void *var, const struct ConfigDef *cdef, struct Buffer *err)
{
  return *(short *) var;
}

/**
 * sort_has_been_set - Is the config value different to its initial value? - Implements ConfigSetType::has_been_set() - @ingroup cfg_type_has_been_set
 */
static bool sort_has_been_set(void *var, const struct ConfigDef *cdef)
{
  return (cdef->initial != (*(short *) var));
}

/**
 * sort_reset - Reset a Sort to its initial value - Implements ConfigSetType::reset() - @ingroup cfg_type_reset
 */
static int sort_reset(void *var, const struct ConfigDef *cdef, struct Buffer *err)
{
  if (cdef->initial == (*(short *) var))
    return CSR_SUCCESS | CSR_SUC_NO_CHANGE;

  if (startup_only(cdef, err))
    return CSR_ERR_INVALID | CSR_INV_VALIDATOR;

  if (cdef->validator)
  {
    int rc = cdef->validator(cdef, cdef->initial, err);

    if (CSR_RESULT(rc) != CSR_SUCCESS)
      return rc | CSR_INV_VALIDATOR;
  }

  *(short *) var = cdef->initial;
  return CSR_SUCCESS;
}

/**
 * CstSort - Config type representing a sort option
 */
const struct ConfigSetType CstSort = {
  DT_SORT,
  "sort",
  sort_string_set,
  sort_string_get,
  sort_native_set,
  sort_native_get,
  NULL, // string_plus_equals
  NULL, // string_minus_equals
  sort_has_been_set,
  sort_reset,
  NULL, // destroy
};
