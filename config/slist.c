/**
 * @file
 * Type representing a list of strings
 *
 * @authors
 * Copyright (C) 2019-2025 Richard Russon <rich@flatcap.org>
 * Copyright (C) 2020 Jakub Jindra <jakub.jindra@socialbakers.com>
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
 * @page config_slist Type: List of strings
 *
 * Config type representing a list of strings.
 *
 * - Backed by `struct Slist`
 * - Empty string list is stored as `NULL`
 * - Validator is passed `struct Slist`, which may be `NULL`
 * - Data is freed when `ConfigSet` is freed
 * - Implementation: #CstSlist
 */

#include "config.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "mutt/lib.h"
#include "set.h"
#include "types.h"

/**
 * slist_destroy - Destroy an Slist object - Implements ConfigSetType::destroy() - @ingroup cfg_type_destroy
 */
static void slist_destroy(void *var, const struct ConfigDef *cdef)
{
  struct Slist **l = (struct Slist **) var;
  if (!*l)
    return;

  slist_free(l);
}

/**
 * slist_string_set - Set a Slist by string - Implements ConfigSetType::string_set() - @ingroup cfg_type_string_set
 */
static int slist_string_set(void *var, struct ConfigDef *cdef,
                            const char *value, struct Buffer *err)
{
  /* Store empty string list as NULL */
  if (value && (value[0] == '\0'))
    value = NULL;

  struct Slist *list = NULL;

  int rc = CSR_SUCCESS;

  if (var)
  {
    list = slist_parse(value, cdef->type);

    if (slist_equal(list, *(struct Slist **) var))
    {
      slist_free(&list);
      return CSR_SUCCESS | CSR_SUC_NO_CHANGE;
    }

    if (startup_only(cdef, err))
    {
      slist_free(&list);
      return CSR_ERR_INVALID | CSR_INV_VALIDATOR;
    }

    if (cdef->validator)
    {
      rc = cdef->validator(cdef, (intptr_t) list, err);

      if (CSR_RESULT(rc) != CSR_SUCCESS)
      {
        slist_free(&list);
        return rc | CSR_INV_VALIDATOR;
      }
    }

    slist_destroy(var, cdef);

    *(struct Slist **) var = list;

    if (!list)
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
 * slist_string_get - Get a Slist as a string - Implements ConfigSetType::string_get() - @ingroup cfg_type_string_get
 */
static int slist_string_get(void *var, const struct ConfigDef *cdef, struct Buffer *result)
{
  if (var)
  {
    struct Slist *list = *(struct Slist **) var;
    if (!list)
      return CSR_SUCCESS | CSR_SUC_EMPTY; /* empty string */

    slist_to_buffer(list, result);
  }
  else
  {
    buf_addstr(result, (char *) cdef->initial);
  }

  int rc = CSR_SUCCESS;
  if (buf_is_empty(result))
    rc |= CSR_SUC_EMPTY;

  return rc;
}

/**
 * slist_native_set - Set a Slist config item by Slist - Implements ConfigSetType::native_set() - @ingroup cfg_type_native_set
 */
static int slist_native_set(void *var, const struct ConfigDef *cdef,
                            intptr_t value, struct Buffer *err)
{
  int rc;

  if (slist_equal((struct Slist *) value, *(struct Slist **) var))
    return CSR_SUCCESS | CSR_SUC_NO_CHANGE;

  if (startup_only(cdef, err))
    return CSR_ERR_INVALID | CSR_INV_VALIDATOR;

  if (cdef->validator)
  {
    rc = cdef->validator(cdef, value, err);

    if (CSR_RESULT(rc) != CSR_SUCCESS)
      return rc | CSR_INV_VALIDATOR;
  }

  slist_free(var);

  struct Slist *list = slist_dup((struct Slist *) value);

  rc = CSR_SUCCESS;
  if (!list)
    rc |= CSR_SUC_EMPTY;

  *(struct Slist **) var = list;
  return rc;
}

/**
 * slist_native_get - Get a Slist from a Slist config item - Implements ConfigSetType::native_get() - @ingroup cfg_type_native_get
 */
static intptr_t slist_native_get(void *var, const struct ConfigDef *cdef, struct Buffer *err)
{
  struct Slist *list = *(struct Slist **) var;

  return (intptr_t) list;
}

/**
 * slist_string_plus_equals - Add to a Slist by string - Implements ConfigSetType::string_plus_equals() - @ingroup cfg_type_string_plus_equals
 */
static int slist_string_plus_equals(void *var, const struct ConfigDef *cdef,
                                    const char *value, struct Buffer *err)
{
  int rc = CSR_SUCCESS;

  /* Store empty strings as NULL */
  if (value && (value[0] == '\0'))
    value = NULL;

  if (!value)
    return rc | CSR_SUC_NO_CHANGE;

  if (startup_only(cdef, err))
    return CSR_ERR_INVALID | CSR_INV_VALIDATOR;

  struct Slist *orig = *(struct Slist **) var;
  if (slist_is_member(orig, value))
    return rc | CSR_SUC_NO_CHANGE;

  struct Slist *copy = slist_dup(orig);
  if (!copy)
    copy = slist_new(cdef->type & D_SLIST_SEP_MASK);

  slist_add_string(copy, value);

  if (cdef->validator)
  {
    rc = cdef->validator(cdef, (intptr_t) copy, err);
    if (CSR_RESULT(rc) != CSR_SUCCESS)
    {
      slist_free(&copy);
      return rc | CSR_INV_VALIDATOR;
    }
  }

  slist_free(&orig);
  *(struct Slist **) var = copy;

  return rc;
}

/**
 * slist_string_minus_equals - Remove from a Slist by string - Implements ConfigSetType::string_minus_equals() - @ingroup cfg_type_string_minus_equals
 */
static int slist_string_minus_equals(void *var, const struct ConfigDef *cdef,
                                     const char *value, struct Buffer *err)
{
  int rc = CSR_SUCCESS;

  /* Store empty strings as NULL */
  if (value && (value[0] == '\0'))
    value = NULL;

  if (!value)
    return rc | CSR_SUC_NO_CHANGE;

  if (startup_only(cdef, err))
    return CSR_ERR_INVALID | CSR_INV_VALIDATOR;

  struct Slist *orig = *(struct Slist **) var;
  if (!slist_is_member(orig, value))
    return rc | CSR_SUC_NO_CHANGE;

  struct Slist *copy = slist_dup(orig);
  slist_remove_string(copy, value);

  if (cdef->validator)
  {
    rc = cdef->validator(cdef, (intptr_t) copy, err);
    if (CSR_RESULT(rc) != CSR_SUCCESS)
    {
      slist_free(&copy);
      return rc | CSR_INV_VALIDATOR;
    }
  }

  slist_free(&orig);
  *(struct Slist **) var = copy;

  return rc;
}

/**
 * slist_has_been_set - Is the config value different to its initial value? - Implements ConfigSetType::has_been_set() - @ingroup cfg_type_has_been_set
 */
static bool slist_has_been_set(void *var, const struct ConfigDef *cdef)
{
  struct Slist *list = NULL;
  const char *initial = (const char *) cdef->initial;

  if (initial)
    list = slist_parse(initial, cdef->type);

  bool rc = !slist_equal(list, *(struct Slist **) var);
  slist_free(&list);
  return rc;
}

/**
 * slist_reset - Reset a Slist to its initial value - Implements ConfigSetType::reset() - @ingroup cfg_type_reset
 */
static int slist_reset(void *var, const struct ConfigDef *cdef, struct Buffer *err)
{
  struct Slist *list = NULL;
  const char *initial = (const char *) cdef->initial;

  if (initial)
    list = slist_parse(initial, cdef->type);

  if (slist_equal(list, *(struct Slist **) var))
  {
    slist_free(&list);
    return CSR_SUCCESS | CSR_SUC_NO_CHANGE;
  }

  if (startup_only(cdef, err))
  {
    slist_free(&list);
    return CSR_ERR_INVALID | CSR_INV_VALIDATOR;
  }

  int rc = CSR_SUCCESS;

  if (cdef->validator)
  {
    rc = cdef->validator(cdef, (intptr_t) list, err);

    if (CSR_RESULT(rc) != CSR_SUCCESS)
    {
      slist_destroy(&list, cdef);
      return rc | CSR_INV_VALIDATOR;
    }
  }

  if (!list)
    rc |= CSR_SUC_EMPTY;

  slist_destroy(var, cdef);

  *(struct Slist **) var = list;
  return rc;
}

/**
 * CstSlist - Config type representing a list of strings
 */
const struct ConfigSetType CstSlist = {
  DT_SLIST,
  "slist",
  slist_string_set,
  slist_string_get,
  slist_native_set,
  slist_native_get,
  slist_string_plus_equals,
  slist_string_minus_equals,
  slist_has_been_set,
  slist_reset,
  slist_destroy,
};
