/**
 * @file
 * Type representing a regular expression
 *
 * @authors
 * Copyright (C) 2017-2025 Richard Russon <rich@flatcap.org>
 * Copyright (C) 2020 Pietro Cerutti <gahr@gahr.ch>
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
 * @page config_regex Type: Regular expression
 *
 * Config type representing a regular expression.
 *
 * - Backed by `struct Regex`
 * - Empty regular expression is stored as `NULL`
 * - Validator is passed `struct Regex`, which may be `NULL`
 * - Data is freed when `ConfigSet` is freed
 * - Implementation: #CstRegex
 */

#include "config.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "mutt/lib.h"
#include "regex2.h"
#include "set.h"
#include "types.h"

/**
 * regex_equal - Compare two regexes
 * @param a First regex
 * @param b Second regex
 * @retval true They are identical
 */
bool regex_equal(const struct Regex *a, const struct Regex *b)
{
  if (!a && !b) /* both empty */
    return true;
  if (!a ^ !b) /* one is empty, but not the other */
    return false;
  if (a->pat_not != b->pat_not)
    return false;

  return mutt_str_equal(a->pattern, b->pattern);
}

/**
 * regex_free - Free a Regex object
 * @param[out] ptr Regex to free
 */
void regex_free(struct Regex **ptr)
{
  if (!ptr || !*ptr)
    return;

  struct Regex *rx = *ptr;
  FREE(&rx->pattern);
  if (rx->regex)
    regfree(rx->regex);
  FREE(&rx->regex);

  FREE(ptr);
}

/**
 * regex_destroy - Destroy a Regex object - Implements ConfigSetType::destroy() - @ingroup cfg_type_destroy
 */
static void regex_destroy(void *var, const struct ConfigDef *cdef)
{
  struct Regex **r = var;
  if (!*r)
    return;

  regex_free(r);
}

/**
 * regex_new - Create an Regex from a string
 * @param str   Regular expression
 * @param flags Type flags, e.g. #D_REGEX_MATCH_CASE
 * @param err   Buffer for error messages
 * @retval ptr New Regex object
 * @retval NULL Error
 */
struct Regex *regex_new(const char *str, uint32_t flags, struct Buffer *err)
{
  if (!str)
    return NULL;

  int rflags = 0;
  struct Regex *reg = MUTT_MEM_CALLOC(1, struct Regex);

  reg->regex = MUTT_MEM_CALLOC(1, regex_t);
  reg->pattern = mutt_str_dup(str);

  /* Should we use smart case matching? */
  if (((flags & D_REGEX_MATCH_CASE) == 0) && mutt_mb_is_lower(str))
    rflags |= REG_ICASE;

  if ((flags & D_REGEX_NOSUB))
    rflags |= REG_NOSUB;

  /* Is a prefix of '!' allowed? */
  if (((flags & D_REGEX_ALLOW_NOT) != 0) && (str[0] == '!'))
  {
    reg->pat_not = true;
    str++;
  }

  int rc = REG_COMP(reg->regex, str, rflags);
  if (rc != 0)
  {
    if (err)
      regerror(rc, reg->regex, err->data, err->dsize);
    regex_free(&reg);
    return NULL;
  }

  return reg;
}

/**
 * regex_string_set - Set a Regex by string - Implements ConfigSetType::string_set() - @ingroup cfg_type_string_set
 */
static int regex_string_set(void *var, struct ConfigDef *cdef,
                            const char *value, struct Buffer *err)
{
  /* Store empty regexes as NULL */
  if (value && (value[0] == '\0'))
    value = NULL;

  struct Regex *r = NULL;

  int rc = CSR_SUCCESS;

  if (var)
  {
    struct Regex *curval = *(struct Regex **) var;
    if (curval && mutt_str_equal(value, curval->pattern))
      return CSR_SUCCESS | CSR_SUC_NO_CHANGE;

    if (startup_only(cdef, err))
      return CSR_ERR_INVALID | CSR_INV_VALIDATOR;

    if (value)
    {
      r = regex_new(value, cdef->type, err);
      if (!r)
        return CSR_ERR_INVALID;
    }

    if (cdef->validator)
    {
      rc = cdef->validator(cdef, (intptr_t) r, err);

      if (CSR_RESULT(rc) != CSR_SUCCESS)
      {
        regex_free(&r);
        return rc | CSR_INV_VALIDATOR;
      }
    }

    regex_destroy(var, cdef);

    *(struct Regex **) var = r;

    if (!r)
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
 * regex_string_get - Get a Regex as a string - Implements ConfigSetType::string_get() - @ingroup cfg_type_string_get
 */
static int regex_string_get(void *var, const struct ConfigDef *cdef, struct Buffer *result)
{
  const char *str = NULL;

  if (var)
  {
    struct Regex *r = *(struct Regex **) var;
    if (r)
      str = r->pattern;
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
 * regex_native_set - Set a Regex config item by Regex object - Implements ConfigSetType::native_set() - @ingroup cfg_type_native_set
 */
static int regex_native_set(void *var, const struct ConfigDef *cdef,
                            intptr_t value, struct Buffer *err)
{
  int rc;

  if (regex_equal(*(struct Regex **) var, (struct Regex *) value))
    return CSR_SUCCESS | CSR_SUC_NO_CHANGE;

  if (startup_only(cdef, err))
    return CSR_ERR_INVALID | CSR_INV_VALIDATOR;

  if (cdef->validator)
  {
    rc = cdef->validator(cdef, value, err);

    if (CSR_RESULT(rc) != CSR_SUCCESS)
      return rc | CSR_INV_VALIDATOR;
  }

  rc = CSR_SUCCESS;
  struct Regex *orig = (struct Regex *) value;
  struct Regex *r = NULL;

  if (orig && orig->pattern)
  {
    const uint32_t flags = orig->pat_not ? D_REGEX_ALLOW_NOT : 0;
    r = regex_new(orig->pattern, flags, err);
    if (!r)
      rc = CSR_ERR_INVALID;
  }
  else
  {
    rc |= CSR_SUC_EMPTY;
  }

  if (CSR_RESULT(rc) == CSR_SUCCESS)
  {
    regex_free(var);
    *(struct Regex **) var = r;
  }

  return rc;
}

/**
 * regex_native_get - Get a Regex object from a Regex config item - Implements ConfigSetType::native_get() - @ingroup cfg_type_native_get
 */
static intptr_t regex_native_get(void *var, const struct ConfigDef *cdef, struct Buffer *err)
{
  struct Regex *r = *(struct Regex **) var;

  return (intptr_t) r;
}

/**
 * regex_has_been_set - Is the config value different to its initial value? - Implements ConfigSetType::has_been_set() - @ingroup cfg_type_has_been_set
 */
static bool regex_has_been_set(void *var, const struct ConfigDef *cdef)
{
  const char *initial = (const char *) cdef->initial;

  struct Regex *currx = *(struct Regex **) var;
  const char *curval = currx ? currx->pattern : NULL;

  return !mutt_str_equal(initial, curval);
}

/**
 * regex_reset - Reset a Regex to its initial value - Implements ConfigSetType::reset() - @ingroup cfg_type_reset
 */
static int regex_reset(void *var, const struct ConfigDef *cdef, struct Buffer *err)
{
  struct Regex *r = NULL;
  const char *initial = (const char *) cdef->initial;

  struct Regex *currx = *(struct Regex **) var;
  const char *curval = currx ? currx->pattern : NULL;

  int rc = CSR_SUCCESS;
  if (!currx)
    rc |= CSR_SUC_EMPTY;

  if (mutt_str_equal(initial, curval))
    return rc | CSR_SUC_NO_CHANGE;

  if (startup_only(cdef, err))
    return CSR_ERR_INVALID | CSR_INV_VALIDATOR;

  if (initial)
  {
    r = regex_new(initial, cdef->type, err);
    if (!r)
      return CSR_ERR_CODE;
  }

  if (cdef->validator)
  {
    rc = cdef->validator(cdef, (intptr_t) r, err);

    if (CSR_RESULT(rc) != CSR_SUCCESS)
    {
      regex_destroy(&r, cdef);
      return rc | CSR_INV_VALIDATOR;
    }
  }

  if (!r)
    rc |= CSR_SUC_EMPTY;

  regex_destroy(var, cdef);

  *(struct Regex **) var = r;
  return rc;
}

/**
 * CstRegex - Config type representing a regular expression
 */
const struct ConfigSetType CstRegex = {
  DT_REGEX,
  "regex",
  regex_string_set,
  regex_string_get,
  regex_native_set,
  regex_native_get,
  NULL, // string_plus_equals
  NULL, // string_minus_equals
  regex_has_been_set,
  regex_reset,
  regex_destroy,
};
