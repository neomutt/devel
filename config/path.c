/**
 * @file
 * Type representing a path
 *
 * @authors
 * Copyright (C) 2020 Pietro Cerutti <gahr@gahr.ch>
 * Copyright (C) 2020-2025 Richard Russon <rich@flatcap.org>
 * Copyright (C) 2023 Dennis Schön <mail@dennis-schoen.de>
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
 * @page config_path Type: Path
 *
 * Config type representing a path.
 *
 * - Backed by `char *`
 * - Empty path is stored as `NULL`
 * - Validator is passed `char *`, which may be `NULL`
 * - Data is freed when `ConfigSet` is freed
 * - Implementation: #CstPath
 */

#include "config.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "mutt/lib.h"
#include "set.h"
#include "types.h"

extern char *HomeDir;

/**
 * path_tidy - Tidy a path for storage
 * @param path   Path to be tidied
 * @param is_dir Is the path a directory?
 * @retval ptr Tidy path
 *
 * Expand `~` and remove junk like `/./`
 *
 * @note The caller must free the returned string
 */
static char *path_tidy(const char *path, bool is_dir)
{
  if (!path || (*path == '\0'))
    return NULL;

  struct Buffer *buf = buf_pool_get();
  buf_strcpy(buf, path);

  mutt_path_tilde(buf, HomeDir);
  mutt_path_tidy(buf, is_dir);

  char *tidy_path = buf_strdup(buf);
  buf_pool_release(&buf);

  return tidy_path;
}

/**
 * path_destroy - Destroy a Path - Implements ConfigSetType::destroy() - @ingroup cfg_type_destroy
 */
static void path_destroy(void *var, const struct ConfigDef *cdef)
{
  const char **str = (const char **) var;
  if (!*str)
    return;

  FREE(var);
}

/**
 * path_string_set - Set a Path by string - Implements ConfigSetType::string_set() - @ingroup cfg_type_string_set
 */
static int path_string_set(void *var, struct ConfigDef *cdef, const char *value,
                           struct Buffer *err)
{
  /* Store empty paths as NULL */
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

    path_destroy(var, cdef);

    const char *str = path_tidy(value, cdef->type & D_PATH_DIR);
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
 * path_string_get - Get a Path as a string - Implements ConfigSetType::string_get() - @ingroup cfg_type_string_get
 */
static int path_string_get(void *var, const struct ConfigDef *cdef, struct Buffer *result)
{
  const char *str = NULL;

  if (var)
    str = *(const char **) var;
  else
    str = (char *) cdef->initial;

  if (!str)
    return CSR_SUCCESS | CSR_SUC_EMPTY; /* empty path */

  buf_addstr(result, str);
  return CSR_SUCCESS;
}

/**
 * path_native_set - Set a Path config item by string - Implements ConfigSetType::native_set() - @ingroup cfg_type_native_set
 */
static int path_native_set(void *var, const struct ConfigDef *cdef,
                           intptr_t value, struct Buffer *err)
{
  const char *str = (const char *) value;

  /* Store empty paths as NULL */
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

  path_destroy(var, cdef);

  str = path_tidy(str, cdef->type & D_PATH_DIR);
  rc = CSR_SUCCESS;
  if (!str)
    rc |= CSR_SUC_EMPTY;

  *(const char **) var = str;
  return rc;
}

/**
 * path_native_get - Get a string from a Path config item - Implements ConfigSetType::native_get() - @ingroup cfg_type_native_get
 */
static intptr_t path_native_get(void *var, const struct ConfigDef *cdef, struct Buffer *err)
{
  const char *str = *(const char **) var;

  return (intptr_t) str;
}

/**
 * path_has_been_set - Is the config value different to its initial value? - Implements ConfigSetType::has_been_set() - @ingroup cfg_type_has_been_set
 */
static bool path_has_been_set(void *var, const struct ConfigDef *cdef)
{
  const char *initial = path_tidy((const char *) cdef->initial, cdef->type & D_PATH_DIR);
  const char *value = *(const char **) var;

  bool rc = !mutt_str_equal(initial, value);
  FREE(&initial);
  return rc;
}

/**
 * path_reset - Reset a Path to its initial value - Implements ConfigSetType::reset() - @ingroup cfg_type_reset
 */
static int path_reset(void *var, const struct ConfigDef *cdef, struct Buffer *err)
{
  int rc = CSR_SUCCESS;

  const char *str = path_tidy((const char *) cdef->initial, cdef->type & D_PATH_DIR);
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

  path_destroy(var, cdef);

  if (!str)
    rc |= CSR_SUC_EMPTY;

  *(const char **) var = str;
  return rc;
}

/**
 * CstPath - Config type representing a path
 */
const struct ConfigSetType CstPath = {
  DT_PATH,
  "path",
  path_string_set,
  path_string_get,
  path_native_set,
  path_native_get,
  NULL, // string_plus_equals
  NULL, // string_minus_equals
  path_has_been_set,
  path_reset,
  path_destroy,
};
