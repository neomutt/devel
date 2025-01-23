/**
 * @file
 * Type representing a multibyte character table
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
 * @page config_mbtable Type: Multi-byte character table
 *
 * Config type representing a multibyte character table.
 *
 * - Backed by `struct MbTable`
 * - Empty multibyte character table is stored as `NULL`
 * - Validator is passed `struct MbTable`, which may be `NULL`
 * - Data is freed when `ConfigSet` is freed
 * - Implementation: #CstMbtable
 */

#include "config.h"
#include <stdint.h>
#include <string.h>
#include <wchar.h>
#include "mutt/lib.h"
#include "mbtable.h"
#include "set.h"
#include "types.h"

/**
 * mbtable_equal - Compare two MbTables
 * @param a First MbTable
 * @param b Second MbTable
 * @retval true They are identical
 */
bool mbtable_equal(const struct MbTable *a, const struct MbTable *b)
{
  if (!a && !b) /* both empty */
    return true;
  if (!a ^ !b) /* one is empty, but not the other */
    return false;

  return mutt_str_equal(a->orig_str, b->orig_str);
}

/**
 * mbtable_parse - Parse a multibyte string into a table
 * @param s String of multibyte characters
 * @retval ptr New MbTable object
 */
struct MbTable *mbtable_parse(const char *s)
{
  struct MbTable *t = NULL;
  size_t slen, k;
  mbstate_t mbstate = { 0 };
  char *d = NULL;

  slen = mutt_str_len(s);
  if (!slen)
    return NULL;

  t = MUTT_MEM_CALLOC(1, struct MbTable);

  t->orig_str = mutt_str_dup(s);
  /* This could be more space efficient.  However, being used on tiny
   * strings (`$to_chars` and `$status_chars`), the overhead is not great. */
  t->chars = MUTT_MEM_CALLOC(slen, char *);
  t->segmented_str = MUTT_MEM_CALLOC(slen * 2, char);
  d = t->segmented_str;

  while (slen && (k = mbrtowc(NULL, s, slen, &mbstate)))
  {
    if ((k == ICONV_ILLEGAL_SEQ) || (k == ICONV_BUF_TOO_SMALL))
    {
      /* XXX put message in err buffer; fail? warning? */
      mutt_debug(LL_DEBUG1, "mbrtowc returned %zd converting %s in %s\n", k, s, t->orig_str);
      if (k == ICONV_ILLEGAL_SEQ)
        memset(&mbstate, 0, sizeof(mbstate));
      k = (k == ICONV_ILLEGAL_SEQ) ? 1 : slen;
    }

    slen -= k;
    t->chars[t->len++] = d;
    while (k-- > 0)
      *d++ = *s++;
    *d++ = '\0';
  }

  return t;
}

/**
 * mbtable_destroy - Destroy an MbTable object - Implements ConfigSetType::destroy() - @ingroup cfg_type_destroy
 */
static void mbtable_destroy(void *var, const struct ConfigDef *cdef)
{
  struct MbTable **m = var;
  if (!*m)
    return;

  mbtable_free(m);
}

/**
 * mbtable_string_set - Set an MbTable by string - Implements ConfigSetType::string_set() - @ingroup cfg_type_string_set
 */
static int mbtable_string_set(void *var, struct ConfigDef *cdef,
                              const char *value, struct Buffer *err)
{
  /* Store empty mbtables as NULL */
  if (value && (value[0] == '\0'))
    value = NULL;

  struct MbTable *table = NULL;

  int rc = CSR_SUCCESS;

  if (var)
  {
    struct MbTable *curval = *(struct MbTable **) var;
    if (curval && mutt_str_equal(value, curval->orig_str))
      return CSR_SUCCESS | CSR_SUC_NO_CHANGE;

    if (startup_only(cdef, err))
      return CSR_ERR_INVALID | CSR_INV_VALIDATOR;

    table = mbtable_parse(value);

    if (cdef->validator)
    {
      rc = cdef->validator(cdef, (intptr_t) table, err);

      if (CSR_RESULT(rc) != CSR_SUCCESS)
      {
        mbtable_free(&table);
        return rc | CSR_INV_VALIDATOR;
      }
    }

    mbtable_destroy(var, cdef);

    *(struct MbTable **) var = table;

    if (!table)
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
 * mbtable_string_get - Get a MbTable as a string - Implements ConfigSetType::string_get() - @ingroup cfg_type_string_get
 */
static int mbtable_string_get(void *var, const struct ConfigDef *cdef, struct Buffer *result)
{
  const char *str = NULL;

  if (var)
  {
    struct MbTable *table = *(struct MbTable **) var;
    if (!table || !table->orig_str)
      return CSR_SUCCESS | CSR_SUC_EMPTY; /* empty string */
    str = table->orig_str;
  }
  else
  {
    str = (char *) cdef->initial;
  }

  buf_addstr(result, str);
  return CSR_SUCCESS;
}

/**
 * mbtable_dup - Create a copy of an MbTable object
 * @param table MbTable to duplicate
 * @retval ptr New MbTable object
 */
static struct MbTable *mbtable_dup(struct MbTable *table)
{
  if (!table)
    return NULL; /* LCOV_EXCL_LINE */

  struct MbTable *m = MUTT_MEM_CALLOC(1, struct MbTable);
  m->orig_str = mutt_str_dup(table->orig_str);
  return m;
}

/**
 * mbtable_native_set - Set an MbTable config item by MbTable object - Implements ConfigSetType::native_set() - @ingroup cfg_type_native_set
 */
static int mbtable_native_set(void *var, const struct ConfigDef *cdef,
                              intptr_t value, struct Buffer *err)
{
  int rc;

  if (mbtable_equal(*(struct MbTable **) var, (struct MbTable *) value))
    return CSR_SUCCESS | CSR_SUC_NO_CHANGE;

  if (startup_only(cdef, err))
    return CSR_ERR_INVALID | CSR_INV_VALIDATOR;

  if (cdef->validator)
  {
    rc = cdef->validator(cdef, value, err);

    if (CSR_RESULT(rc) != CSR_SUCCESS)
      return rc | CSR_INV_VALIDATOR;
  }

  mbtable_free(var);

  struct MbTable *table = mbtable_dup((struct MbTable *) value);

  rc = CSR_SUCCESS;
  if (!table)
    rc |= CSR_SUC_EMPTY;

  *(struct MbTable **) var = table;
  return rc;
}

/**
 * mbtable_native_get - Get an MbTable object from a MbTable config item - Implements ConfigSetType::native_get() - @ingroup cfg_type_native_get
 */
static intptr_t mbtable_native_get(void *var, const struct ConfigDef *cdef, struct Buffer *err)
{
  struct MbTable *table = *(struct MbTable **) var;

  return (intptr_t) table;
}

/**
 * mbtable_has_been_set - Is the config value different to its initial value? - Implements ConfigSetType::has_been_set() - @ingroup cfg_type_has_been_set
 */
static bool mbtable_has_been_set(void *var, const struct ConfigDef *cdef)
{
  const char *initial = (const char *) cdef->initial;

  struct MbTable *table = *(struct MbTable **) var;
  const char *table_str = table ? table->orig_str : NULL;

  return !mutt_str_equal(initial, table_str);
}

/**
 * mbtable_reset - Reset an MbTable to its initial value - Implements ConfigSetType::reset() - @ingroup cfg_type_reset
 */
static int mbtable_reset(void *var, const struct ConfigDef *cdef, struct Buffer *err)
{
  struct MbTable *table = NULL;
  const char *initial = (const char *) cdef->initial;

  struct MbTable *curtable = *(struct MbTable **) var;
  const char *curval = curtable ? curtable->orig_str : NULL;

  int rc = CSR_SUCCESS;
  if (!curtable)
    rc |= CSR_SUC_EMPTY;

  if (mutt_str_equal(initial, curval))
    return rc | CSR_SUC_NO_CHANGE;

  if (startup_only(cdef, err))
    return CSR_ERR_INVALID | CSR_INV_VALIDATOR;

  if (initial)
    table = mbtable_parse(initial);

  if (cdef->validator)
  {
    rc = cdef->validator(cdef, (intptr_t) table, err);

    if (CSR_RESULT(rc) != CSR_SUCCESS)
    {
      mbtable_destroy(&table, cdef);
      return rc | CSR_INV_VALIDATOR;
    }
  }

  if (!table)
    rc |= CSR_SUC_EMPTY;

  mbtable_destroy(var, cdef);

  *(struct MbTable **) var = table;
  return rc;
}

/**
 * mbtable_free - Free an MbTable object
 * @param[out] ptr MbTable to free
 */
void mbtable_free(struct MbTable **ptr)
{
  if (!ptr || !*ptr)
    return;

  struct MbTable *table = *ptr;
  FREE(&table->orig_str);
  FREE(&table->chars);
  FREE(&table->segmented_str);

  FREE(ptr);
}

/**
 * mbtable_get_nth_wchar - Extract one char from a multi-byte table
 * @param table  Multi-byte table
 * @param index  Select this character
 * @retval ptr String pointer to the character
 *
 * Extract one multi-byte character from a string table.
 * If the index is invalid, then a space character will be returned.
 * If the character selected is '\n' (Ctrl-M), then "" will be returned.
 */
const char *mbtable_get_nth_wchar(const struct MbTable *table, int index)
{
  if (!table || !table->chars || (index < 0) || (index >= table->len))
    return " ";

  if (table->chars[index][0] == '\r')
    return "";

  return table->chars[index];
}

/**
 * CstMbtable - Config type representing a multi-byte table
 */
const struct ConfigSetType CstMbtable = {
  DT_MBTABLE,
  "mbtable",
  mbtable_string_set,
  mbtable_string_get,
  mbtable_native_set,
  mbtable_native_get,
  NULL, // string_plus_equals
  NULL, // string_minus_equals
  mbtable_has_been_set,
  mbtable_reset,
  mbtable_destroy,
};
