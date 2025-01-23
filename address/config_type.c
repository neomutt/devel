/**
 * @file
 * Config type representing an email address
 *
 * @authors
 * Copyright (C) 2017-2025 Richard Russon <rich@flatcap.org>
 * Copyright (C) 2019-2023 Pietro Cerutti <gahr@gahr.ch>
 * Copyright (C) 2023 Dennis Schön <mail@dennis-schoen.de>
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
 * @page addr_config_type Config type: Email address
 *
 * Config type representing an email address.
 *
 * - Backed by `struct Address`
 * - Empty address is stored as `NULL`
 * - Validator is passed `struct Address *`, which may be `NULL`
 * - Data is freed when `ConfigSet` is freed
 * - Implementation: #CstAddress
 */

#include "config.h"
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "mutt/lib.h"
#include "config/lib.h"
#include "config_type.h"
#include "address.h"

/**
 * address_new - Create an Address from a string
 * @param addr Email address to parse
 * @retval ptr New Address object
 */
struct Address *address_new(const char *addr)
{
  struct Address *a = MUTT_MEM_CALLOC(1, struct Address);
  a->mailbox = buf_new(addr);
  return a;
}

/**
 * address_destroy - Destroy an Address object - Implements ConfigSetType::destroy() - @ingroup cfg_type_destroy
 */
static void address_destroy(void *var, const struct ConfigDef *cdef)
{
  struct Address **a = var;
  if (!*a)
    return;

  mutt_addr_free(a);
}

/**
 * address_string_set - Set an Address by string - Implements ConfigSetType::string_set() - @ingroup cfg_type_string_set
 */
static int address_string_set(void *var, struct ConfigDef *cdef,
                              const char *value, struct Buffer *err)
{
  /* Store empty address as NULL */
  if (value && (value[0] == '\0'))
    value = NULL;

  struct Address *addr = NULL;

  int rc = CSR_SUCCESS;

  if (!value && (cdef->type & D_NOT_EMPTY))
  {
    buf_printf(err, _("Option %s may not be empty"), cdef->name);
    return CSR_ERR_INVALID | CSR_INV_VALIDATOR;
  }

  if (var && value)
  {
    // TODO - config can only store one
    struct AddressList al = TAILQ_HEAD_INITIALIZER(al);
    mutt_addrlist_parse(&al, value);
    addr = mutt_addr_copy(TAILQ_FIRST(&al));
    mutt_addrlist_clear(&al);
  }

  if (var)
  {
    if (cdef->validator)
    {
      rc = cdef->validator(cdef, (intptr_t) addr, err);

      if (CSR_RESULT(rc) != CSR_SUCCESS)
      {
        address_destroy(&addr, cdef);
        return rc | CSR_INV_VALIDATOR;
      }
    }

    /* ordinary variable setting */
    address_destroy(var, cdef);

    *(struct Address **) var = addr;

    if (!addr)
      rc |= CSR_SUC_EMPTY;
  }
  else
  {
    /* set the default/initial value */
    if (cdef->type & D_INTERNAL_INITIAL_SET)
      FREE(&cdef->initial);

    cdef->type |= D_INTERNAL_INITIAL_SET;
    cdef->initial = (intptr_t) mutt_str_dup(value);
  }

  return rc;
}

/**
 * address_string_get - Get an Address as a string - Implements ConfigSetType::string_get() - @ingroup cfg_type_string_get
 */
static int address_string_get(void *var, const struct ConfigDef *cdef, struct Buffer *result)
{
  if (var)
  {
    struct Address *a = *(struct Address **) var;
    if (a)
    {
      mutt_addr_write(result, a, false);
    }
  }
  else
  {
    buf_addstr(result, (char *) cdef->initial);
  }

  if (buf_is_empty(result))
    return CSR_SUCCESS | CSR_SUC_EMPTY; /* empty string */

  return CSR_SUCCESS;
}

/**
 * address_dup - Create a copy of an Address object
 * @param addr Address to duplicate
 * @retval ptr New Address object
 */
static struct Address *address_dup(struct Address *addr)
{
  if (!addr)
    return NULL; /* LCOV_EXCL_LINE */

  struct Address *a = MUTT_MEM_CALLOC(1, struct Address);
  a->personal = buf_dup(addr->personal);
  a->mailbox = buf_dup(addr->mailbox);
  return a;
}

/**
 * address_native_set - Set an Address config item by Address object - Implements ConfigSetType::native_set() - @ingroup cfg_type_native_set
 */
static int address_native_set(void *var, const struct ConfigDef *cdef,
                              intptr_t value, struct Buffer *err)
{
  int rc;

  if (cdef->validator)
  {
    rc = cdef->validator(cdef, value, err);

    if (CSR_RESULT(rc) != CSR_SUCCESS)
      return rc | CSR_INV_VALIDATOR;
  }

  mutt_addr_free(var);

  struct Address *addr = address_dup((struct Address *) value);

  rc = CSR_SUCCESS;
  if (!addr)
    rc |= CSR_SUC_EMPTY;

  *(struct Address **) var = addr;
  return rc;
}

/**
 * address_native_get - Get an Address object from an Address config item - Implements ConfigSetType::native_get() - @ingroup cfg_type_native_get
 */
static intptr_t address_native_get(void *var, const struct ConfigDef *cdef, struct Buffer *err)
{
  struct Address *addr = *(struct Address **) var;

  return (intptr_t) addr;
}

/**
 * address_has_been_set - Is the config value different to its initial value? - Implements ConfigSetType::has_been_set() - @ingroup cfg_type_has_been_set
 */
static bool address_has_been_set(void *var, const struct ConfigDef *cdef)
{
  struct Buffer *value = buf_pool_get();
  struct Address *a = *(struct Address **) var;
  if (a)
    mutt_addr_write(value, a, false);

  const char *initial = (const char *) cdef->initial;

  bool rc = !mutt_str_equal(initial, buf_string(value));
  buf_pool_release(&value);
  return rc;
}

/**
 * address_reset - Reset an Address to its initial value - Implements ConfigSetType::reset() - @ingroup cfg_type_reset
 */
static int address_reset(void *var, const struct ConfigDef *cdef, struct Buffer *err)
{
  struct Address *a = NULL;
  const char *initial = (const char *) cdef->initial;

  if (initial)
    a = address_new(initial);

  int rc = CSR_SUCCESS;

  if (cdef->validator)
  {
    rc = cdef->validator(cdef, (intptr_t) a, err);

    if (CSR_RESULT(rc) != CSR_SUCCESS)
    {
      address_destroy(&a, cdef);
      return rc | CSR_INV_VALIDATOR;
    }
  }

  if (!a)
    rc |= CSR_SUC_EMPTY;

  address_destroy(var, cdef);

  *(struct Address **) var = a;
  return rc;
}

/**
 * CstAddress - Config type representing an Email Address
 */
const struct ConfigSetType CstAddress = {
  DT_ADDRESS,
  "address",
  address_string_set,
  address_string_get,
  address_native_set,
  address_native_get,
  NULL, // string_plus_equals
  NULL, // string_minus_equals
  address_has_been_set,
  address_reset,
  address_destroy,
};

/**
 * cs_subset_address - Get an Address config item by name
 * @param sub   Config Subset
 * @param name  Name of config item
 * @retval ptr  Address
 * @retval NULL Empty address
 */
const struct Address *cs_subset_address(const struct ConfigSubset *sub, const char *name)
{
  ASSERT(sub && name);

  struct HashElem *he = cs_subset_create_inheritance(sub, name);
  ASSERT(he);

#ifndef NDEBUG
  struct HashElem *he_base = cs_get_base(he);
  ASSERT(CONFIG_TYPE(he_base->type) == DT_ADDRESS);
#endif

  intptr_t value = cs_subset_he_native_get(sub, he, NULL);
  ASSERT(value != INT_MIN);

  return (const struct Address *) value;
}
