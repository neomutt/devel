/**
 * @file
 * A collection of config items
 *
 * @authors
 * Copyright (C) 2017-2025 Richard Russon <rich@flatcap.org>
 * Copyright (C) 2020 Pietro Cerutti <gahr@gahr.ch>
 * Copyright (C) 2023 Rayford Shireman
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
 * @page config_set Config Set
 *
 * A collection of config items.
 */

#include "config.h"
#include <limits.h>
#include <stdio.h>
#include "mutt/lib.h"
#include "set.h"
#include "inheritance.h"
#include "types.h"

/**
 * cs_hashelem_free - Free our hash table data - Implements ::hash_hdata_free_t - @ingroup hash_hdata_free_api
 * @param type Object type, e.g. #DT_STRING
 * @param obj  Object to destroy
 * @param data ConfigSet associated with the object
 */
static void cs_hashelem_free(int type, void *obj, intptr_t data)
{
  if (data == 0)
    return; /* LCOV_EXCL_LINE */

  struct ConfigSet *cs = (struct ConfigSet *) data;

  const struct ConfigSetType *cst = NULL;

  if (type & D_INTERNAL_INHERITED)
  {
    struct Inheritance *i = obj;

    struct HashElem *he_base = cs_get_base(i->parent);
    struct ConfigDef *cdef = he_base->data;

    if (!cdef)
      return; // LCOV_EXCL_LINE

    cst = cs_get_type_def(cs, he_base->type);
    if (cst && cst->destroy)
      cst->destroy((void **) &i->var, cdef);

    FREE(&i->name);
    FREE(&i);
  }
  else
  {
    struct ConfigDef *cdef = obj;

    cst = cs_get_type_def(cs, type);
    if (cst && cst->destroy)
      cst->destroy(&cdef->var, cdef);

    /* If we allocated the initial value, clean it up */
    if (cdef->type & D_INTERNAL_INITIAL_SET)
      FREE(&cdef->initial);
    if (cdef->type & D_INTERNAL_FREE_CONFIGDEF)
    {
      FREE(&cdef->name);
      FREE(&cdef->docs);
      FREE(&cdef);
    }
  }
}

/**
 * create_synonym - Create an alternative name for a config item
 * @param cs   Config items
 * @param cdef Variable definition
 * @param err  Buffer for error messages
 * @retval ptr New HashElem representing the config item synonym
 */
static struct HashElem *create_synonym(const struct ConfigSet *cs,
                                       struct ConfigDef *cdef, struct Buffer *err)
{
  if (!cs || !cdef)
    return NULL; /* LCOV_EXCL_LINE */

  const char *name = (const char *) cdef->initial;
  struct HashElem *he_parent = cs_get_elem(cs, name);
  if (!he_parent)
  {
    buf_printf(err, _("Unknown option %s"), name);
    return NULL;
  }

  struct HashElem *he_child = mutt_hash_typed_insert(cs->hash, cdef->name,
                                                     cdef->type, (void *) cdef);
  if (!he_child)
    return NULL; /* LCOV_EXCL_LINE */

  cdef->var = (intptr_t) he_parent;
  return he_child;
}

/**
 * cs_new - Create a new Config Set
 * @param size Number of expected config items
 * @retval ptr New ConfigSet object
 */
struct ConfigSet *cs_new(size_t size)
{
  struct ConfigSet *cs = MUTT_MEM_CALLOC(1, struct ConfigSet);

  cs->hash = mutt_hash_new(size, MUTT_HASH_NO_FLAGS);
  mutt_hash_set_destructor(cs->hash, cs_hashelem_free, (intptr_t) cs);

  return cs;
}

/**
 * cs_free - Free a Config Set
 * @param[out] ptr Config items
 */
void cs_free(struct ConfigSet **ptr)
{
  if (!ptr || !*ptr)
    return;

  struct ConfigSet *cs = *ptr;

  mutt_hash_free(&cs->hash);
  FREE(ptr);
}

/**
 * cs_get_base - Find the root Config Item
 * @param he Config Item to examine
 * @retval ptr Root Config Item
 *
 * Given an inherited HashElem, find the HashElem representing the original
 * Config Item.
 */
struct HashElem *cs_get_base(struct HashElem *he)
{
  if (!(he->type & D_INTERNAL_INHERITED))
    return he;

  struct Inheritance *i = he->data;
  return cs_get_base(i->parent);
}

/**
 * cs_get_elem - Get the HashElem representing a config item
 * @param cs   Config items
 * @param name Name of config item
 * @retval ptr HashElem representing the config item
 */
struct HashElem *cs_get_elem(const struct ConfigSet *cs, const char *name)
{
  if (!cs || !name)
    return NULL;

  struct HashElem *he = mutt_hash_find_elem(cs->hash, name);
  if (!he)
    return NULL;

  if (CONFIG_TYPE(he->type) != DT_SYNONYM)
    return he;

  const struct ConfigDef *cdef = he->data;

  return (struct HashElem *) cdef->var;
}

/**
 * cs_get_type_def - Get the definition for a type
 * @param cs   Config items
 * @param type Type to lookup, e.g. #DT_NUMBER
 * @retval ptr ConfigSetType representing the type
 */
const struct ConfigSetType *cs_get_type_def(const struct ConfigSet *cs, unsigned int type)
{
  if (!cs)
    return NULL;

  type = CONFIG_TYPE(type);
  if (type >= mutt_array_size(cs->types))
    return NULL; // LCOV_EXCL_LINE

  if (!cs->types[type].name)
    return NULL;

  return &cs->types[type];
}

/**
 * cs_register_type - Register a type of config item
 * @param cs   Config items
 * @param cst  Structure defining the type
 * @retval true Type was registered successfully
 */
bool cs_register_type(struct ConfigSet *cs, const struct ConfigSetType *cst)
{
  if (!cs || !cst)
    return false;

  if (!cst->name || !cst->string_set || !cst->string_get || !cst->reset ||
      !cst->native_set || !cst->native_get)
  {
    return false;
  }

  if (cst->type >= mutt_array_size(cs->types))
    return false;

  if (cs->types[cst->type].name)
    return false; /* already registered */

  cs->types[cst->type] = *cst;
  return true;
}

/**
 * cs_register_variable - Register one config item
 * @param cs   Config items
 * @param cdef Variable definition
 * @param err  Buffer for error messages
 * @retval ptr New HashElem representing the config item
 *
 * Similar to cs_create_variable() but assumes that cdef lives indefinitely.
 */
struct HashElem *cs_register_variable(const struct ConfigSet *cs,
                                      struct ConfigDef *cdef, struct Buffer *err)
{
  if (!cs || !cdef)
    return NULL; /* LCOV_EXCL_LINE */

  if (CONFIG_TYPE(cdef->type) == DT_SYNONYM)
    return create_synonym(cs, cdef, err);

  const struct ConfigSetType *cst = cs_get_type_def(cs, cdef->type);
  if (!cst)
  {
    buf_printf(err, _("Option %s has an invalid type %d"), cdef->name, cdef->type);
    return NULL;
  }

  struct HashElem *he = mutt_hash_typed_insert(cs->hash, cdef->name, cdef->type, cdef);
  if (!he)
    return NULL; /* LCOV_EXCL_LINE */

  // Temporarily disable the validator
  // (trust that the hard-coded initial values are sane)
  int (*validator)(const struct ConfigDef *cdef, intptr_t value,
                   struct Buffer *err) = cdef->validator;
  cdef->validator = NULL;

  if (cst->reset)
    cst->reset(&cdef->var, cdef, err);

  cdef->validator = validator;

  return he;
}

/**
 * cs_register_variables - Register a set of config items
 * @param cs    Config items
 * @param vars  Variable definition
 * @retval true All variables were registered successfully
 */
bool cs_register_variables(const struct ConfigSet *cs, struct ConfigDef vars[])
{
  if (!cs || !vars)
    return false;

  struct Buffer *err = buf_pool_get();

  bool rc = true;

  for (size_t i = 0; vars[i].name; i++)
  {
    if (!cs_register_variable(cs, &vars[i], err))
    {
      mutt_debug(LL_DEBUG1, "%s\n", buf_string(err));
      rc = false;
    }
  }

  buf_pool_release(&err);
  return rc;
}

/**
 * cs_create_variable - Create and register one config item
 * @param cs   Config items
 * @param cdef Variable definition
 * @param err  Buffer for error messages
 * @retval ptr New HashElem representing the config item
 *
 * Similar to cs_register_variable() but copies the ConfigDef first.  Allowing
 * the caller to free it and its parts afterwards.
 *
 * This function does not know anything about how the internal representation
 * of the type must be handled.  Thus, the fields 'initial', 'data', 'var' must
 * be copyable.  If they need allocation, then the caller must set them after
 * the variable is created, e.g. with cs_he_initial_set(), cs_he_native_set.
 */
struct HashElem *cs_create_variable(const struct ConfigSet *cs,
                                    struct ConfigDef *cdef, struct Buffer *err)
{
  struct ConfigDef *cdef_copy = MUTT_MEM_CALLOC(1, struct ConfigDef);
  cdef_copy->name = mutt_str_dup(cdef->name);
  cdef_copy->type = cdef->type | D_INTERNAL_FREE_CONFIGDEF;
  cdef_copy->initial = cdef->initial;
  cdef_copy->data = cdef->data;
  cdef_copy->validator = cdef->validator;
  cdef_copy->docs = mutt_str_dup(cdef->name);
  cdef_copy->var = cdef->var;

  struct HashElem *he = cs_register_variable(cs, cdef_copy, err);
  if (!he)
  {
    FREE(&cdef_copy->name);
    FREE(&cdef_copy->docs);
    FREE(&cdef_copy);
  }
  return he;
}

/**
 * cs_inherit_variable - Create in inherited config item
 * @param cs        Config items
 * @param he_parent HashElem of parent config item
 * @param name      Name of account-specific config item
 * @retval ptr New HashElem representing the inherited config item
 */
struct HashElem *cs_inherit_variable(const struct ConfigSet *cs,
                                     struct HashElem *he_parent, const char *name)
{
  if (!cs || !he_parent)
    return NULL;

  /* MyVars cannot be inherited, as they might get deleted */
  if (CONFIG_TYPE(he_parent->type) == DT_MYVAR)
    return NULL;

  struct Inheritance *i = MUTT_MEM_CALLOC(1, struct Inheritance);
  i->parent = he_parent;
  i->name = mutt_str_dup(name);

  struct HashElem *he = mutt_hash_typed_insert(cs->hash, i->name, D_INTERNAL_INHERITED, i);
  if (!he)
  {
    FREE(&i->name);
    FREE(&i);
  }

  return he;
}

/**
 * cs_uninherit_variable - Remove an inherited config item
 * @param cs   Config items
 * @param name Name of config item to remove
 */
void cs_uninherit_variable(const struct ConfigSet *cs, const char *name)
{
  if (!cs || !name)
    return;

  mutt_hash_delete(cs->hash, name, NULL);
}

/**
 * cs_he_reset - Reset a config item to its initial value
 * @param cs   Config items
 * @param he   HashElem representing config item
 * @param err  Buffer for error messages
 * @retval num Result, e.g. #CSR_SUCCESS
 */
int cs_he_reset(const struct ConfigSet *cs, struct HashElem *he, struct Buffer *err)
{
  if (!cs || !he)
    return CSR_ERR_CODE;

  /* An inherited var that's already pointing to its parent.
   * Return 'success', but don't send a notification. */
  if ((he->type & D_INTERNAL_INHERITED) && (CONFIG_TYPE(he->type) == 0))
    return CSR_SUCCESS;

  int rc = CSR_SUCCESS;

  if (he->type & D_INTERNAL_INHERITED)
  {
    struct Inheritance *i = he->data;
    struct HashElem *he_base = cs_get_base(he);
    struct ConfigDef *cdef = he_base->data;
    if (!cdef)
      return CSR_ERR_CODE; // LCOV_EXCL_LINE

    const struct ConfigSetType *cst = cs_get_type_def(cs, he_base->type);
    if (cst && cst->destroy)
      cst->destroy((void **) &i->var, cdef);

    he->type = D_INTERNAL_INHERITED;
  }
  else
  {
    struct ConfigDef *cdef = he->data;
    if (!cdef)
      return CSR_ERR_CODE; // LCOV_EXCL_LINE

    const struct ConfigSetType *cst = cs_get_type_def(cs, he->type);
    if (cst)
      rc = cst->reset(&cdef->var, cdef, err);
  }

  return rc;
}

/**
 * cs_str_reset - Reset a config item to its initial value
 * @param cs   Config items
 * @param name Name of config item
 * @param err  Buffer for error messages
 * @retval num Result, e.g. #CSR_SUCCESS
 */
int cs_str_reset(const struct ConfigSet *cs, const char *name, struct Buffer *err)
{
  if (!cs || !name)
    return CSR_ERR_CODE;

  struct HashElem *he = cs_get_elem(cs, name);
  if (!he)
  {
    buf_printf(err, _("Unknown option %s"), name);
    return CSR_ERR_UNKNOWN;
  }

  return cs_he_reset(cs, he, err);
}

/**
 * cs_he_has_been_set - Is the config value different to its initial value?
 * @param cs   Config items
 * @param he   HashElem representing config item
 * @retval true  Config has been set
 * @retval false Config has not been set
 */
bool cs_he_has_been_set(const struct ConfigSet *cs, struct HashElem *he)
{
  if (!cs || !he)
    return false;

  const struct ConfigSetType *cst = cs_get_type_def(cs, he->type);
  if (!cst)
    return false; // LCOV_EXCL_LINE

  if (!cst->has_been_set) // Probably a my_var
    return true;

  struct ConfigDef *cdef = he->data;
  void *var = &cdef->var;

  return cst->has_been_set(var, cdef);
}

/**
 * cs_str_has_been_set - Is the config value different to its initial value?
 * @param cs   Config items
 * @param name Name of config item
 * @retval true  Config has been set
 * @retval false Config has not been set
 */
bool cs_str_has_been_set(const struct ConfigSet *cs, const char *name)
{
  if (!cs || !name)
    return false;

  struct HashElem *he = cs_get_elem(cs, name);
  if (!he)
    return false;

  return cs_he_has_been_set(cs, he);
}

/**
 * cs_he_initial_set - Set the initial value of a config item
 * @param cs    Config items
 * @param he    HashElem representing config item
 * @param value Value to set
 * @param err   Buffer for error messages
 * @retval num Result, e.g. #CSR_SUCCESS
 */
int cs_he_initial_set(const struct ConfigSet *cs, struct HashElem *he,
                      const char *value, struct Buffer *err)
{
  if (!cs || !he)
    return CSR_ERR_CODE;

  struct ConfigDef *cdef = NULL;

  if (he->type & D_INTERNAL_INHERITED)
  {
    struct HashElem *he_base = cs_get_base(he);
    cdef = he_base->data;
    mutt_debug(LL_DEBUG1, "Variable '%s' is inherited type\n", cdef->name);
    return CSR_ERR_CODE;
  }

  cdef = he->data;
  if (!cdef)
    return CSR_ERR_CODE; // LCOV_EXCL_LINE

  const struct ConfigSetType *cst = cs_get_type_def(cs, he->type);
  if (!cst)
  {
    mutt_debug(LL_DEBUG1, "Variable '%s' has an invalid type %d\n", cdef->name, he->type);
    return CSR_ERR_CODE;
  }

  int rc = cst->string_set(NULL, cdef, value, err);
  if (CSR_RESULT(rc) != CSR_SUCCESS)
    return rc;

  return CSR_SUCCESS;
}

/**
 * cs_str_initial_set - Set the initial value of a config item
 * @param cs    Config items
 * @param name  Name of config item
 * @param value Value to set
 * @param err   Buffer for error messages
 * @retval num Result, e.g. #CSR_SUCCESS
 */
int cs_str_initial_set(const struct ConfigSet *cs, const char *name,
                       const char *value, struct Buffer *err)
{
  if (!cs || !name)
    return CSR_ERR_CODE;

  struct HashElem *he = cs_get_elem(cs, name);
  if (!he)
  {
    buf_printf(err, _("Unknown option %s"), name);
    return CSR_ERR_UNKNOWN;
  }

  return cs_he_initial_set(cs, he, value, err);
}

/**
 * cs_he_initial_get - Get the initial, or parent, value of a config item
 * @param cs     Config items
 * @param he     HashElem representing config item
 * @param result Buffer for results or error messages
 * @retval num Result, e.g. #CSR_SUCCESS
 *
 * If a config item is inherited from another, then this will get the parent's
 * value.  Otherwise, it will get the config item's initial value.
 */
int cs_he_initial_get(const struct ConfigSet *cs, struct HashElem *he, struct Buffer *result)
{
  if (!cs || !he || !result)
    return CSR_ERR_CODE;

  const struct ConfigDef *cdef = NULL;
  const struct ConfigSetType *cst = NULL;

  if (he->type & D_INTERNAL_INHERITED)
  {
    struct HashElem *he_base = cs_get_base(he);
    cdef = he_base->data;
    cst = cs_get_type_def(cs, he_base->type);
  }
  else
  {
    cdef = he->data;
    cst = cs_get_type_def(cs, he->type);
  }

  if (!cst)
    return CSR_ERR_CODE; // LCOV_EXCL_LINE

  return cst->string_get(NULL, cdef, result);
}

/**
 * cs_str_initial_get - Get the initial, or parent, value of a config item
 * @param cs     Config items
 * @param name   Name of config item
 * @param result Buffer for results or error messages
 * @retval num Result, e.g. #CSR_SUCCESS
 *
 * If a config item is inherited from another, then this will get the parent's
 * value.  Otherwise, it will get the config item's initial value.
 */
int cs_str_initial_get(const struct ConfigSet *cs, const char *name, struct Buffer *result)
{
  if (!cs || !name)
    return CSR_ERR_CODE;

  struct HashElem *he = cs_get_elem(cs, name);
  if (!he)
  {
    buf_printf(result, _("Unknown option %s"), name);
    return CSR_ERR_UNKNOWN;
  }

  return cs_he_initial_get(cs, he, result);
}

/**
 * cs_he_string_set - Set a config item by string
 * @param cs    Config items
 * @param he    HashElem representing config item
 * @param value Value to set
 * @param err   Buffer for error messages
 * @retval num Result, e.g. #CSR_SUCCESS
 */
int cs_he_string_set(const struct ConfigSet *cs, struct HashElem *he,
                     const char *value, struct Buffer *err)
{
  if (!cs || !he)
    return CSR_ERR_CODE;

  struct ConfigDef *cdef = NULL;
  const struct ConfigSetType *cst = NULL;
  void *var = NULL;

  if (he->type & D_INTERNAL_INHERITED)
  {
    struct Inheritance *i = he->data;
    struct HashElem *he_base = cs_get_base(he);
    cdef = he_base->data;
    cst = cs_get_type_def(cs, he_base->type);
    var = &i->var;
  }
  else
  {
    cdef = he->data;
    cst = cs_get_type_def(cs, he->type);
    var = &cdef->var;
  }

  if (!cdef)
    return CSR_ERR_CODE; // LCOV_EXCL_LINE

  if (!cst)
  {
    mutt_debug(LL_DEBUG1, "Variable '%s' has an invalid type %d\n", cdef->name, he->type);
    return CSR_ERR_CODE;
  }

  int rc = cst->string_set(var, cdef, value, err);
  if (CSR_RESULT(rc) != CSR_SUCCESS)
    return rc;

  if (he->type & D_INTERNAL_INHERITED)
    he->type = cdef->type | D_INTERNAL_INHERITED;

  return rc;
}

/**
 * cs_str_string_set - Set a config item by string
 * @param cs    Config items
 * @param name  Name of config item
 * @param value Value to set
 * @param err   Buffer for error messages
 * @retval num Result, e.g. #CSR_SUCCESS
 */
int cs_str_string_set(const struct ConfigSet *cs, const char *name,
                      const char *value, struct Buffer *err)
{
  if (!cs || !name)
    return CSR_ERR_CODE;

  struct HashElem *he = cs_get_elem(cs, name);
  if (!he)
  {
    buf_printf(err, _("Unknown option %s"), name);
    return CSR_ERR_UNKNOWN;
  }

  return cs_he_string_set(cs, he, value, err);
}

/**
 * cs_he_string_get - Get a config item as a string
 * @param cs     Config items
 * @param he     HashElem representing config item
 * @param result Buffer for results or error messages
 * @retval num Result, e.g. #CSR_SUCCESS
 */
int cs_he_string_get(const struct ConfigSet *cs, struct HashElem *he, struct Buffer *result)
{
  if (!cs || !he || !result)
    return CSR_ERR_CODE;

  struct ConfigDef *cdef = NULL;
  const struct ConfigSetType *cst = NULL;
  void *var = NULL;

  if (he->type & D_INTERNAL_INHERITED)
  {
    struct Inheritance *i = he->data;

    // inherited, value not set
    if (CONFIG_TYPE(he->type) == 0)
      return cs_he_string_get(cs, i->parent, result);

    // inherited, value set
    struct HashElem *he_base = cs_get_base(he);
    cdef = he_base->data;
    cst = cs_get_type_def(cs, he_base->type);
    var = &i->var;
  }
  else
  {
    // not inherited
    cdef = he->data;
    cst = cs_get_type_def(cs, he->type);
    var = &cdef->var;
  }

  if (!cdef || !cst)
    return CSR_ERR_CODE; // LCOV_EXCL_LINE

  return cst->string_get(var, cdef, result);
}

/**
 * cs_he_native_set - Natively set the value of a HashElem config item
 * @param cs    Config items
 * @param he    HashElem representing config item
 * @param value Native pointer/value to set
 * @param err   Buffer for error messages
 * @retval num Result, e.g. #CSR_SUCCESS
 */
int cs_he_native_set(const struct ConfigSet *cs, struct HashElem *he,
                     intptr_t value, struct Buffer *err)
{
  if (!cs || !he)
    return CSR_ERR_CODE;

  struct ConfigDef *cdef = NULL;
  const struct ConfigSetType *cst = NULL;
  void *var = NULL;

  if (he->type & D_INTERNAL_INHERITED)
  {
    struct Inheritance *i = he->data;
    struct HashElem *he_base = cs_get_base(he);
    cdef = he_base->data;
    cst = cs_get_type_def(cs, he_base->type);
    var = &i->var;
  }
  else
  {
    cdef = he->data;
    cst = cs_get_type_def(cs, he->type);
    var = &cdef->var;
  }

  if (!cst)
  {
    mutt_debug(LL_DEBUG1, "Variable '%s' has an invalid type %d\n", cdef->name, he->type);
    return CSR_ERR_CODE;
  }

  if (!var || !cdef)
    return CSR_ERR_CODE; // LCOV_EXCL_LINE

  int rc = cst->native_set(var, cdef, value, err);
  if (CSR_RESULT(rc) != CSR_SUCCESS)
    return rc;

  if (he->type & D_INTERNAL_INHERITED)
    he->type = cdef->type | D_INTERNAL_INHERITED;

  return rc;
}

/**
 * cs_str_native_set - Natively set the value of a string config item
 * @param cs    Config items
 * @param name  Name of config item
 * @param value Native pointer/value to set
 * @param err   Buffer for error messages
 * @retval num Result, e.g. #CSR_SUCCESS
 */
int cs_str_native_set(const struct ConfigSet *cs, const char *name,
                      intptr_t value, struct Buffer *err)
{
  if (!cs || !name)
    return CSR_ERR_CODE;

  struct HashElem *he = cs_get_elem(cs, name);
  if (!he)
  {
    buf_printf(err, _("Unknown option %s"), name);
    return CSR_ERR_UNKNOWN;
  }

  struct ConfigDef *cdef = NULL;
  const struct ConfigSetType *cst = NULL;
  void *var = NULL;

  if (he->type & D_INTERNAL_INHERITED)
  {
    struct Inheritance *i = he->data;
    struct HashElem *he_base = cs_get_base(he);
    cdef = he_base->data;
    cst = cs_get_type_def(cs, he_base->type);
    var = &i->var;
  }
  else
  {
    cdef = he->data;
    cst = cs_get_type_def(cs, he->type);
    var = &cdef->var;
  }

  if (!cst || !var || !cdef)
    return CSR_ERR_CODE; /* LCOV_EXCL_LINE */

  int rc = cst->native_set(var, cdef, value, err);
  if (CSR_RESULT(rc) != CSR_SUCCESS)
    return rc;

  if (he->type & D_INTERNAL_INHERITED)
    he->type = cdef->type | D_INTERNAL_INHERITED;

  return rc;
}

/**
 * cs_he_native_get - Natively get the value of a HashElem config item
 * @param cs  Config items
 * @param he  HashElem representing config item
 * @param err Buffer for results or error messages
 * @retval intptr_t Native pointer/value
 * @retval INT_MIN  Error
 */
intptr_t cs_he_native_get(const struct ConfigSet *cs, struct HashElem *he, struct Buffer *err)
{
  if (!cs || !he)
    return INT_MIN;

  struct ConfigDef *cdef = NULL;
  const struct ConfigSetType *cst = NULL;
  void *var = NULL;

  if (he->type & D_INTERNAL_INHERITED)
  {
    struct Inheritance *i = he->data;

    // inherited, value not set
    if (CONFIG_TYPE(he->type) == 0)
      return cs_he_native_get(cs, i->parent, err);

    // inherited, value set
    struct HashElem *he_base = cs_get_base(he);
    cdef = he_base->data;
    cst = cs_get_type_def(cs, he_base->type);
    var = &i->var;
  }
  else
  {
    // not inherited
    cdef = he->data;
    cst = cs_get_type_def(cs, he->type);
    var = &cdef->var;
  }

  if (!var || !cdef)
    return INT_MIN; // LCOV_EXCL_LINE

  if (!cst)
  {
    buf_printf(err, _("Option %s has an invalid type %d"), cdef->name, he->type);
    return INT_MIN;
  }

  return cst->native_get(var, cdef, err);
}

/**
 * cs_he_string_plus_equals - Add to a config item by string
 * @param cs    Config items
 * @param he    HashElem representing config item
 * @param value Value to set
 * @param err   Buffer for error messages
 * @retval num Result, e.g. #CSR_SUCCESS
 */
int cs_he_string_plus_equals(const struct ConfigSet *cs, struct HashElem *he,
                             const char *value, struct Buffer *err)
{
  if (!cs || !he)
    return CSR_ERR_CODE;

  struct ConfigDef *cdef = NULL;
  const struct ConfigSetType *cst = NULL;
  void *var = NULL;

  if (he->type & D_INTERNAL_INHERITED)
  {
    struct Inheritance *i = he->data;
    struct HashElem *he_base = cs_get_base(he);
    cdef = he_base->data;
    cst = cs_get_type_def(cs, he_base->type);
    var = &i->var;
  }
  else
  {
    cdef = he->data;
    cst = cs_get_type_def(cs, he->type);
    var = &cdef->var;
  }

  if (!var || !cdef)
    return INT_MIN; // LCOV_EXCL_LINE

  if (!cst)
  {
    mutt_debug(LL_DEBUG1, "Variable '%s' has an invalid type %d\n", cdef->name, he->type);
    return CSR_ERR_CODE;
  }

  if (!cst->string_plus_equals)
  {
    // L10N: e.g. Type 'boolean' doesn't support operation '+='
    buf_printf(err, _("Type '%s' doesn't support operation '%s'"), cst->name, "+=");
    return CSR_ERR_INVALID | CSV_INV_NOT_IMPL;
  }

  int rc = cst->string_plus_equals(var, cdef, value, err);
  if (CSR_RESULT(rc) != CSR_SUCCESS)
    return rc;

  if (he->type & D_INTERNAL_INHERITED)
    he->type = cdef->type | D_INTERNAL_INHERITED;

  return rc;
}

/**
 * cs_he_string_minus_equals - Remove from a config item by string
 * @param cs    Config items
 * @param he    HashElem representing config item
 * @param value Value to set
 * @param err   Buffer for error messages
 * @retval num Result, e.g. #CSR_SUCCESS
 */
int cs_he_string_minus_equals(const struct ConfigSet *cs, struct HashElem *he,
                              const char *value, struct Buffer *err)
{
  if (!cs || !he)
    return CSR_ERR_CODE;

  struct ConfigDef *cdef = NULL;
  const struct ConfigSetType *cst = NULL;
  void *var = NULL;

  if (he->type & D_INTERNAL_INHERITED)
  {
    struct Inheritance *i = he->data;
    struct HashElem *he_base = cs_get_base(he);
    cdef = he_base->data;
    cst = cs_get_type_def(cs, he_base->type);
    var = &i->var;
  }
  else
  {
    cdef = he->data;
    cst = cs_get_type_def(cs, he->type);
    var = &cdef->var;
  }

  if (!var || !cdef)
    return INT_MIN; // LCOV_EXCL_LINE

  if (!cst)
  {
    mutt_debug(LL_DEBUG1, "Variable '%s' has an invalid type %d\n", cdef->name, he->type);
    return CSR_ERR_CODE;
  }

  if (!cst->string_minus_equals)
  {
    // L10N: e.g. Type 'boolean' doesn't support operation '+='
    buf_printf(err, _("Type '%s' doesn't support operation '%s'"), cst->name, "-=");
    return CSR_ERR_INVALID | CSV_INV_NOT_IMPL;
  }

  int rc = cst->string_minus_equals(var, cdef, value, err);
  if (CSR_RESULT(rc) != CSR_SUCCESS)
    return rc;

  if (he->type & D_INTERNAL_INHERITED)
    he->type = cdef->type | D_INTERNAL_INHERITED;

  return rc;
}

/**
 * cs_he_delete - Delete config item from a config set
 * @param cs    Config items
 * @param he    HashElem representing config item
 * @param err   Buffer for error messages
 * @retval num Result, e.g. #CSR_SUCCESS
 */
int cs_he_delete(const struct ConfigSet *cs, struct HashElem *he, struct Buffer *err)
{
  if (!cs || !he)
    return CSR_ERR_CODE;

  mutt_hash_delete(cs->hash, he->key.strkey, he->data);
  return CSR_SUCCESS;
}
