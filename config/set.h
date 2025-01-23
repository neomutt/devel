/**
 * @file
 * A collection of config items
 *
 * @authors
 * Copyright (C) 2017-2025 Richard Russon <rich@flatcap.org>
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

#ifndef MUTT_CONFIG_SET_H
#define MUTT_CONFIG_SET_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include "mutt/lib.h"
#include "types.h"

struct ConfigSet;

/* Config Set Results */
#define CSR_SUCCESS       0 ///< Action completed successfully
#define CSR_ERR_CODE      1 ///< Problem with the code
#define CSR_ERR_UNKNOWN   2 ///< Unrecognised config item
#define CSR_ERR_INVALID   3 ///< Value hasn't been set

/* Flags for CSR_SUCCESS */
#define CSR_SUC_INHERITED (1 << 4) ///< Value is inherited
#define CSR_SUC_EMPTY     (1 << 5) ///< Value is empty/unset
#define CSR_SUC_WARNING   (1 << 6) ///< Notify the user of a warning
#define CSR_SUC_NO_CHANGE (1 << 7) ///< The value hasn't changed

/* Flags for CSR_INVALID */
#define CSR_INV_TYPE      (1 << 4) ///< Value is not valid for the type
#define CSR_INV_VALIDATOR (1 << 5) ///< Value was rejected by the validator
#define CSV_INV_NOT_IMPL  (1 << 6) ///< Operation not permitted for the type

#define CSR_RESULT_MASK 0x0F
#define CSR_RESULT(x) ((x) & CSR_RESULT_MASK)

#define IP (intptr_t)

/**
 * @defgroup cfg_def_api Config Definition API
 *
 * Config item definition
 *
 * Every config variable that NeoMutt supports is backed by a ConfigDef.
 */
struct ConfigDef
{
  const char   *name;      ///< User-visible name
  uint32_t      type;      ///< Variable type, e.g. #DT_STRING
  intptr_t      initial;   ///< Initial value
  intptr_t      data;      ///< Extra variable data

  /**
   * @defgroup cfg_def_validator validator()
   * @ingroup cfg_def_api
   *
   * validator - Validate a config variable
   * @param cdef  Config definition
   * @param value Native value
   * @param err   Message for the user
   * @retval #CSR_SUCCESS     Success
   * @retval #CSR_ERR_INVALID Failure
   */
  int (*validator)(const struct ConfigDef *cdef, intptr_t value, struct Buffer *err);

  const char *docs; ///< One-liner description
  intptr_t    var;  ///< Storage for the variable
};

/**
 * @defgroup cfg_type_api Config Type API
 *
 * Type definition for a config item
 *
 * Each config item has a type which is defined by a set of callback functions.
 */
struct ConfigSetType
{
  int type;                  ///< Data type, e.g. #DT_STRING
  const char *name;          ///< Name of the type, e.g. "String"

  /**
   * @defgroup cfg_type_string_set string_set()
   * @ingroup cfg_type_api
   *
   * string_set - Set a config item by string
   * @param var   Variable to set (may be NULL)
   * @param cdef  Variable definition
   * @param value Value to set (may be NULL)
   * @param err   Buffer for error messages (may be NULL)
   * @retval num Result, e.g. #CSR_SUCCESS
   *
   * If var is NULL, then the config item's initial value will be set.
   *
   * @pre cdef is not NULL
   */
  int (*string_set)(void *var, struct ConfigDef *cdef, const char *value, struct Buffer *err);

  /**
   * @defgroup cfg_type_string_get string_get()
   * @ingroup cfg_type_api
   *
   * string_get - Get a config item as a string
   * @param var    Variable to get (may be NULL)
   * @param cdef   Variable definition
   * @param result Buffer for results or error messages
   * @retval num Result, e.g. #CSR_SUCCESS
   *
   * If var is NULL, then the config item's initial value will be returned.
   *
   * @pre cdef   is not NULL
   * @pre result is not NULL
   */
  int (*string_get)(void *var, const struct ConfigDef *cdef, struct Buffer *result);

  /**
   * @defgroup cfg_type_native_set native_set()
   * @ingroup cfg_type_api
   *
   * native_set - Set a config item by string
   * @param var   Variable to set
   * @param cdef  Variable definition
   * @param value Native pointer/value to set
   * @param err   Buffer for error messages (may be NULL)
   * @retval num Result, e.g. #CSR_SUCCESS
   *
   * @pre var  is not NULL
   * @pre cdef is not NULL
   */
  int (*native_set)(void *var, const struct ConfigDef *cdef, intptr_t value, struct Buffer *err);

  /**
   * @defgroup cfg_type_native_get native_get()
   * @ingroup cfg_type_api
   *
   * native_get - Get a string from a config item
   * @param var  Variable to get
   * @param cdef Variable definition
   * @param err  Buffer for error messages (may be NULL)
   * @retval intptr_t Config item string
   * @retval INT_MIN  Error
   *
   * @pre var  is not NULL
   * @pre cdef is not NULL
   */
  intptr_t (*native_get)(void *var, const struct ConfigDef *cdef, struct Buffer *err);

  /**
   * @defgroup cfg_type_string_plus_equals string_plus_equals()
   * @ingroup cfg_type_api
   *
   * string_plus_equals - Add to a config item by string
   * @param var   Variable to set
   * @param cdef  Variable definition
   * @param value Value to set
   * @param err   Buffer for error messages (may be NULL)
   * @retval num Result, e.g. #CSR_SUCCESS
   *
   * @pre var  is not NULL
   * @pre cdef is not NULL
   */
  int (*string_plus_equals)(void *var, const struct ConfigDef *cdef, const char *value, struct Buffer *err);

  /**
   * @defgroup cfg_type_string_minus_equals string_minus_equals()
   * @ingroup cfg_type_api
   *
   * string_minus_equals - Remove from a config item as a string
   * @param var   Variable to set
   * @param cdef  Variable definition
   * @param value Value to set
   * @param err   Buffer for error messages (may be NULL)
   * @retval num Result, e.g. #CSR_SUCCESS
   *
   * @pre var  is not NULL
   * @pre cdef is not NULL
   */
  int (*string_minus_equals)(void *var, const struct ConfigDef *cdef, const char *value, struct Buffer *err);

  /**
   * @defgroup cfg_type_has_been_set has_been_set()
   * @ingroup cfg_type_api
   *
   * has_been_set - Is the config value different to its initial value?
   * @param var  Variable to check
   * @param cdef Variable definition
   * @retval true  Value differs from its initial value
   * @retval false Value is the same as its initial value
   *
   * @pre var  is not NULL
   * @pre cdef is not NULL
   */
  bool (*has_been_set)(void *var, const struct ConfigDef *cdef);

  /**
   * @defgroup cfg_type_reset reset()
   * @ingroup cfg_type_api
   *
   * reset - Reset a config item to its initial value
   * @param var  Variable to reset
   * @param cdef Variable definition
   * @param err  Buffer for error messages (may be NULL)
   * @retval num Result, e.g. #CSR_SUCCESS
   *
   * @pre var  is not NULL
   * @pre cdef is not NULL
   */
  int (*reset)(void *var, const struct ConfigDef *cdef, struct Buffer *err);

  /**
   * @defgroup cfg_type_destroy destroy()
   * @ingroup cfg_type_api
   *
   * destroy - Destroy a config item
   * @param var  Variable to destroy
   * @param cdef Variable definition
   *
   * @pre var  is not NULL
   * @pre cdef is not NULL
   */
  void (*destroy)(void *var, const struct ConfigDef *cdef);
};

/**
 * struct ConfigSet - Container for lots of config items
 *
 * The config items are stored in a HashTable so that their names can be looked
 * up efficiently.  Each config item is represented by a HashElem.  Once
 * created, this HashElem is static and may be used for the lifetime of the
 * ConfigSet.
 */
struct ConfigSet
{
  struct HashTable *hash;         ///< Hash Table: "$name" -> ConfigDef
  struct ConfigSetType types[18]; ///< All the defined config types
};

struct ConfigSet *cs_new(size_t size);
void              cs_free(struct ConfigSet **ptr);

struct HashElem *           cs_get_base    (struct HashElem *he);
struct HashElem *           cs_get_elem    (const struct ConfigSet *cs, const char *name);
const struct ConfigSetType *cs_get_type_def(const struct ConfigSet *cs, unsigned int type);

bool             cs_register_type     (struct ConfigSet *cs, const struct ConfigSetType *cst);
struct HashElem *cs_register_variable (const struct ConfigSet *cs, struct ConfigDef *cdef, struct Buffer *err);
bool             cs_register_variables(const struct ConfigSet *cs, struct ConfigDef vars[]);
struct HashElem *cs_create_variable   (const struct ConfigSet *cs, struct ConfigDef *cdef, struct Buffer *err);
struct HashElem *cs_inherit_variable  (const struct ConfigSet *cs, struct HashElem *he_parent, const char *name);
void             cs_uninherit_variable(const struct ConfigSet *cs, const char *name);

bool     cs_he_has_been_set        (const struct ConfigSet *cs, struct HashElem *he);
int      cs_he_initial_get         (const struct ConfigSet *cs, struct HashElem *he,                    struct Buffer *result);
int      cs_he_initial_set         (const struct ConfigSet *cs, struct HashElem *he, const char *value, struct Buffer *err);
intptr_t cs_he_native_get          (const struct ConfigSet *cs, struct HashElem *he,                    struct Buffer *err);
int      cs_he_native_set          (const struct ConfigSet *cs, struct HashElem *he, intptr_t value,    struct Buffer *err);
int      cs_he_reset               (const struct ConfigSet *cs, struct HashElem *he,                    struct Buffer *err);
int      cs_he_string_get          (const struct ConfigSet *cs, struct HashElem *he,                    struct Buffer *result);
int      cs_he_string_minus_equals (const struct ConfigSet *cs, struct HashElem *he, const char *value, struct Buffer *err);
int      cs_he_string_plus_equals  (const struct ConfigSet *cs, struct HashElem *he, const char *value, struct Buffer *err);
int      cs_he_string_set          (const struct ConfigSet *cs, struct HashElem *he, const char *value, struct Buffer *err);
int      cs_he_delete              (const struct ConfigSet *cs, struct HashElem *he,                    struct Buffer *err);

bool     cs_str_has_been_set       (const struct ConfigSet *cs, const char *name);
int      cs_str_initial_get        (const struct ConfigSet *cs, const char *name,                       struct Buffer *result);
int      cs_str_initial_set        (const struct ConfigSet *cs, const char *name,    const char *value, struct Buffer *err);
int      cs_str_native_set         (const struct ConfigSet *cs, const char *name,    intptr_t value,    struct Buffer *err);
int      cs_str_reset              (const struct ConfigSet *cs, const char *name,                       struct Buffer *err);
int      cs_str_string_set         (const struct ConfigSet *cs, const char *name,    const char *value, struct Buffer *err);

extern bool StartupComplete;

/**
 * startup_only - Validator function for D_ON_STARTUP
 * @param cdef Variable definition
 * @param err  Buffer for error messages
 * @retval true Variable may only be set at startup
 */
static inline bool startup_only(const struct ConfigDef *cdef, struct Buffer *err)
{
  if ((cdef->type & D_ON_STARTUP) && StartupComplete)
  {
    buf_printf(err, _("Option %s may only be set at startup"), cdef->name);
    return true;
  }

  return false;
}

#endif /* MUTT_CONFIG_SET_H */
