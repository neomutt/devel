/**
 * @file
 * Config used by libhcache
 *
 * @authors
 * Copyright (C) 2020 Louis Brauer <louis@openbooking.ch>
 * Copyright (C) 2020-2023 Richard Russon <rich@flatcap.org>
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
 * @page hc_config Config used by Header Cache
 *
 * Config used by libhcache
 */

#include "config.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "mutt/lib.h"
#include "config/lib.h"
#include "core/lib.h"
#include "compress/lib.h"
#include "store/lib.h"

/**
 * hcache_validator - Validate the "header_cache_backend" config variable - Implements ConfigDef::validator() - @ingroup cfg_def_validator
 */
static int hcache_validator(const struct ConfigDef *cdef, intptr_t value, struct Buffer *err)
{
#ifdef USE_HCACHE
  if (value == 0)
    return CSR_SUCCESS;

  const char *str = (const char *) value;

  if (store_is_valid_backend(str))
    return CSR_SUCCESS;

  buf_printf(err, _("Invalid value for option %s: %s"), cdef->name, str);
  return CSR_ERR_INVALID;
#else
  return CSR_SUCCESS;
#endif
}

#if defined(USE_HCACHE_COMPRESSION)
/**
 * compress_method_validator - Validate the "header_cache_compress_method" config variable - Implements ConfigDef::validator() - @ingroup cfg_def_validator
 */
static int compress_method_validator(const struct ConfigDef *cdef,
                                     intptr_t value, struct Buffer *err)
{
#ifdef USE_HCACHE_COMPRESSION
  if (value == 0)
    return CSR_SUCCESS;

  const char *str = (const char *) value;

  if (compress_get_ops(str))
    return CSR_SUCCESS;

  buf_printf(err, _("Invalid value for option %s: %s"), cdef->name, str);
  return CSR_ERR_INVALID;
#else
  return CSR_SUCCESS;
#endif
}

/**
 * compress_level_validator - Validate the "header_cache_compress_level" config variable - Implements ConfigDef::validator() - @ingroup cfg_def_validator
 */
static int compress_level_validator(const struct ConfigDef *cdef,
                                    intptr_t value, struct Buffer *err)
{
#ifdef USE_HCACHE_COMPRESSION
  const char *const c_header_cache_compress_method = cs_subset_string(NeoMutt->sub, "header_cache_compress_method");
  if (!c_header_cache_compress_method)
  {
    buf_printf(err, _("Set option %s before setting %s"),
               "header_cache_compress_method", cdef->name);
    return CSR_ERR_INVALID;
  }

  const struct ComprOps *cops = compress_get_ops(c_header_cache_compress_method);
  if (!cops)
  {
    buf_printf(err, _("Invalid value for option %s: %s"),
               "header_cache_compress_method", c_header_cache_compress_method);
    return CSR_ERR_INVALID;
  }

  if ((value < cops->min_level) || (value > cops->max_level))
  {
    // L10N: This applies to the "$header_cache_compress_level" config variable.
    //       It shows the minimum and maximum values, e.g. 'between 1 and 22'
    buf_printf(err, _("Option %s must be between %d and %d inclusive"),
               cdef->name, cops->min_level, cops->max_level);
    return CSR_ERR_INVALID;
  }
#endif
  return CSR_SUCCESS;
}
#endif

/**
 * HcacheVars - Config definitions for the Header Cache
 */
static struct ConfigDef HcacheVars[] = {
  // clang-format off
  { "header_cache", DT_PATH, 0, 0, NULL,
    "(hcache) Directory/file for the header cache database"
  },
  { "header_cache_backend", DT_STRING, 0, 0, hcache_validator,
    "(hcache) Header cache backend to use"
  },
  { NULL },
  // clang-format on
};

#if defined(USE_HCACHE_COMPRESSION)
/**
 * HcacheVarsComp - Config definitions for the Header Cache Compression
 */
static struct ConfigDef HcacheVarsComp[] = {
  // clang-format off
  // These two are not in alphabetical order because `level`s validator depends on `method`
  { "header_cache_compress_method", DT_STRING, 0, 0, compress_method_validator,
    "(hcache) Enable generic hcache database compression"
  },
  { "header_cache_compress_level", DT_NUMBER|D_INTEGER_NOT_NEGATIVE, 1, 0, compress_level_validator,
    "(hcache) Level of compression for method"
  },
  { NULL },
  // clang-format on
};
#endif

#if defined(HAVE_QDBM) || defined(HAVE_TC) || defined(HAVE_KC)
/**
 * HcacheVarsComp2 - Deprecated Config definitions for the Header Cache Compression
 */
static struct ConfigDef HcacheVarsComp2[] = {
  // clang-format off
  { "header_cache_compress", D_INTERNAL_DEPRECATED|DT_BOOL, 0, IP "2020-03-25" },
  { NULL },
  // clang-format on
};
#endif

#if defined(HAVE_GDBM) || defined(HAVE_BDB)
/**
 * HcacheVarsPage - Deprecated Config definitions for the Header Cache
 */
static struct ConfigDef HcacheVarsPage[] = {
  // clang-format off
  { "header_cache_pagesize", D_INTERNAL_DEPRECATED|DT_LONG, 0, IP "2020-03-25" },
  { NULL },
  // clang-format on
};
#endif

/**
 * config_init_hcache - Register hcache config variables - Implements ::module_init_config_t - @ingroup cfg_module_api
 */
bool config_init_hcache(struct ConfigSet *cs)
{
  bool rc = false;

#if defined(USE_HCACHE)
  rc |= cs_register_variables(cs, HcacheVars);
#endif

#if defined(USE_HCACHE_COMPRESSION)
  rc |= cs_register_variables(cs, HcacheVarsComp);
#endif

#if defined(HAVE_QDBM) || defined(HAVE_TC) || defined(HAVE_KC)
  rc |= cs_register_variables(cs, HcacheVarsComp2);
#endif

#if defined(HAVE_GDBM) || defined(HAVE_BDB)
  rc |= cs_register_variables(cs, HcacheVarsPage);
#endif

  return rc;
}
