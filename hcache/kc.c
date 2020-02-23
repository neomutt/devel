/**
 * @file
 * Kyotocabinet DB backend for the header cache
 *
 * @authors
 * Copyright (C) 2004 Thomas Glanzmann <sithglan@stud.uni-erlangen.de>
 * Copyright (C) 2004 Tobias Werth <sitowert@stud.uni-erlangen.de>
 * Copyright (C) 2004 Brian Fundakowski Feldman <green@FreeBSD.org>
 * Copyright (C) 2016 Pietro Cerutti <gahr@gahr.ch>
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
 * @page hc_kc Kyoto Cabinet
 *
 * Use a Kyoto Cabinet file as a header cache backend.
 */

#include "config.h"
#include <kclangc.h>
#include <stdio.h>
#include "mutt/lib.h"
#include "backend.h"
#include "globals.h"

/**
 * hcache_kyotocabinet_open - Implements HcacheOps::open()
 */
static void *hcache_kyotocabinet_open(const char *path)
{
  KCDB *db = kcdbnew();
  if (!db)
    return NULL;

  struct Buffer kcdbpath = mutt_buffer_make(1024);

  mutt_buffer_printf(&kcdbpath, "%s#type=kct#opts=%s#rcomp=lex", path,
                     C_HeaderCacheCompress ? "lc" : "l");

  if (!kcdbopen(db, mutt_b2s(&kcdbpath), KCOWRITER | KCOCREATE))
  {
    int ecode = kcdbecode(db);
    mutt_debug(LL_DEBUG2, "kcdbopen failed for %s: %s (ecode %d)\n",
               mutt_b2s(&kcdbpath), kcdbemsg(db), ecode);
    kcdbdel(db);
    db = NULL;
  }

  mutt_buffer_dealloc(&kcdbpath);
  return db;
}

/**
 * hcache_kyotocabinet_fetch - Implements HcacheOps::fetch()
 */
static void *hcache_kyotocabinet_fetch(void *ctx, const char *key, size_t keylen, size_t *dlen)
{
  if (!ctx)
    return NULL;

  KCDB *db = ctx;
  return kcdbget(db, key, keylen, dlen);
}

/**
 * hcache_kyotocabinet_free - Implements HcacheOps::free()
 */
static void hcache_kyotocabinet_free(void *vctx, void **data)
{
  kcfree(*data);
  *data = NULL;
}

/**
 * hcache_kyotocabinet_store - Implements HcacheOps::store()
 */
static int hcache_kyotocabinet_store(void *ctx, const char *key, size_t keylen,
                                     void *data, size_t dlen)
{
  if (!ctx)
    return -1;

  KCDB *db = ctx;
  if (!kcdbset(db, key, keylen, data, dlen))
  {
    int ecode = kcdbecode(db);
    return ecode ? ecode : -1;
  }
  return 0;
}

/**
 * hcache_kyotocabinet_delete_header - Implements HcacheOps::delete_header()
 */
static int hcache_kyotocabinet_delete_header(void *ctx, const char *key, size_t keylen)
{
  if (!ctx)
    return -1;

  KCDB *db = ctx;
  if (!kcdbremove(db, key, keylen))
  {
    int ecode = kcdbecode(db);
    return ecode ? ecode : -1;
  }
  return 0;
}

/**
 * hcache_kyotocabinet_close - Implements HcacheOps::close()
 */
static void hcache_kyotocabinet_close(void **ptr)
{
  if (!ptr || !*ptr)
    return;

  KCDB *db = *ptr;
  if (!kcdbclose(db))
  {
    int ecode = kcdbecode(db);
    mutt_debug(LL_DEBUG2, "kcdbclose failed: %s (ecode %d)\n", kcdbemsg(db), ecode);
  }
  kcdbdel(db);
  *ptr = NULL;
}

/**
 * hcache_kyotocabinet_backend - Implements HcacheOps::backend()
 */
static const char *hcache_kyotocabinet_backend(void)
{
  static char version_cache[128] = { 0 }; ///< should be more than enough for KCVERSION
  if (version_cache[0] == '\0')
    snprintf(version_cache, sizeof(version_cache), "kyotocabinet %s", KCVERSION);

  return version_cache;
}

HCACHE_BACKEND_OPS(kyotocabinet)
