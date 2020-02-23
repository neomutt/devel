/**
 * @file
 * Header cache multiplexor
 *
 * @authors
 * Copyright (C) 2004 Thomas Glanzmann <sithglan@stud.uni-erlangen.de>
 * Copyright (C) 2004 Tobias Werth <sitowert@stud.uni-erlangen.de>
 * Copyright (C) 2004 Brian Fundakowski Feldman <green@FreeBSD.org>
 * Copyright (C) 2016 Pietro Cerutti <gahr@gahr.ch>
 * Copyright (C) 2019 Tino Reichardt <milky-neomutt@mcmilk.de>
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
 * @page hc_hcache Header cache multiplexor
 *
 * This module implements the gateway between the user visible part of the
 * header cache API and the backend specific API. Also, this module implements
 * the serialization/deserialization routines for the Header structure.
 */

#include "config.h"
#include "muttlib.h"
#include "serialize.h"

#if !(defined(HAVE_BDB) || defined(HAVE_GDBM) || defined(HAVE_KC) ||           \
      defined(HAVE_LMDB) || defined(HAVE_QDBM) || defined(HAVE_TC))
#error "No hcache backend defined"
#endif

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "mutt/lib.h"
#include "email/lib.h"
#include "lib.h"
#include "backend.h"
#include "compr.h"
#include "hcache/hcversion.h"

/* These Config Variables are only used in hcache/hcache.c */
char *C_HeaderCacheBackend; ///< Config: (hcache) Header cache backend to use

static unsigned int hcachever = 0x0;

#define HCACHE_BACKEND(name) extern const struct HcacheOps hcache_##name##_ops;
HCACHE_BACKEND(bdb)
HCACHE_BACKEND(gdbm)
HCACHE_BACKEND(kyotocabinet)
HCACHE_BACKEND(lmdb)
HCACHE_BACKEND(qdbm)
HCACHE_BACKEND(tokyocabinet)
#undef HCACHE_BACKEND

#define hcache_get_ops() hcache_get_backend_ops(C_HeaderCacheBackend)

/**
 * hcache_ops - Backend implementations
 */
const struct HcacheOps *hcache_ops[] = {
#ifdef HAVE_TC
  &hcache_tokyocabinet_ops,
#endif
#ifdef HAVE_KC
  &hcache_kyotocabinet_ops,
#endif
#ifdef HAVE_QDBM
  &hcache_qdbm_ops,
#endif
#ifdef HAVE_GDBM
  &hcache_gdbm_ops,
#endif
#ifdef HAVE_BDB
  &hcache_bdb_ops,
#endif
#ifdef HAVE_LMDB
  &hcache_lmdb_ops,
#endif
  NULL,
};

/**
 * hcache_get_backend_ops - Get the API functions for an hcache backend
 * @param backend Name of the backend
 * @retval ptr Set of function pointers
 */
static const struct HcacheOps *hcache_get_backend_ops(const char *backend)
{
  const struct HcacheOps **ops = hcache_ops;

  if (!backend || !*backend)
  {
    return *ops;
  }

  for (; *ops; ops++)
    if (strcmp(backend, (*ops)->name) == 0)
      break;

  return *ops;
}

#ifdef USE_HCACHE_COMPRESSION
char *C_HeaderCacheCompressDictionary; ///< Config: (hcache) Filepath to dictionary for zstd compression
short C_HeaderCacheCompressLevel; ///< Config: (hcache) Level of compression for method
char *C_HeaderCacheCompressMethod; ///< Config: (hcache) Enable generic hcache database compression

#define HCACHE_COMPR(name) extern const struct ComprOps compr_##name##_ops;
HCACHE_COMPR(lz4)
HCACHE_COMPR(zlib)
HCACHE_COMPR(zstd)
#undef HCACHE_COMPR

#define compr_get_ops()                                                        \
  hcache_get_backend_compr_ops(C_HeaderCacheCompressMethod)

/**
 * compr_ops - Backend implementations
 */
const struct ComprOps *compr_ops[] = {
#ifdef HAVE_LZ4
  &compr_lz4_ops,
#endif
#ifdef HAVE_ZLIB
  &compr_zlib_ops,
#endif
#ifdef HAVE_ZSTD
  &compr_zstd_ops,
#endif
  NULL
};

/**
 * hcache_get_backend_compr_ops - Get the API functions for an hcache compress backend
 * @param compr Name of the backend
 * @retval ptr Set of function pointers
 */
static const struct ComprOps *hcache_get_backend_compr_ops(const char *compr)
{
  const struct ComprOps **ops = compr_ops;

  if (!compr || !*compr)
  {
    return *ops;
  }

  for (; *ops; ops++)
  {
    if (strcmp(compr, (*ops)->name) == 0)
      break;
  }

  return *ops;
}

/**
 * mutt_hcache_is_valid_compression - Is the string a valid hcache compression backend
 * @param s String identifying a compression method
 * @retval true  s is recognized as a valid backend
 * @retval false otherwise
 */
bool mutt_hcache_is_valid_compression(const char *s)
{
  return hcache_get_backend_compr_ops(s);
}

#endif /* USE_HCACHE_COMPRESSION */

/**
 * crc_matches - Is the CRC number correct?
 * @param d   Binary blob to read CRC from
 * @param crc CRC to compare
 * @retval num 1 if true, 0 if not
 */
static bool crc_matches(const char *d, unsigned int crc)
{
  if (!d)
    return false;

  unsigned int mycrc = *(unsigned int *) (d + sizeof(size_t));

  return crc == mycrc;
}

/**
 * create_hcache_dir - Create parent dirs for the hcache database
 * @param path Database filename
 * @retval true Success
 * @retval false Failure (errno set)
 */
static bool create_hcache_dir(const char *path)
{
  char *dir = mutt_str_strdup(path);
  if (!dir)
    return false;

  char *p = strrchr(dir, '/');
  if (!p)
  {
    FREE(&dir);
    return true;
  }

  *p = '\0';

  int rc = mutt_file_mkdir(dir, S_IRWXU | S_IRWXG | S_IRWXO);
  if (rc != 0)
    mutt_error(_("Can't create %s: %s"), dir, strerror(errno));

  FREE(&dir);
  return (rc == 0);
}

/**
 * hcache_per_folder - Generate the hcache pathname
 * @param hcpath Buffer for the result
 * @param path   Base directory, from $header_cache
 * @param folder Mailbox name (including protocol)
 * @param namer  Callback to generate database filename - Implements ::hcache_namer_t
 * @retval ptr Full pathname to the database (to be generated)
 *             (path must be freed by the caller)
 *
 * Generate the pathname for the hcache database, it will be of the form:
 *     BASE/FOLDER/NAME
 *
 * * BASE:   Base directory (@a path)
 * * FOLDER: Mailbox name (@a folder)
 * * NAME:   Create by @a namer, or md5sum of @a folder
 *
 * This function will create any parent directories needed, so the caller just
 * needs to create the database file.
 *
 * If @a path exists and is a directory, it is used.
 * If @a path has a trailing '/' it is assumed to be a directory.
 * Otherwise @a path is assumed to be a file.
 */
static void hcache_per_folder(struct Buffer *hcpath, const char *path,
                              const char *folder, hcache_namer_t namer)
{
  struct stat sb;

  int plen = mutt_str_strlen(path);
  int rc = stat(path, &sb);
  bool slash = (path[plen - 1] == '/');

  if (((rc == 0) && !S_ISDIR(sb.st_mode)) || ((rc == -1) && !slash))
  {
    /* An existing file or a non-existing path not ending with a slash */
    mutt_encode_path(hcpath, path);
    return;
  }

  /* We have a directory - no matter whether it exists, or not */
  struct Buffer *hcfile = mutt_buffer_pool_get();
  if (namer)
  {
    namer(folder, hcfile);
    mutt_buffer_concat_path(hcpath, path, mutt_b2s(hcfile));
  }
  else
  {
    unsigned char m[16]; /* binary md5sum */
    struct Buffer *name = mutt_buffer_pool_get();
#ifdef USE_HCACHE_COMPRESSION
    const char *cm = C_HeaderCacheCompressMethod;
    mutt_buffer_printf(name, "%s|%s%s", hcache_get_ops()->name, folder, cm ? cm : "");
#else
    mutt_buffer_printf(name, "%s|%s", hcache_get_ops()->name, folder);
#endif
    mutt_md5(mutt_b2s(name), m);
    mutt_buffer_reset(name);
    mutt_md5_toascii(m, name->data);
    mutt_buffer_printf(hcpath, "%s%s%s", path, slash ? "" : "/", mutt_b2s(name));
    mutt_buffer_pool_release(&name);
  }

  mutt_encode_path(hcpath, mutt_b2s(hcpath));
  create_hcache_dir(mutt_b2s(hcpath));
  mutt_buffer_pool_release(&hcfile);
}

/**
 * get_foldername - Where should the cache be stored?
 * @param folder Path to be canonicalised
 * @retval ptr New string with canonical path
 */
static char *get_foldername(const char *folder)
{
  /* if the folder is local, canonify the path to avoid
   * to ensure equivalent paths share the hcache */
  char *p = mutt_mem_malloc(PATH_MAX + 1);
  if (!realpath(folder, p))
    mutt_str_replace(&p, folder);

  return p;
}

/**
 * mutt_hcache_open - Multiplexor for HcacheOps::open
 */
header_cache_t *mutt_hcache_open(const char *path, const char *folder, hcache_namer_t namer)
{
  const struct HcacheOps *ops = hcache_get_ops();
  if (!ops)
    return NULL;

  header_cache_t *hc = mutt_mem_calloc(1, sizeof(header_cache_t));

  /* Calculate the current hcache version from dynamic configuration */
  if (hcachever == 0x0)
  {
    union {
      unsigned char charval[16];
      unsigned int intval;
    } digest;
    struct Md5Ctx md5ctx;

    hcachever = HCACHEVER;

    mutt_md5_init_ctx(&md5ctx);

    /* Seed with the compiled-in header structure hash */
    mutt_md5_process_bytes(&hcachever, sizeof(hcachever), &md5ctx);

    /* Mix in user's spam list */
    struct Replace *sp = NULL;
    STAILQ_FOREACH(sp, &SpamList, entries)
    {
      mutt_md5_process(sp->regex->pattern, &md5ctx);
      mutt_md5_process(sp->templ, &md5ctx);
    }

    /* Mix in user's nospam list */
    struct RegexNode *np = NULL;
    STAILQ_FOREACH(np, &NoSpamList, entries)
    {
      mutt_md5_process(np->regex->pattern, &md5ctx);
    }

    /* Get a hash and take its bytes as an (unsigned int) hash version */
    mutt_md5_finish_ctx(&md5ctx, digest.charval);
    hcachever = digest.intval;
  }

#ifdef USE_HCACHE_COMPRESSION
  if (C_HeaderCacheCompressMethod)
  {
    const struct ComprOps *cops = compr_get_ops();

    hc->cctx = cops->open();
    if (!hc->cctx)
    {
      FREE(&hc);
      return NULL;
    }

    /* remember the buffer of database backend */
    hc->ondisk = NULL;
  }
#endif

  hc->folder = get_foldername(folder);
  hc->crc = hcachever;

  if (!path || (path[0] == '\0'))
  {
    FREE(&hc->folder);
    FREE(&hc);
    return NULL;
  }

  struct Buffer *hcpath = mutt_buffer_pool_get();
  hcache_per_folder(hcpath, path, hc->folder, namer);

  hc->ctx = ops->open(mutt_b2s(hcpath));
  if (!hc->ctx)
  {
    /* remove a possibly incompatible version */
    if (unlink(mutt_b2s(hcpath)) == 0)
    {
      hc->ctx = ops->open(mutt_b2s(hcpath));
      if (!hc->ctx)
      {
        FREE(&hc->folder);
        FREE(&hc);
      }
    }
  }

  mutt_buffer_pool_release(&hcpath);
  return hc;
}

/**
 * mutt_hcache_close - Multiplexor for HcacheOps::close
 */
void mutt_hcache_close(header_cache_t *hc)
{
  const struct HcacheOps *ops = hcache_get_ops();
  if (!hc || !ops)
    return;

#ifdef USE_HCACHE_COMPRESSION
  if (C_HeaderCacheCompressMethod)
    compr_get_ops()->close(&hc->cctx);
#endif

  ops->close(&hc->ctx);
  FREE(&hc->folder);
  FREE(&hc);
}

/**
 * mutt_hcache_fetch - Multiplexor for HcacheOps::fetch
 */
void *mutt_hcache_fetch(header_cache_t *hc, const char *key, size_t keylen)
{
  void *data = mutt_hcache_fetch_raw(hc, key, keylen);
  if (!data)
  {
    return NULL;
  }

  if (!crc_matches(data, hc->crc))
  {
    mutt_hcache_free(hc, &data);
    return NULL;
  }

  return data;
}

/**
 * mutt_hcache_fetch_raw - Fetch a message's header from the cache
 * @param hc     Pointer to the header_cache_t structure got by mutt_hcache_open()
 * @param key    Message identification string
 * @param keylen Length of the string pointed to by key
 * @retval ptr  Success, the data if found
 * @retval NULL Otherwise
 *
 * @note This function does not perform any check on the validity of the data
 *       found.
 * @note The returned pointer must be freed by calling mutt_hcache_free. This
 *       must be done before closing the header cache with mutt_hcache_close.
 */
void *mutt_hcache_fetch_raw(header_cache_t *hc, const char *key, size_t keylen)
{
  const struct HcacheOps *ops = hcache_get_ops();

  if (!hc || !ops)
    return NULL;

  struct Buffer path = mutt_buffer_make(1024);
  size_t dlen;
  keylen = mutt_buffer_printf(&path, "%s%s", hc->folder, key);
  void *blob = ops->fetch(hc->ctx, mutt_b2s(&path), keylen, &dlen);
  mutt_buffer_dealloc(&path);

#ifdef USE_HCACHE_COMPRESSION
  if (C_HeaderCacheCompressMethod && blob != NULL)
  {
    const struct ComprOps *cops = compr_get_ops();
    hc->ondisk = blob;
    blob = cops->decompress(hc->cctx, blob, dlen);
  }
#endif

  return blob;
}

/**
 * mutt_hcache_free - Multiplexor for HcacheOps::free
 */
void mutt_hcache_free(header_cache_t *hc, void **data)
{
  const struct HcacheOps *ops = hcache_get_ops();

  if (!hc || !ops)
    return;

#ifdef USE_HCACHE_COMPRESSION
  /* give back the buffer returned by backend */
  if (C_HeaderCacheCompressMethod && hc->ondisk)
  {
    *data = hc->ondisk;
    hc->ondisk = NULL;
  }
#endif

  ops->free(hc->ctx, data);
}

/**
 * mutt_hcache_store - Multiplexor for HcacheOps::store
 */
int mutt_hcache_store(header_cache_t *hc, const char *key, size_t keylen,
                      struct Email *e, unsigned int uidvalidity)
{
  if (!hc)
    return -1;

  int dlen = 0;

  char *data = mutt_hcache_dump(hc, e, &dlen, uidvalidity);
  int rc = mutt_hcache_store_raw(hc, key, keylen, data, dlen);

  FREE(&data);

  return rc;
}

/**
 * mutt_hcache_store_raw - store a key / data pair
 * @param hc     Pointer to the header_cache_t structure got by mutt_hcache_open()
 * @param key    Message identification string
 * @param keylen Length of the string pointed to by key
 * @param data   Payload to associate with key
 * @param dlen   Length of the buffer pointed to by the @a data parameter
 * @retval 0   success
 * @retval num Generic or backend-specific error code otherwise
 */
int mutt_hcache_store_raw(header_cache_t *hc, const char *key, size_t keylen,
                          void *data, size_t dlen)
{
  const struct HcacheOps *ops = hcache_get_ops();

  if (!hc || !ops)
    return -1;

  struct Buffer path = mutt_buffer_make(1024);

  keylen = mutt_buffer_printf(&path, "%s%s", hc->folder, key);

#ifdef USE_HCACHE_COMPRESSION
  if (C_HeaderCacheCompressMethod)
  {
    /* data/dlen gets ptr to compressed data here */
    const struct ComprOps *cops = compr_get_ops();
    data = cops->compress(hc->cctx, data, dlen, &dlen);
  }
#endif

  /* store uncompressed data */
  int rc = ops->store(hc->ctx, mutt_b2s(&path), keylen, data, dlen);
  mutt_buffer_dealloc(&path);

  return rc;
}

/**
 * mutt_hcache_delete_header - Multiplexor for HcacheOps::delete_header
 */
int mutt_hcache_delete_header(header_cache_t *hc, const char *key, size_t keylen)
{
  const struct HcacheOps *ops = hcache_get_ops();
  if (!hc)
    return -1;

  struct Buffer path = mutt_buffer_make(1024);

  keylen = mutt_buffer_printf(&path, "%s%s", hc->folder, key);

  int rc = ops->delete_header(hc->ctx, mutt_b2s(&path), keylen);
  mutt_buffer_dealloc(&path);
  return rc;
}

/**
 * mutt_hcache_backend_list - Get a list of backend names
 * @retval ptr Comma-space-separated list of names
 *
 * The caller should free the string.
 */
const char *mutt_hcache_backend_list(void)
{
  char tmp[256] = { 0 };
  const struct HcacheOps **ops = hcache_ops;
  size_t len = 0;

  for (; *ops; ops++)
  {
    if (len != 0)
    {
      len += snprintf(tmp + len, sizeof(tmp) - len, ", ");
    }
    len += snprintf(tmp + len, sizeof(tmp) - len, "%s", (*ops)->name);
  }

  return mutt_str_strdup(tmp);
}

/**
 * mutt_hcache_is_valid_backend - Is the string a valid hcache backend
 * @param s String identifying a backend
 * @retval true  s is recognized as a valid backend
 * @retval false otherwise
 */
bool mutt_hcache_is_valid_backend(const char *s)
{
  return hcache_get_backend_ops(s);
}
