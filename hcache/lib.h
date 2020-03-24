/**
 * @file
 * Header cache multiplexor
 *
 * @authors
 * Copyright (C) 2004 Thomas Glanzmann <sithglan@stud.uni-erlangen.de>
 * Copyright (C) 2004 Tobias Werth <sitowert@stud.uni-erlangen.de>
 * Copyright (C) 2004 Brian Fundakowski Feldman <green@FreeBSD.org>
 * Copyright (C) 2016 Pietro Cerutti <gahr@gahr.ch>
 * Copyright (C) 2020 Tino Reichardt <milky-neomutt@mcmilk.de>
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
 * @page hcache HCACHE: Header cache API
 *
 * Header cache API
 *
 * This module defines the user-visible header cache API, which is used within
 * neomutt to cache and restore mail header data.
 *
 * @subpage hc_serial
 *
 * @subpage hc_hcache
 *
 * Backends:
 *
 * | File          | Description      |
 * | :------------ | :--------------- |
 * | hcache/bdb.c  | @subpage hc_bdb  |
 * | hcache/gdbm.c | @subpage hc_gdbm |
 * | hcache/kc.c   | @subpage hc_kc   |
 * | hcache/lmdb.c | @subpage hc_lmdb |
 * | hcache/qdbm.c | @subpage hc_qdbm |
 * | hcache/tc.c   | @subpage hc_tc   |
 */

#ifndef MUTT_HCACHE_LIB_H
#define MUTT_HCACHE_LIB_H

#include <stddef.h>
#include <stdbool.h>
#include "compress/lib.h"

struct Buffer;
struct Email;

/**
 * struct EmailCache - header cache structure
 *
 * This struct holds both the backend-agnostic and the backend-specific parts
 * of the header cache. Backend code MUST initialize the fetch, store,
 * delete and close function pointers in hcache_open, and MAY store
 * backend-specific context in the ctx pointer.
 */
struct EmailCache
{
  char *folder;
  unsigned int crc;
  void *ctx;
  void *cctx;
};

typedef struct EmailCache header_cache_t;

/**
 * struct HCacheEntry - Wrapper for Email retrieved from the header cache
 */
struct HCacheEntry
{
  size_t uidvalidity;  ///< IMAP-specific UIDVALIDITY
  unsigned int crc;    ///< CRC of Email/Body/etc structs
  struct Email *email; ///< Retrieved email
};

/**
 * typedef hcache_namer_t - Prototype for function to compose hcache file names
 * @param path    Path of message
 * @param dest    Buffer for filename
 */
typedef void (*hcache_namer_t)(const char *path, struct Buffer *dest);

/* These Config Variables are only used in hcache/hcache.c */
extern char *C_HeaderCacheBackend;
extern short C_HeaderCacheCompressLevel;
extern char *C_HeaderCacheCompressMethod;

/**
 * mutt_hcache_open - open the connection to the header cache
 * @param path   Location of the header cache (often as specified by the user)
 * @param folder Name of the folder containing the messages
 * @param namer  Optional (might be NULL) client-specific function to form the
 *               final name of the hcache database file.
 * @retval ptr  Success, header_cache_t struct
 * @retval NULL Otherwise
 */
header_cache_t *mutt_hcache_open(const char *path, const char *folder, hcache_namer_t namer);

/**
 * mutt_hcache_close - close the connection to the header cache
 * @param hc Pointer to the header_cache_t structure got by mutt_hcache_open()
 */
void mutt_hcache_close(header_cache_t *hc);

/**
 * mutt_hcache_store - store a Header along with a validity datum
 * @param hc          Pointer to the header_cache_t structure got by mutt_hcache_open()
 * @param key         Message identification string
 * @param keylen      Length of the key string
 * @param e           Email to store
 * @param uidvalidity IMAP-specific UIDVALIDITY value, or 0 to use the current time
 * @retval 0   Success
 * @retval num Generic or backend-specific error code otherwise
 */
int mutt_hcache_store(header_cache_t *hc, const char *key, size_t keylen,
                      struct Email *e, unsigned int uidvalidity);

/**
 * mutt_hcache_fetch - fetch and validate a  message's header from the cache
 * @param hc     Pointer to the header_cache_t structure got by mutt_hcache_open()
 * @param key    Message identification string
 * @param keylen Length of the string pointed to by key
 * @param uidvalidity Only restore if it matches the stored uidvalidity
 * @retval obj Success, HCacheEntry containing an Email
 * @retval obj Failure, empty HCacheEntry
 *
 * @note This function performs a check on the validity of the data found by
 *       comparing it with the crc value of the header_cache_t structure.
 */
struct HCacheEntry mutt_hcache_fetch(header_cache_t *hc, const char *key, size_t keylen, unsigned int uidvalidity);

int mutt_hcache_store_raw(header_cache_t *hc, const char *key, size_t keylen,
                          void *data, size_t dlen);

void *mutt_hcache_fetch_raw(header_cache_t *hc, const char *key, size_t keylen, size_t *dlen);

/**
 * mutt_hcache_free_raw - free data fetched with mutt_hcache_fetch_raw()
 * @param hc   Pointer to the header_cache_t structure got by mutt_hcache_open()
 * @param data Pointer to the data got using mutt_hcache_fetch_raw
 */
void mutt_hcache_free_raw(header_cache_t *hc, void **data);

/**
 * mutt_hcache_delete_header - delete a key / data pair
 * @param hc     Pointer to the header_cache_t structure got by mutt_hcache_open()
 * @param key    Message identification string
 * @param keylen Length of the string pointed to by key
 * @retval 0   Success
 * @retval num Generic or backend-specific error code otherwise
 */
int mutt_hcache_delete_header(header_cache_t *hc, const char *key, size_t keylen);

/**
 * mutt_hcache_backend_list - get a list of backend identification strings
 * @retval ptr Comma separated string describing the compiled-in backends
 *
 * @note The returned string must be free'd by the caller
 */
const char *mutt_hcache_backend_list(void);
#ifdef USE_HCACHE_COMPRESSION
const char *mutt_hcache_compress_list(void);
#endif

bool mutt_hcache_is_valid_backend(const char *s);

#endif /* MUTT_HCACHE_LIB_H */
