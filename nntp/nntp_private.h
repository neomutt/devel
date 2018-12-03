/**
 * @file
 * Usenet network mailbox type; talk to an NNTP server
 *
 * @authors
 * Copyright (C) 2018 Richard Russon <rich@flatcap.org>
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

#ifndef MUTT_NNTP_NNTP_PRIVATE_H
#define MUTT_NNTP_NNTP_PRIVATE_H

#include <inttypes.h>
#include <stdint.h>
#include "nntp.h"
#ifdef USE_HCACHE
#include "hcache/hcache.h"
#endif

struct Connection;
struct Context;
struct Email;
struct Mailbox;

#define NNTP_PORT 119
#define NNTP_SSL_PORT 563

/**
 * enum NntpStatus - NNTP server return values
 */
enum NntpStatus
{
  NNTP_NONE = 0, ///< No connection to server
  NNTP_OK,       ///< Connected to server
  NNTP_BYE,      ///< Disconnected from server
};

void nntp_acache_free(struct NntpMboxData *mdata);
int  nntp_active_save_cache(struct NntpAccountData *adata);
struct NntpAccountData *nntp_adata_new(struct Connection *conn);
int  nntp_add_group(char *line, void *data);
void nntp_bcache_update(struct NntpMboxData *mdata);
int  nntp_check_new_groups(struct Mailbox *m, struct NntpAccountData *adata);
void nntp_delete_group_cache(struct NntpMboxData *mdata);
struct NntpEmailData *nntp_edata_get(struct Email *e);
void nntp_group_unread_stat(struct NntpMboxData *mdata);
void nntp_hash_destructor_t(int type, void *obj, intptr_t data);
void nntp_mdata_free(void **ptr);
void nntp_newsrc_gen_entries(struct Context *ctx);
int  nntp_open_connection(struct NntpAccountData *adata);
void nntp_article_status(struct Mailbox *m, struct Email *e, char *group, anum_t anum);

#ifdef USE_HCACHE
header_cache_t *nntp_hcache_open(struct NntpMboxData *mdata);
void nntp_hcache_update(struct NntpMboxData *mdata, header_cache_t *hc);
#endif

#endif /* MUTT_NNTP_NNTP_PRIVATE_H */
