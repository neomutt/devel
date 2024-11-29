/**
 * @file
 * Ncrypt Expando definitions
 *
 * @authors
 * Copyright (C) 2024 Richard Russon <rich@flatcap.org>
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
 * @page ncrypt_expando_pgp Ncrypt Expando definitions
 *
 * Ncrypt Expando definitions
 */

#include <stdbool.h>
#include <stdio.h>
#include "private.h"
#include "mutt/lib.h"
#include "core/lib.h"
#include "expando_pgp.h"
#include "lib.h"
#include "expando/lib.h"
#include "pgp.h"
#include "pgpkey.h"
#include "pgplib.h"

/// Characters used to show the trust level for PGP keys
static const char TrustFlags[] = "?- +";

/**
 * pgp_flags - Turn PGP key flags into a string
 * @param flags Flags, see #KeyFlags
 * @retval char Flag character
 */
static char pgp_flags(KeyFlags flags)
{
  if (flags & KEYFLAG_REVOKED)
    return 'R';
  if (flags & KEYFLAG_EXPIRED)
    return 'X';
  if (flags & KEYFLAG_DISABLED)
    return 'd';
  if (flags & KEYFLAG_CRITICAL)
    return 'c';

  return ' ';
}

/**
 * pgp_entry_ignore - PGP: Field not supported - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void pgp_entry_ignore(const struct ExpandoNode *node, void *data,
                             MuttFormatFlags flags, struct Buffer *buf)
{
}

/**
 * pgp_entry_number_num - PGP: Index number - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long pgp_entry_number_num(const struct ExpandoNode *node, void *data, MuttFormatFlags flags)
{
  const struct PgpEntry *entry = data;
  return entry->num;
}

/**
 * pgp_entry_trust - PGP: Trust/validity - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void pgp_entry_trust(const struct ExpandoNode *node, void *data,
                            MuttFormatFlags flags, struct Buffer *buf)
{
  const struct PgpEntry *entry = data;
  const struct PgpUid *uid = entry->uid;

  buf_printf(buf, "%c", TrustFlags[uid->trust & 0x03]);
}

/**
 * pgp_entry_user_id - PGP: User id - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void pgp_entry_user_id(const struct ExpandoNode *node, void *data,
                              MuttFormatFlags flags, struct Buffer *buf)
{
  const struct PgpEntry *entry = data;
  const struct PgpUid *uid = entry->uid;

  const char *s = uid->addr;
  buf_strcpy(buf, s);
}

/**
 * pgp_key_abilities - Turn PGP key abilities into a string
 * @param flags Flags, see #KeyFlags
 * @retval ptr Abilities string
 *
 * @note This returns a pointer to a static buffer
 */
static char *pgp_key_abilities(KeyFlags flags)
{
  static char buf[3];

  if (!(flags & KEYFLAG_CANENCRYPT))
    buf[0] = '-';
  else if (flags & KEYFLAG_PREFER_SIGNING)
    buf[0] = '.';
  else
    buf[0] = 'e';

  if (!(flags & KEYFLAG_CANSIGN))
    buf[1] = '-';
  else if (flags & KEYFLAG_PREFER_ENCRYPTION)
    buf[1] = '.';
  else
    buf[1] = 's';

  buf[2] = '\0';

  return buf;
}

/**
 * pgp_key_algorithm - PGP: Key Algorithm - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void pgp_key_algorithm(const struct ExpandoNode *node, void *data,
                              MuttFormatFlags flags, struct Buffer *buf)
{
  const struct PgpEntry *entry = data;
  const struct PgpUid *uid = entry->uid;
  const struct PgpKeyInfo *key = uid->parent;

  const char *s = key->algorithm;
  buf_strcpy(buf, s);
}

/**
 * pgp_key_capabilities - PGP: Key Capabilities - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void pgp_key_capabilities(const struct ExpandoNode *node, void *data,
                                 MuttFormatFlags flags, struct Buffer *buf)
{
  const struct PgpEntry *entry = data;
  const struct PgpUid *uid = entry->uid;
  const struct PgpKeyInfo *key = uid->parent;

  const KeyFlags kflags = key->flags | uid->flags;

  const char *s = pgp_key_abilities(kflags);
  buf_strcpy(buf, s);
}

/**
 * pgp_key_date - PGP: Date of the key - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void pgp_key_date(const struct ExpandoNode *node, void *data,
                         MuttFormatFlags flags, struct Buffer *buf)
{
  const struct PgpEntry *entry = data;
  const struct PgpUid *uid = entry->uid;
  const struct PgpKeyInfo *key = uid->parent;

  bool use_c_locale = false;
  const char *text = node->text;
  if (*text == '!')
  {
    use_c_locale = true;
    text++;
  }

  char tmp[128] = { 0 };
  if (use_c_locale)
  {
    mutt_date_localtime_format_locale(tmp, sizeof(tmp), text, key->gen_time,
                                      NeoMutt->time_c_locale);
  }
  else
  {
    mutt_date_localtime_format(tmp, sizeof(tmp), text, key->gen_time);
  }

  buf_strcpy(buf, tmp);
}

/**
 * pgp_key_date_num - PGP: Date of the key - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long pgp_key_date_num(const struct ExpandoNode *node, void *data, MuttFormatFlags flags)
{
  const struct PgpEntry *entry = data;
  const struct PgpUid *uid = entry->uid;
  const struct PgpKeyInfo *key = uid->parent;

  return key->gen_time;
}

/**
 * pgp_key_flags - PGP: Key Flags - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void pgp_key_flags(const struct ExpandoNode *node, void *data,
                          MuttFormatFlags flags, struct Buffer *buf)
{
  const struct PgpEntry *entry = data;
  const struct PgpUid *uid = entry->uid;
  const struct PgpKeyInfo *key = uid->parent;

  const KeyFlags kflags = key->flags | uid->flags;

  buf_printf(buf, "%c", pgp_flags(kflags));
}

/**
 * pgp_key_id - PGP: Key id - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void pgp_key_id(const struct ExpandoNode *node, void *data,
                       MuttFormatFlags flags, struct Buffer *buf)
{
  const struct PgpEntry *entry = data;
  const struct PgpUid *uid = entry->uid;
  struct PgpKeyInfo *key = uid->parent;

  const char *s = pgp_this_keyid(key);
  buf_strcpy(buf, s);
}

/**
 * pgp_key_length_num - PGP: Key length - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long pgp_key_length_num(const struct ExpandoNode *node, void *data, MuttFormatFlags flags)
{
  const struct PgpEntry *entry = data;
  const struct PgpUid *uid = entry->uid;
  const struct PgpKeyInfo *key = uid->parent;

  return key->keylen;
}

/**
 * pgp_pkey_algorithm - PGP: Principal Key Algorithm - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void pgp_pkey_algorithm(const struct ExpandoNode *node, void *data,
                               MuttFormatFlags flags, struct Buffer *buf)
{
  const struct PgpEntry *entry = data;
  const struct PgpUid *uid = entry->uid;
  struct PgpKeyInfo *key = uid->parent;
  struct PgpKeyInfo *pkey = pgp_principal_key(key);

  const char *s = pkey->algorithm;
  buf_strcpy(buf, s);
}

/**
 * pgp_pkey_capabilities - PGP: Principal Key Capabilities - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void pgp_pkey_capabilities(const struct ExpandoNode *node, void *data,
                                  MuttFormatFlags flags, struct Buffer *buf)
{
  const struct PgpEntry *entry = data;
  const struct PgpUid *uid = entry->uid;
  struct PgpKeyInfo *key = uid->parent;
  struct PgpKeyInfo *pkey = pgp_principal_key(key);

  const KeyFlags kflags = (pkey->flags & KEYFLAG_RESTRICTIONS) | uid->flags;

  const char *s = pgp_key_abilities(kflags);
  buf_strcpy(buf, s);
}

/**
 * pgp_pkey_flags - PGP: Principal Key Flags - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void pgp_pkey_flags(const struct ExpandoNode *node, void *data,
                           MuttFormatFlags flags, struct Buffer *buf)
{
  const struct PgpEntry *entry = data;
  const struct PgpUid *uid = entry->uid;
  struct PgpKeyInfo *key = uid->parent;
  struct PgpKeyInfo *pkey = pgp_principal_key(key);

  const KeyFlags kflags = (pkey->flags & KEYFLAG_RESTRICTIONS) | uid->flags;

  buf_printf(buf, "%c", pgp_flags(kflags));
}

/**
 * pgp_pkey_id - PGP: Principal Key id - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void pgp_pkey_id(const struct ExpandoNode *node, void *data,
                        MuttFormatFlags flags, struct Buffer *buf)
{
  const struct PgpEntry *entry = data;
  const struct PgpUid *uid = entry->uid;
  struct PgpKeyInfo *key = uid->parent;
  struct PgpKeyInfo *pkey = pgp_principal_key(key);

  const char *s = pgp_this_keyid(pkey);
  buf_strcpy(buf, s);
}

/**
 * pgp_pkey_length_num - PGP: Principal Key length - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long pgp_pkey_length_num(const struct ExpandoNode *node, void *data, MuttFormatFlags flags)
{
  const struct PgpEntry *entry = data;
  const struct PgpUid *uid = entry->uid;
  struct PgpKeyInfo *key = uid->parent;
  struct PgpKeyInfo *pkey = pgp_principal_key(key);

  return pkey->keylen;
}

/**
 * PgpEntryRenderCallbacks1 - Callbacks for PGP Key Expandos
 *
 * @sa PgpEntryFormatDef, ExpandoDataGlobal, ExpandoDataPgp, ExpandoDataPgpKey
 */
const struct ExpandoRenderCallback PgpEntryRenderCallbacks1[] = {
  // clang-format off
  { ED_PGP,     ED_PGP_NUMBER,            NULL,                  pgp_entry_number_num },
  { ED_PGP,     ED_PGP_TRUST,             pgp_entry_trust,       NULL },
  { ED_PGP,     ED_PGP_USER_ID,           pgp_entry_user_id,     NULL },
  { -1, -1, NULL, NULL },
  // clang-format on
};

/**
 * PgpEntryRenderCallbacks2 - Callbacks for PGP Key Expandos
 *
 * @sa PgpEntryFormatDef, ExpandoDataGlobal, ExpandoDataPgp, ExpandoDataPgpKey
 */
const struct ExpandoRenderCallback PgpEntryRenderCallbacks2[] = {
  // clang-format off
  { ED_PGP_KEY, ED_PGK_DATE,              pgp_key_date,          pgp_key_date_num },
  { ED_PGP_KEY, ED_PGK_KEY_ALGORITHM,     pgp_key_algorithm,     NULL },
  { ED_PGP_KEY, ED_PGK_KEY_CAPABILITIES,  pgp_key_capabilities,  NULL },
  { ED_PGP_KEY, ED_PGK_KEY_FINGERPRINT,   pgp_entry_ignore,      NULL },
  { ED_PGP_KEY, ED_PGK_KEY_FLAGS,         pgp_key_flags,         NULL },
  { ED_PGP_KEY, ED_PGK_KEY_ID,            pgp_key_id,            NULL },
  { ED_PGP_KEY, ED_PGK_KEY_LENGTH,        NULL,                  pgp_key_length_num },
  { ED_PGP_KEY, ED_PGK_PKEY_ALGORITHM,    pgp_pkey_algorithm,    NULL },
  { ED_PGP_KEY, ED_PGK_PKEY_CAPABILITIES, pgp_pkey_capabilities, NULL },
  { ED_PGP_KEY, ED_PGK_PKEY_FINGERPRINT,  pgp_entry_ignore,      NULL },
  { ED_PGP_KEY, ED_PGK_PKEY_FLAGS,        pgp_pkey_flags,        NULL },
  { ED_PGP_KEY, ED_PGK_PKEY_ID,           pgp_pkey_id,           NULL },
  { ED_PGP_KEY, ED_PGK_PKEY_LENGTH,       NULL,                  pgp_pkey_length_num },
  { ED_PGP_KEY, ED_PGK_PROTOCOL,          pgp_entry_ignore,      NULL },
  { -1, -1, NULL, NULL },
  // clang-format on
};
