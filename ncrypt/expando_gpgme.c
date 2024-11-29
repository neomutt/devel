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
 * @page ncrypt_expando_gpgme Ncrypt Expando definitions
 *
 * Ncrypt Expando definitions
 */

#include <gpgme.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>
#include "private.h"
#include "mutt/lib.h"
#include "core/lib.h"
#include "expando_gpgme.h"
#include "lib.h"
#include "expando/lib.h"
#include "crypt_gpgme.h"
#include "pgplib.h"

/**
 * crypt_key_abilities - Parse key flags into a string
 * @param flags Flags, see #KeyFlags
 * @retval ptr Flag string
 *
 * @note The string is statically allocated.
 */
static char *crypt_key_abilities(KeyFlags flags)
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
 * crypt_flags - Parse the key flags into a single character
 * @param flags Flags, see #KeyFlags
 * @retval char Flag character
 *
 * The returned character describes the most important flag.
 */
static char *crypt_flags(KeyFlags flags)
{
  if (flags & KEYFLAG_REVOKED)
    return "R";
  if (flags & KEYFLAG_EXPIRED)
    return "X";
  if (flags & KEYFLAG_DISABLED)
    return "d";
  if (flags & KEYFLAG_CRITICAL)
    return "c";

  return " ";
}

/**
 * gpgme_entry_number_num - GPGME: Index number - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long gpgme_entry_number_num(const struct ExpandoNode *node, void *data, MuttFormatFlags flags)
{
  const struct CryptEntry *entry = data;
  return entry->num;
}

/**
 * gpgme_entry_trust - GPGME: Trust/validity - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void gpgme_entry_trust(const struct ExpandoNode *node, void *data,
                              MuttFormatFlags flags, struct Buffer *buf)
{
  const struct CryptEntry *entry = data;
  const struct CryptKeyInfo *key = entry->key;

  const char *s = "";
  if ((key->flags & KEYFLAG_ISX509))
  {
    s = "x";
  }
  else
  {
    switch (key->validity)
    {
      case GPGME_VALIDITY_FULL:
        s = "f";
        break;
      case GPGME_VALIDITY_MARGINAL:
        s = "m";
        break;
      case GPGME_VALIDITY_NEVER:
        s = "n";
        break;
      case GPGME_VALIDITY_ULTIMATE:
        s = "u";
        break;
      case GPGME_VALIDITY_UNDEFINED:
        s = "q";
        break;
      case GPGME_VALIDITY_UNKNOWN:
      default:
        s = "?";
        break;
    }
  }

  buf_strcpy(buf, s);
}

/**
 * gpgme_entry_user_id - GPGME: User id - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void gpgme_entry_user_id(const struct ExpandoNode *node, void *data,
                                MuttFormatFlags flags, struct Buffer *buf)
{
  const struct CryptEntry *entry = data;
  const struct CryptKeyInfo *key = entry->key;

  const char *s = key->uid;
  buf_strcpy(buf, s);
}

/**
 * gpgme_key_algorithm - GPGME: Key Algorithm - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void gpgme_key_algorithm(const struct ExpandoNode *node, void *data,
                                MuttFormatFlags flags, struct Buffer *buf)
{
  const struct CryptEntry *entry = data;
  const struct CryptKeyInfo *key = entry->key;

  const char *s = NULL;
  if (key->kobj->subkeys)
    s = gpgme_pubkey_algo_name(key->kobj->subkeys->pubkey_algo);
  else
    s = "?";

  buf_strcpy(buf, s);
}

/**
 * gpgme_key_capabilities - GPGME: Key Capabilities - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void gpgme_key_capabilities(const struct ExpandoNode *node, void *data,
                                   MuttFormatFlags flags, struct Buffer *buf)
{
  const struct CryptEntry *entry = data;
  const struct CryptKeyInfo *key = entry->key;

  const char *s = crypt_key_abilities(key->flags);
  buf_strcpy(buf, s);
}

/**
 * gpgme_key_date - GPGME: Date of the key - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void gpgme_key_date(const struct ExpandoNode *node, void *data,
                           MuttFormatFlags flags, struct Buffer *buf)
{
  const struct CryptEntry *entry = data;
  const struct CryptKeyInfo *key = entry->key;

  const char *text = node->text;
  bool use_c_locale = false;
  if (*text == '!')
  {
    use_c_locale = true;
    text++;
  }

  struct tm tm = { 0 };
  if (key->kobj->subkeys && (key->kobj->subkeys->timestamp > 0))
  {
    tm = mutt_date_localtime(key->kobj->subkeys->timestamp);
  }
  else
  {
    tm = mutt_date_localtime(0); // Default to 1970-01-01
  }

  char tmp[128] = { 0 };
  if (use_c_locale)
  {
    strftime_l(tmp, sizeof(tmp), text, &tm, NeoMutt->time_c_locale);
  }
  else
  {
    strftime(tmp, sizeof(tmp), text, &tm);
  }

  buf_strcpy(buf, tmp);
}

/**
 * gpgme_key_date_num - GPGME: Date of the key - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long gpgme_key_date_num(const struct ExpandoNode *node, void *data, MuttFormatFlags flags)
{
  const struct CryptEntry *entry = data;
  const struct CryptKeyInfo *key = entry->key;
  return key->kobj->subkeys->timestamp;
}

/**
 * gpgme_key_fingerprint - GPGME: Key fingerprint - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void gpgme_key_fingerprint(const struct ExpandoNode *node, void *data,
                                  MuttFormatFlags flags, struct Buffer *buf)
{
  const struct CryptEntry *entry = data;
  struct CryptKeyInfo *key = entry->key;

  /* fixme: we need a way to distinguish between main and subkeys.
   * Store the idx in entry? */
  const char *s = crypt_fpr_or_lkeyid(key);
  buf_strcpy(buf, s);
}

/**
 * gpgme_key_flags - GPGME: Key Flags - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void gpgme_key_flags(const struct ExpandoNode *node, void *data,
                            MuttFormatFlags flags, struct Buffer *buf)
{
  const struct CryptEntry *entry = data;
  const struct CryptKeyInfo *key = entry->key;

  const char *s = crypt_flags(key->flags);
  buf_strcpy(buf, s);
}

/**
 * gpgme_key_id - GPGME: Key id - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void gpgme_key_id(const struct ExpandoNode *node, void *data,
                         MuttFormatFlags flags, struct Buffer *buf)
{
  const struct CryptEntry *entry = data;
  struct CryptKeyInfo *key = entry->key;

  /* fixme: we need a way to distinguish between main and subkeys.
   * Store the idx in entry? */
  const char *s = crypt_keyid(key);
  buf_strcpy(buf, s);
}

/**
 * gpgme_key_length_num - GPGME: Key length - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long gpgme_key_length_num(const struct ExpandoNode *node, void *data, MuttFormatFlags flags)
{
  const struct CryptEntry *entry = data;
  const struct CryptKeyInfo *key = entry->key;

  return key->kobj->subkeys ? key->kobj->subkeys->length : 0;
}

/**
 * gpgme_key_protocol - GPGME: Protocol - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void gpgme_key_protocol(const struct ExpandoNode *node, void *data,
                               MuttFormatFlags flags, struct Buffer *buf)
{
  const struct CryptEntry *entry = data;
  const struct CryptKeyInfo *key = entry->key;

  const char *s = gpgme_get_protocol_name(key->kobj->protocol);
  buf_strcpy(buf, s);
}

/**
 * PgpEntryGpgmeRenderCallbacks1 - Callbacks for GPGME Key Expandos
 *
 * @sa PgpEntryFormatDef, ExpandoDataGlobal, ExpandoDataPgpKeyGpgme
 */
const struct ExpandoRenderCallback PgpEntryGpgmeRenderCallbacks1[] = {
  // clang-format off
  { ED_PGP,     ED_PGP_NUMBER,            NULL,                   gpgme_entry_number_num },
  { ED_PGP,     ED_PGP_TRUST,             gpgme_entry_trust,      NULL },
  { ED_PGP,     ED_PGP_USER_ID,           gpgme_entry_user_id,    NULL },
  { -1, -1, NULL, NULL },
  // clang-format on
};

/**
 * PgpEntryGpgmeRenderCallbacks2 - Callbacks for GPGME Key Expandos
 *
 * @sa PgpEntryFormatDef, ExpandoDataGlobal, ExpandoDataPgpKeyGpgme
 */
const struct ExpandoRenderCallback PgpEntryGpgmeRenderCallbacks2[] = {
  // clang-format off
  { ED_PGP_KEY, ED_PGK_DATE,              gpgme_key_date,         gpgme_key_date_num },
  { ED_PGP_KEY, ED_PGK_DATE,              gpgme_key_date,         gpgme_key_date_num },
  { ED_PGP_KEY, ED_PGK_KEY_ALGORITHM,     gpgme_key_algorithm,    NULL },
  { ED_PGP_KEY, ED_PGK_KEY_CAPABILITIES,  gpgme_key_capabilities, NULL },
  { ED_PGP_KEY, ED_PGK_KEY_FINGERPRINT,   gpgme_key_fingerprint,  NULL },
  { ED_PGP_KEY, ED_PGK_KEY_FLAGS,         gpgme_key_flags,        NULL },
  { ED_PGP_KEY, ED_PGK_KEY_ID,            gpgme_key_id,           NULL },
  { ED_PGP_KEY, ED_PGK_KEY_LENGTH,        NULL,                   gpgme_key_length_num },
  { ED_PGP_KEY, ED_PGK_PKEY_ALGORITHM,    gpgme_key_algorithm,    NULL },
  { ED_PGP_KEY, ED_PGK_PKEY_CAPABILITIES, gpgme_key_capabilities, NULL },
  { ED_PGP_KEY, ED_PGK_PKEY_FINGERPRINT,  gpgme_key_fingerprint,  NULL },
  { ED_PGP_KEY, ED_PGK_PKEY_FLAGS,        gpgme_key_flags,        NULL },
  { ED_PGP_KEY, ED_PGK_PKEY_ID,           gpgme_key_id,           NULL },
  { ED_PGP_KEY, ED_PGK_PKEY_LENGTH,       NULL,                   gpgme_key_length_num },
  { ED_PGP_KEY, ED_PGK_PROTOCOL,          gpgme_key_protocol,     NULL },
  { -1, -1, NULL, NULL },
  // clang-format on
};
