/**
 * @file
 * SMIME helper routines
 *
 * @authors
 * Copyright (C) 2017-2024 Richard Russon <rich@flatcap.org>
 * Copyright (C) 2019-2021 Pietro Cerutti <gahr@gahr.ch>
 * Copyright (C) 2020 Lars Haalck <lars.haalck@uni-muenster.de>
 * Copyright (C) 2023 Anna Figueiredo Gomes <navi@vlhl.dev>
 * Copyright (C) 2024 Alejandro Colomar <alx@kernel.org>
 * Copyright (C) 2023-2024 Tóth János <gomba007@gmail.com>
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
 * @page crypt_smime SMIME helper routines
 *
 * SMIME helper routines
 */

#include "config.h"
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include "private.h"
#include "mutt/lib.h"
#include "address/lib.h"
#include "config/lib.h"
#include "email/lib.h"
#include "core/lib.h"
#include "alias/lib.h"
#include "gui/lib.h"
#include "mutt.h"
#include "lib.h"
#include "editor/lib.h"
#include "expando/lib.h"
#include "history/lib.h"
#include "question/lib.h"
#include "send/lib.h"
#include "copy.h"
#include "crypt.h"
#include "cryptglue.h"
#include "expando_smime.h"
#include "globals.h"
#include "handler.h"
#include "mutt_logging.h"
#ifdef CRYPT_BACKEND_CLASSIC_SMIME
#include "smime.h"
#endif

/// Cached Smime Passphrase
static char SmimePass[256];
/// Unix time when #SmimePass expires
static time_t SmimeExpTime = 0; /* when does the cached passphrase expire? */

/// Smime key to use
static struct Buffer SmimeKeyToUse = { 0 };
/// Smime certificate to use
static struct Buffer SmimeCertToUse = { 0 };
/// Smime intermediate certificate to use
static struct Buffer SmimeIntermediateToUse = { 0 };

/**
 * smime_init - Initialise smime globals
 */
void smime_init(void)
{
  buf_alloc(&SmimeKeyToUse, 256);
  buf_alloc(&SmimeCertToUse, 256);
  buf_alloc(&SmimeIntermediateToUse, 256);
}

/**
 * smime_cleanup - Clean up smime globals
 */
void smime_cleanup(void)
{
  buf_dealloc(&SmimeKeyToUse);
  buf_dealloc(&SmimeCertToUse);
  buf_dealloc(&SmimeIntermediateToUse);
}

/**
 * smime_key_free - Free a list of SMIME keys
 * @param[out] keylist List of keys to free
 */
static void smime_key_free(struct SmimeKey **keylist)
{
  if (!keylist)
    return;

  struct SmimeKey *key = NULL;

  while (*keylist)
  {
    key = *keylist;
    *keylist = (*keylist)->next;

    FREE(&key->email);
    FREE(&key->hash);
    FREE(&key->label);
    FREE(&key->issuer);
    FREE(&key);
  }
}

/**
 * smime_copy_key - Copy an SMIME key
 * @param key Key to copy
 * @retval ptr Newly allocated SMIME key
 */
static struct SmimeKey *smime_copy_key(struct SmimeKey *key)
{
  if (!key)
    return NULL;

  struct SmimeKey *copy = NULL;

  copy = MUTT_MEM_CALLOC(1, struct SmimeKey);
  copy->email = mutt_str_dup(key->email);
  copy->hash = mutt_str_dup(key->hash);
  copy->label = mutt_str_dup(key->label);
  copy->issuer = mutt_str_dup(key->issuer);
  copy->trust = key->trust;
  copy->flags = key->flags;

  return copy;
}

/**
 * smime_class_void_passphrase - Forget the cached passphrase - Implements CryptModuleSpecs::void_passphrase() - @ingroup crypto_void_passphrase
 */
void smime_class_void_passphrase(void)
{
  memset(SmimePass, 0, sizeof(SmimePass));
  SmimeExpTime = 0;
}

/**
 * smime_class_valid_passphrase - Ensure we have a valid passphrase - Implements CryptModuleSpecs::valid_passphrase() - @ingroup crypto_valid_passphrase
 */
bool smime_class_valid_passphrase(void)
{
  const time_t now = mutt_date_now();
  if (now < SmimeExpTime)
  {
    /* Use cached copy.  */
    return true;
  }

  smime_class_void_passphrase();

  struct Buffer *buf = buf_pool_get();
  const int rc = mw_get_field(_("Enter S/MIME passphrase:"), buf,
                              MUTT_COMP_PASS | MUTT_COMP_UNBUFFERED, HC_OTHER, NULL, NULL);
  mutt_str_copy(SmimePass, buf_string(buf), sizeof(SmimePass));
  buf_pool_release(&buf);

  if (rc == 0)
  {
    const short c_smime_timeout = cs_subset_number(NeoMutt->sub, "smime_timeout");
    SmimeExpTime = mutt_date_add_timeout(now, c_smime_timeout);
    return true;
  }
  else
  {
    SmimeExpTime = 0;
  }

  return false;
}

/**
 * smime_command - Format an SMIME command string
 * @param buf    Buffer for the result
 * @param cctx   Data to pass to the formatter
 * @param exp    Expando to use
 */
static void smime_command(struct Buffer *buf, struct SmimeCommandContext *cctx,
                          const struct Expando *exp)
{
  struct ExpandoRenderData SmimeCommandRenderData[] = {
    // clang-format off
    { ED_SMIME_CMD, SmimeCommandRenderCallbacks, cctx, MUTT_FORMAT_NO_FLAGS },
    { -1, NULL, NULL, 0 },
    // clang-format on
  };

  expando_render(exp, SmimeCommandRenderData, buf->dsize, buf);
  mutt_debug(LL_DEBUG2, "%s\n", buf_string(buf));
}

/**
 * smime_invoke - Run an SMIME command
 * @param[out] fp_smime_in       stdin  for the command, or NULL (OPTIONAL)
 * @param[out] fp_smime_out      stdout for the command, or NULL (OPTIONAL)
 * @param[out] fp_smime_err      stderr for the command, or NULL (OPTIONAL)
 * @param[in]  fp_smime_infd     stdin  for the command, or -1 (OPTIONAL)
 * @param[in]  fp_smime_outfd    stdout for the command, or -1 (OPTIONAL)
 * @param[in]  fp_smime_errfd    stderr for the command, or -1 (OPTIONAL)
 * @param[in]  fname         Filename to pass to the command
 * @param[in]  sig_fname     Signature filename to pass to the command
 * @param[in]  cryptalg      Encryption algorithm
 * @param[in]  digestalg     Hashing algorithm
 * @param[in]  key           SMIME key
 * @param[in]  certificates  Public certificates
 * @param[in]  intermediates Intermediate certificates
 * @param[in]  exp           Expando format string
 * @retval num PID of the created process
 * @retval -1  Error creating pipes or forking
 *
 * @note `fp_smime_in` has priority over `fp_smime_infd`.
 *       Likewise `fp_smime_out` and `fp_smime_err`.
 */
static pid_t smime_invoke(FILE **fp_smime_in, FILE **fp_smime_out, FILE **fp_smime_err,
                          int fp_smime_infd, int fp_smime_outfd, int fp_smime_errfd,
                          const char *fname, const char *sig_fname, const char *cryptalg,
                          const char *digestalg, const char *key, const char *certificates,
                          const char *intermediates, const struct Expando *exp)
{
  struct SmimeCommandContext cctx = { 0 };

  if (!exp)
    return (pid_t) -1;

  cctx.fname = fname;
  cctx.sig_fname = sig_fname;
  cctx.key = key;
  cctx.cryptalg = cryptalg;
  cctx.digestalg = digestalg;
  cctx.certificates = certificates;
  cctx.intermediates = intermediates;

  struct Buffer *cmd = buf_pool_get();
  smime_command(cmd, &cctx, exp);

  pid_t pid = filter_create_fd(buf_string(cmd), fp_smime_in, fp_smime_out, fp_smime_err,
                               fp_smime_infd, fp_smime_outfd, fp_smime_errfd, EnvList);
  buf_pool_release(&cmd);
  return pid;
}

/**
 * smime_parse_key - Parse an SMIME key block
 * @param buf String to parse
 * @retval ptr  SMIME key
 * @retval NULL Error
 */
static struct SmimeKey *smime_parse_key(char *buf)
{
  char *pend = NULL, *p = NULL;
  int field = 0;

  struct SmimeKey *key = MUTT_MEM_CALLOC(1, struct SmimeKey);

  for (p = buf; p; p = pend)
  {
    /* Some users manually maintain their .index file, and use a tab
     * as a delimiter, which the old parsing code (using fscanf)
     * happened to allow.  smime_keys uses a space, so search for both.  */
    if ((pend = strchr(p, ' ')) || (pend = strchr(p, '\t')) || (pend = strchr(p, '\n')))
      *pend++ = 0;

    /* For backward compatibility, don't count consecutive delimiters
     * as an empty field.  */
    if (*p == '\0')
      continue;

    field++;

    switch (field)
    {
      case 1: /* mailbox */
        key->email = mutt_str_dup(p);
        break;
      case 2: /* hash */
        key->hash = mutt_str_dup(p);
        break;
      case 3: /* label */
        key->label = mutt_str_dup(p);
        break;
      case 4: /* issuer */
        key->issuer = mutt_str_dup(p);
        break;
      case 5: /* trust */
        key->trust = *p;
        break;
      case 6: /* purpose */
        while (*p)
        {
          switch (*p++)
          {
            case 'e':
              key->flags |= KEYFLAG_CANENCRYPT;
              break;

            case 's':
              key->flags |= KEYFLAG_CANSIGN;
              break;
          }
        }
        break;
    }
  }

  /* Old index files could be missing issuer, trust, and purpose,
   * but anything less than that is an error. */
  if (field < 3)
  {
    smime_key_free(&key);
    return NULL;
  }

  if (field < 4)
    key->issuer = mutt_str_dup("?");

  if (field < 5)
    key->trust = 't';

  if (field < 6)
    key->flags = (KEYFLAG_CANENCRYPT | KEYFLAG_CANSIGN);

  return key;
}

/**
 * smime_get_candidates - Find keys matching a string
 * @param search           String to match
 * @param only_public_key  If true, only get the public keys
 * @retval ptr Matching key
 */
static struct SmimeKey *smime_get_candidates(const char *search, bool only_public_key)
{
  char buf[1024] = { 0 };
  struct SmimeKey *key = NULL, *results = NULL;
  struct SmimeKey **results_end = &results;

  struct Buffer *index_file = buf_pool_get();
  const char *const c_smime_certificates = cs_subset_path(NeoMutt->sub, "smime_certificates");
  const char *const c_smime_keys = cs_subset_path(NeoMutt->sub, "smime_keys");
  buf_printf(index_file, "%s/.index",
             only_public_key ? NONULL(c_smime_certificates) : NONULL(c_smime_keys));

  FILE *fp = mutt_file_fopen(buf_string(index_file), "r");
  if (!fp)
  {
    mutt_perror("%s", buf_string(index_file));
    buf_pool_release(&index_file);
    return NULL;
  }
  buf_pool_release(&index_file);

  while (fgets(buf, sizeof(buf), fp))
  {
    if (((*search == '\0')) || mutt_istr_find(buf, search))
    {
      key = smime_parse_key(buf);
      if (key)
      {
        *results_end = key;
        results_end = &key->next;
      }
    }
  }

  mutt_file_fclose(&fp);

  return results;
}

/**
 * smime_get_key_by_hash - Find a key by its hash
 * @param hash             Hash to find
 * @param only_public_key  If true, only get the public keys
 * @retval ptr Matching key
 *
 * Returns the first matching key record, without prompting or checking of
 * abilities or trust.
 */
static struct SmimeKey *smime_get_key_by_hash(const char *hash, bool only_public_key)
{
  struct SmimeKey *match = NULL;
  struct SmimeKey *results = smime_get_candidates(hash, only_public_key);
  for (struct SmimeKey *result = results; result; result = result->next)
  {
    if (mutt_istr_equal(hash, result->hash))
    {
      match = smime_copy_key(result);
      break;
    }
  }

  smime_key_free(&results);

  return match;
}

/**
 * smime_get_key_by_addr - Find an SIME key by address
 * @param mailbox          Email address to match
 * @param abilities        Abilities to match, see #KeyFlags
 * @param only_public_key  If true, only get the public keys
 * @param oppenc_mode      If true, use opportunistic encryption
 * @retval ptr Matching key
 */
static struct SmimeKey *smime_get_key_by_addr(const char *mailbox, KeyFlags abilities,
                                              bool only_public_key, bool oppenc_mode)
{
  if (!mailbox)
    return NULL;

  struct SmimeKey *results = NULL, *result = NULL;
  struct SmimeKey *matches = NULL;
  struct SmimeKey **matches_end = &matches;
  struct SmimeKey *match = NULL;
  struct SmimeKey *trusted_match = NULL;
  struct SmimeKey *valid_match = NULL;
  struct SmimeKey *return_key = NULL;
  bool multi_trusted_matches = false;

  results = smime_get_candidates(mailbox, only_public_key);
  for (result = results; result; result = result->next)
  {
    if (abilities && !(result->flags & abilities))
    {
      continue;
    }

    if (mutt_istr_equal(mailbox, result->email))
    {
      match = smime_copy_key(result);
      *matches_end = match;
      matches_end = &match->next;

      if (match->trust == 't')
      {
        if (trusted_match && !mutt_istr_equal(match->hash, trusted_match->hash))
        {
          multi_trusted_matches = true;
        }
        trusted_match = match;
      }
      else if ((match->trust == 'u') || (match->trust == 'v'))
      {
        valid_match = match;
      }
    }
  }

  smime_key_free(&results);

  if (matches)
  {
    if (oppenc_mode || !isatty(STDIN_FILENO))
    {
      const bool c_crypt_opportunistic_encrypt_strong_keys =
          cs_subset_bool(NeoMutt->sub, "crypt_opportunistic_encrypt_strong_keys");
      if (trusted_match)
        return_key = smime_copy_key(trusted_match);
      else if (valid_match && !c_crypt_opportunistic_encrypt_strong_keys)
        return_key = smime_copy_key(valid_match);
      else
        return_key = NULL;
    }
    else if (trusted_match && !multi_trusted_matches)
    {
      return_key = smime_copy_key(trusted_match);
    }
    else
    {
      return_key = smime_copy_key(dlg_smime(matches, mailbox));
    }

    smime_key_free(&matches);
  }

  return return_key;
}

/**
 * smime_get_key_by_str - Find an SMIME key by string
 * @param str              String to match
 * @param abilities        Abilities to match, see #KeyFlags
 * @param only_public_key  If true, only get the public keys
 * @retval ptr Matching key
 */
static struct SmimeKey *smime_get_key_by_str(const char *str, KeyFlags abilities, bool only_public_key)
{
  if (!str)
    return NULL;

  struct SmimeKey *results = NULL, *result = NULL;
  struct SmimeKey *matches = NULL;
  struct SmimeKey **matches_end = &matches;
  struct SmimeKey *match = NULL;
  struct SmimeKey *return_key = NULL;

  results = smime_get_candidates(str, only_public_key);
  for (result = results; result; result = result->next)
  {
    if (abilities && !(result->flags & abilities))
    {
      continue;
    }

    if (mutt_istr_equal(str, result->hash) ||
        mutt_istr_find(result->email, str) || mutt_istr_find(result->label, str))
    {
      match = smime_copy_key(result);
      *matches_end = match;
      matches_end = &match->next;
    }
  }

  smime_key_free(&results);

  if (matches)
  {
    return_key = smime_copy_key(dlg_smime(matches, str));
    smime_key_free(&matches);
  }

  return return_key;
}

/**
 * smime_ask_for_key - Ask the user to select a key
 * @param prompt           Prompt to show the user
 * @param abilities        Abilities to match, see #KeyFlags
 * @param only_public_key  If true, only get the public keys
 * @retval ptr Selected SMIME key
 */
static struct SmimeKey *smime_ask_for_key(const char *prompt, KeyFlags abilities, bool only_public_key)
{
  if (!prompt)
    return NULL;

  struct SmimeKey *key = NULL;
  struct Buffer *resp = buf_pool_get();

  mutt_clear_error();

  while (true)
  {
    buf_reset(resp);
    if (mw_get_field(prompt, resp, MUTT_COMP_NO_FLAGS, HC_OTHER, NULL, NULL) != 0)
    {
      goto done;
    }

    key = smime_get_key_by_str(buf_string(resp), abilities, only_public_key);
    if (key)
      goto done;

    mutt_error(_("No matching keys found for \"%s\""), buf_string(resp));
  }

done:
  buf_pool_release(&resp);
  return key;
}

/**
 * getkeys - Get the keys for a mailbox
 * @param mailbox Email address
 *
 * This sets the '*ToUse' variables for an upcoming decryption, where the
 * required key is different from `$smime_default_key`.
 */
static void getkeys(const char *mailbox)
{
  const char *k = NULL;

  struct SmimeKey *key = smime_get_key_by_addr(mailbox, KEYFLAG_CANENCRYPT, false, false);

  if (!key)
  {
    struct Buffer *prompt = buf_pool_get();
    buf_printf(prompt, _("Enter keyID for %s: "), mailbox);
    key = smime_ask_for_key(buf_string(prompt), KEYFLAG_CANENCRYPT, false);
    buf_pool_release(&prompt);
  }

  const char *const c_smime_keys = cs_subset_path(NeoMutt->sub, "smime_keys");
  size_t smime_keys_len = mutt_str_len(c_smime_keys);

  const char *const c_smime_default_key = cs_subset_string(NeoMutt->sub, "smime_default_key");
  k = key ? key->hash : NONULL(c_smime_default_key);

  /* if the key is different from last time */
  if ((buf_len(&SmimeKeyToUse) <= smime_keys_len) ||
      !mutt_istr_equal(k, SmimeKeyToUse.data + smime_keys_len + 1))
  {
    smime_class_void_passphrase();
    buf_printf(&SmimeKeyToUse, "%s/%s", NONULL(c_smime_keys), k);
    const char *const c_smime_certificates = cs_subset_path(NeoMutt->sub, "smime_certificates");
    buf_printf(&SmimeCertToUse, "%s/%s", NONULL(c_smime_certificates), k);
  }

  smime_key_free(&key);
}

/**
 * smime_class_getkeys - Get the S/MIME keys required to encrypt this email - Implements CryptModuleSpecs::smime_getkeys() - @ingroup crypto_smime_getkeys
 */
void smime_class_getkeys(struct Envelope *env)
{
  const bool c_smime_decrypt_use_default_key = cs_subset_bool(NeoMutt->sub, "smime_decrypt_use_default_key");
  const char *const c_smime_default_key = cs_subset_string(NeoMutt->sub, "smime_default_key");
  if (c_smime_decrypt_use_default_key && c_smime_default_key)
  {
    const char *const c_smime_keys = cs_subset_path(NeoMutt->sub, "smime_keys");
    buf_printf(&SmimeKeyToUse, "%s/%s", NONULL(c_smime_keys), c_smime_default_key);
    const char *const c_smime_certificates = cs_subset_path(NeoMutt->sub, "smime_certificates");
    buf_printf(&SmimeCertToUse, "%s/%s", NONULL(c_smime_certificates), c_smime_default_key);
    return;
  }

  struct Address *a = NULL;
  TAILQ_FOREACH(a, &env->to, entries)
  {
    if (mutt_addr_is_user(a))
    {
      getkeys(buf_string(a->mailbox));
      return;
    }
  }

  TAILQ_FOREACH(a, &env->cc, entries)
  {
    if (mutt_addr_is_user(a))
    {
      getkeys(buf_string(a->mailbox));
      return;
    }
  }

  struct Address *f = mutt_default_from(NeoMutt->sub);
  getkeys(buf_string(f->mailbox));
  mutt_addr_free(&f);
}

/**
 * smime_class_find_keys - Find the keyids of the recipients of a message - Implements CryptModuleSpecs::find_keys() - @ingroup crypto_find_keys
 */
char *smime_class_find_keys(const struct AddressList *al, bool oppenc_mode)
{
  struct SmimeKey *key = NULL;
  char *keyid = NULL, *keylist = NULL;
  size_t keylist_size = 0;
  size_t keylist_used = 0;

  struct Address *a = NULL;
  TAILQ_FOREACH(a, al, entries)
  {
    key = smime_get_key_by_addr(buf_string(a->mailbox), KEYFLAG_CANENCRYPT, true, oppenc_mode);
    if (!key && !oppenc_mode && isatty(STDIN_FILENO))
    {
      struct Buffer *prompt = buf_pool_get();
      buf_printf(prompt, _("Enter keyID for %s: "), buf_string(a->mailbox));
      key = smime_ask_for_key(buf_string(prompt), KEYFLAG_CANENCRYPT, true);
      buf_pool_release(&prompt);
    }
    if (!key)
    {
      if (!oppenc_mode)
        mutt_message(_("No (valid) certificate found for %s"), buf_string(a->mailbox));
      FREE(&keylist);
      return NULL;
    }

    keyid = key->hash;
    keylist_size += mutt_str_len(keyid) + 2;
    MUTT_MEM_REALLOC(&keylist, keylist_size, char);
    sprintf(keylist + keylist_used, "%s%s", keylist_used ? " " : "", keyid);
    keylist_used = mutt_str_len(keylist);

    smime_key_free(&key);
  }
  return keylist;
}

/**
 * smime_handle_cert_email - Process an email containing certificates
 * @param[in]  certificate Email with certificates
 * @param[in]  mailbox     Email address
 * @param[in]  copy        If true, save the certificates to buffer
 * @param[out] buffer      Buffer allocated to hold certificates
 * @param[out] num         Number of certificates in buffer
 * @retval  0 Success
 * @retval -1 Error
 * @retval -2 Error
 */
static int smime_handle_cert_email(const char *certificate, const char *mailbox,
                                   bool copy, char ***buffer, int *num)
{
  char email[256] = { 0 };
  int rc = -1, count = 0;
  pid_t pid;

  FILE *fp_err = mutt_file_mkstemp();
  if (!fp_err)
  {
    mutt_perror(_("Can't create temporary file"));
    return 1;
  }

  FILE *fp_out = mutt_file_mkstemp();
  if (!fp_out)
  {
    mutt_file_fclose(&fp_err);
    mutt_perror(_("Can't create temporary file"));
    return 1;
  }

  const struct Expando *c_smime_get_cert_email_command =
      cs_subset_expando(NeoMutt->sub, "smime_get_cert_email_command");
  pid = smime_invoke(NULL, NULL, NULL, -1, fileno(fp_out), fileno(fp_err), certificate,
                     NULL, NULL, NULL, NULL, NULL, NULL, c_smime_get_cert_email_command);
  if (pid == -1)
  {
    mutt_message(_("Error: unable to create OpenSSL subprocess"));
    mutt_file_fclose(&fp_err);
    mutt_file_fclose(&fp_out);
    return 1;
  }

  filter_wait(pid);

  fflush(fp_out);
  rewind(fp_out);
  fflush(fp_err);
  rewind(fp_err);

  while ((fgets(email, sizeof(email), fp_out)))
  {
    size_t len = mutt_str_len(email);
    if (len && (email[len - 1] == '\n'))
      email[len - 1] = '\0';
    if (mutt_istr_startswith(email, mailbox))
      rc = 1;

    rc = (rc < 0) ? 0 : rc;
    count++;
  }

  if (rc == -1)
  {
    mutt_endwin();
    mutt_file_copy_stream(fp_err, stdout);
    mutt_any_key_to_continue(_("Error: unable to create OpenSSL subprocess"));
    rc = 1;
  }
  else if (rc == 0)
  {
    rc = 1;
  }
  else
  {
    rc = 0;
  }

  if (copy && buffer && num)
  {
    (*num) = count;
    *buffer = MUTT_MEM_CALLOC(count, char *);
    count = 0;

    rewind(fp_out);
    while ((fgets(email, sizeof(email), fp_out)))
    {
      size_t len = mutt_str_len(email);
      if (len && (email[len - 1] == '\n'))
        email[len - 1] = '\0';
      (*buffer)[count] = MUTT_MEM_CALLOC(mutt_str_len(email) + 1, char);
      strncpy((*buffer)[count], email, mutt_str_len(email));
      count++;
    }
  }
  else if (copy)
  {
    rc = 2;
  }

  mutt_file_fclose(&fp_out);
  mutt_file_fclose(&fp_err);

  return rc;
}

/**
 * smime_extract_certificate - Extract an SMIME certificate from a file
 * @param infile File to read
 * @retval ptr Filename of temporary file containing certificate
 */
static char *smime_extract_certificate(const char *infile)
{
  FILE *fp_err = NULL;
  FILE *fp_out = NULL;
  FILE *fp_cert = NULL;
  char *rc = NULL;
  pid_t pid;
  int empty;

  struct Buffer *pk7out = buf_pool_get();
  struct Buffer *certfile = buf_pool_get();

  fp_err = mutt_file_mkstemp();
  if (!fp_err)
  {
    mutt_perror(_("Can't create temporary file"));
    goto cleanup;
  }

  buf_mktemp(pk7out);
  fp_out = mutt_file_fopen(buf_string(pk7out), "w+");
  if (!fp_out)
  {
    mutt_perror("%s", buf_string(pk7out));
    goto cleanup;
  }

  /* Step 1: Convert the signature to a PKCS#7 structure, as we can't
   * extract the full set of certificates directly. */
  const struct Expando *c_smime_pk7out_command = cs_subset_expando(NeoMutt->sub, "smime_pk7out_command");
  pid = smime_invoke(NULL, NULL, NULL, -1, fileno(fp_out), fileno(fp_err), infile,
                     NULL, NULL, NULL, NULL, NULL, NULL, c_smime_pk7out_command);
  if (pid == -1)
  {
    mutt_any_key_to_continue(_("Error: unable to create OpenSSL subprocess"));
    goto cleanup;
  }

  filter_wait(pid);

  fflush(fp_out);
  rewind(fp_out);
  fflush(fp_err);
  rewind(fp_err);
  empty = (fgetc(fp_out) == EOF);
  if (empty)
  {
    mutt_perror("%s", buf_string(pk7out));
    mutt_file_copy_stream(fp_err, stdout);
    goto cleanup;
  }
  mutt_file_fclose(&fp_out);

  buf_mktemp(certfile);
  fp_cert = mutt_file_fopen(buf_string(certfile), "w+");
  if (!fp_cert)
  {
    mutt_perror("%s", buf_string(certfile));
    mutt_file_unlink(buf_string(pk7out));
    goto cleanup;
  }

  // Step 2: Extract the certificates from a PKCS#7 structure.
  const struct Expando *c_smime_get_cert_command = cs_subset_expando(NeoMutt->sub, "smime_get_cert_command");
  pid = smime_invoke(NULL, NULL, NULL, -1, fileno(fp_cert), fileno(fp_err),
                     buf_string(pk7out), NULL, NULL, NULL, NULL, NULL, NULL,
                     c_smime_get_cert_command);
  if (pid == -1)
  {
    mutt_any_key_to_continue(_("Error: unable to create OpenSSL subprocess"));
    mutt_file_unlink(buf_string(pk7out));
    goto cleanup;
  }

  filter_wait(pid);

  mutt_file_unlink(buf_string(pk7out));

  fflush(fp_cert);
  rewind(fp_cert);
  fflush(fp_err);
  rewind(fp_err);
  empty = (fgetc(fp_cert) == EOF);
  if (empty)
  {
    mutt_file_copy_stream(fp_err, stdout);
    goto cleanup;
  }

  mutt_file_fclose(&fp_cert);

  rc = buf_strdup(certfile);

cleanup:
  mutt_file_fclose(&fp_err);
  if (fp_out)
  {
    mutt_file_fclose(&fp_out);
    mutt_file_unlink(buf_string(pk7out));
  }
  if (fp_cert)
  {
    mutt_file_fclose(&fp_cert);
    mutt_file_unlink(buf_string(certfile));
  }
  buf_pool_release(&pk7out);
  buf_pool_release(&certfile);
  return rc;
}

/**
 * smime_extract_signer_certificate - Extract the signer's certificate
 * @param infile File to read
 * @retval ptr Name of temporary file containing certificate
 */
static char *smime_extract_signer_certificate(const char *infile)
{
  char *cert = NULL;
  struct Buffer *certfile = NULL;
  pid_t pid;
  int empty;

  FILE *fp_err = mutt_file_mkstemp();
  if (!fp_err)
  {
    mutt_perror(_("Can't create temporary file"));
    return NULL;
  }

  certfile = buf_pool_get();
  buf_mktemp(certfile);
  FILE *fp_out = mutt_file_fopen(buf_string(certfile), "w+");
  if (!fp_out)
  {
    mutt_file_fclose(&fp_err);
    mutt_perror("%s", buf_string(certfile));
    goto cleanup;
  }

  /* Extract signer's certificate
   */
  const struct Expando *c_smime_get_signer_cert_command =
      cs_subset_expando(NeoMutt->sub, "smime_get_signer_cert_command");
  pid = smime_invoke(NULL, NULL, NULL, -1, -1, fileno(fp_err), infile, NULL, NULL, NULL,
                     NULL, buf_string(certfile), NULL, c_smime_get_signer_cert_command);
  if (pid == -1)
  {
    mutt_any_key_to_continue(_("Error: unable to create OpenSSL subprocess"));
    goto cleanup;
  }

  filter_wait(pid);

  fflush(fp_out);
  rewind(fp_out);
  fflush(fp_err);
  rewind(fp_err);
  empty = (fgetc(fp_out) == EOF);
  if (empty)
  {
    mutt_endwin();
    mutt_file_copy_stream(fp_err, stdout);
    mutt_any_key_to_continue(NULL);
    goto cleanup;
  }

  mutt_file_fclose(&fp_out);
  cert = buf_strdup(certfile);

cleanup:
  mutt_file_fclose(&fp_err);
  if (fp_out)
  {
    mutt_file_fclose(&fp_out);
    mutt_file_unlink(buf_string(certfile));
  }
  buf_pool_release(&certfile);
  return cert;
}

/**
 * smime_class_invoke_import - Add a certificate and update index file (externally) - Implements CryptModuleSpecs::smime_invoke_import() - @ingroup crypto_smime_invoke_import
 */
void smime_class_invoke_import(const char *infile, const char *mailbox)
{
  char *certfile = NULL;
  struct Buffer *buf = NULL;

  FILE *fp_out = NULL;
  FILE *fp_err = mutt_file_mkstemp();
  if (!fp_err)
  {
    mutt_perror(_("Can't create temporary file"));
    goto done;
  }

  fp_out = mutt_file_mkstemp();
  if (!fp_out)
  {
    mutt_perror(_("Can't create temporary file"));
    goto done;
  }

  buf = buf_pool_get();
  const bool c_smime_ask_cert_label = cs_subset_bool(NeoMutt->sub, "smime_ask_cert_label");
  if (c_smime_ask_cert_label)
  {
    if ((mw_get_field(_("Label for certificate: "), buf, MUTT_COMP_NO_FLAGS,
                      HC_OTHER, NULL, NULL) != 0) ||
        buf_is_empty(buf))
    {
      goto done;
    }
  }

  mutt_endwin();
  certfile = smime_extract_certificate(infile);
  if (certfile)
  {
    mutt_endwin();

    const struct Expando *c_smime_import_cert_command =
        cs_subset_expando(NeoMutt->sub, "smime_import_cert_command");
    FILE *fp_smime_in = NULL;
    pid_t pid = smime_invoke(&fp_smime_in, NULL, NULL, -1, fileno(fp_out),
                             fileno(fp_err), certfile, NULL, NULL, NULL, NULL,
                             NULL, NULL, c_smime_import_cert_command);
    if (pid == -1)
    {
      mutt_message(_("Error: unable to create OpenSSL subprocess"));
      goto done;
    }
    fputs(buf_string(buf), fp_smime_in);
    fputc('\n', fp_smime_in);
    mutt_file_fclose(&fp_smime_in);

    filter_wait(pid);

    mutt_file_unlink(certfile);
    FREE(&certfile);
  }

  fflush(fp_out);
  rewind(fp_out);
  fflush(fp_err);
  rewind(fp_err);

  mutt_file_copy_stream(fp_out, stdout);
  mutt_file_copy_stream(fp_err, stdout);

done:
  mutt_file_fclose(&fp_out);
  mutt_file_fclose(&fp_err);
  buf_pool_release(&buf);
}

/**
 * smime_class_verify_sender - Does the sender match the certificate? - Implements CryptModuleSpecs::smime_verify_sender() - @ingroup crypto_smime_verify_sender
 */
int smime_class_verify_sender(struct Email *e, struct Message *msg)
{
  const char *mbox = NULL, *certfile = NULL;
  int rc = 1;

  struct Buffer *tempfname = buf_pool_get();
  buf_mktemp(tempfname);
  FILE *fp_out = mutt_file_fopen(buf_string(tempfname), "w");
  if (!fp_out)
  {
    mutt_perror("%s", buf_string(tempfname));
    goto cleanup;
  }

  const bool encrypt = e->security & SEC_ENCRYPT;
  mutt_copy_message(fp_out, e, msg,
                    encrypt ? (MUTT_CM_DECODE_CRYPT & MUTT_CM_DECODE_SMIME) : MUTT_CM_NO_FLAGS,
                    encrypt ? (CH_MIME | CH_WEED | CH_NONEWLINE) : CH_NO_FLAGS, 0);

  fflush(fp_out);
  mutt_file_fclose(&fp_out);

  if (!TAILQ_EMPTY(&e->env->from))
  {
    mutt_expand_aliases(&e->env->from);
    mbox = buf_string(TAILQ_FIRST(&e->env->from)->mailbox);
  }
  else if (!TAILQ_EMPTY(&e->env->sender))
  {
    mutt_expand_aliases(&e->env->sender);
    mbox = buf_string(TAILQ_FIRST(&e->env->sender)->mailbox);
  }

  if (mbox)
  {
    certfile = smime_extract_signer_certificate(buf_string(tempfname));
    if (certfile)
    {
      mutt_file_unlink(buf_string(tempfname));
      if (smime_handle_cert_email(certfile, mbox, false, NULL, NULL))
      {
        if (isendwin())
          mutt_any_key_to_continue(NULL);
      }
      else
      {
        rc = 0;
      }
      mutt_file_unlink(certfile);
      FREE(&certfile);
    }
    else
    {
      mutt_any_key_to_continue(_("no certfile"));
    }
  }
  else
  {
    mutt_any_key_to_continue(_("no mbox"));
  }

  mutt_file_unlink(buf_string(tempfname));

cleanup:
  buf_pool_release(&tempfname);
  return rc;
}

/**
 * smime_invoke_encrypt - Use SMIME to encrypt a file
 * @param[out] fp_smime_in    stdin  for the command, or NULL (OPTIONAL)
 * @param[out] fp_smime_out   stdout for the command, or NULL (OPTIONAL)
 * @param[out] fp_smime_err   stderr for the command, or NULL (OPTIONAL)
 * @param[in]  fp_smime_infd  stdin  for the command, or -1 (OPTIONAL)
 * @param[in]  fp_smime_outfd stdout for the command, or -1 (OPTIONAL)
 * @param[in]  fp_smime_errfd stderr for the command, or -1 (OPTIONAL)
 * @param[in]  fname      Filename to pass to the command
 * @param[in]  uids       List of IDs/fingerprints, space separated
 * @retval num PID of the created process
 * @retval -1  Error creating pipes or forking
 *
 * @note `fp_smime_in` has priority over `fp_smime_infd`.
 *       Likewise `fp_smime_out` and `fp_smime_err`.
 */
static pid_t smime_invoke_encrypt(FILE **fp_smime_in, FILE **fp_smime_out,
                                  FILE **fp_smime_err, int fp_smime_infd,
                                  int fp_smime_outfd, int fp_smime_errfd,
                                  const char *fname, const char *uids)
{
  const char *const c_smime_encrypt_with = cs_subset_string(NeoMutt->sub, "smime_encrypt_with");
  const struct Expando *c_smime_encrypt_command = cs_subset_expando(NeoMutt->sub, "smime_encrypt_command");
  return smime_invoke(fp_smime_in, fp_smime_out, fp_smime_err, fp_smime_infd,
                      fp_smime_outfd, fp_smime_errfd, fname, NULL, c_smime_encrypt_with,
                      NULL, NULL, uids, NULL, c_smime_encrypt_command);
}

/**
 * smime_invoke_sign - Use SMIME to sign a file
 * @param[out] fp_smime_in    stdin  for the command, or NULL (OPTIONAL)
 * @param[out] fp_smime_out   stdout for the command, or NULL (OPTIONAL)
 * @param[out] fp_smime_err   stderr for the command, or NULL (OPTIONAL)
 * @param[in]  fp_smime_infd  stdin  for the command, or -1 (OPTIONAL)
 * @param[in]  fp_smime_outfd stdout for the command, or -1 (OPTIONAL)
 * @param[in]  fp_smime_errfd stderr for the command, or -1 (OPTIONAL)
 * @param[in]  fname      Filename to pass to the command
 * @retval num PID of the created process
 * @retval -1  Error creating pipes or forking
 *
 * @note `fp_smime_in` has priority over `fp_smime_infd`.
 *       Likewise `fp_smime_out` and `fp_smime_err`.
 */
static pid_t smime_invoke_sign(FILE **fp_smime_in, FILE **fp_smime_out,
                               FILE **fp_smime_err, int fp_smime_infd, int fp_smime_outfd,
                               int fp_smime_errfd, const char *fname)
{
  const char *const c_smime_sign_digest_alg = cs_subset_string(NeoMutt->sub, "smime_sign_digest_alg");
  const struct Expando *c_smime_sign_command = cs_subset_expando(NeoMutt->sub, "smime_sign_command");
  return smime_invoke(fp_smime_in, fp_smime_out, fp_smime_err, fp_smime_infd, fp_smime_outfd,
                      fp_smime_errfd, fname, NULL, NULL, c_smime_sign_digest_alg,
                      buf_string(&SmimeKeyToUse), buf_string(&SmimeCertToUse),
                      buf_string(&SmimeIntermediateToUse), c_smime_sign_command);
}

/**
 * smime_class_build_smime_entity - Encrypt the email body to all recipients - Implements CryptModuleSpecs::smime_build_smime_entity() - @ingroup crypto_smime_build_smime_entity
 */
struct Body *smime_class_build_smime_entity(struct Body *b, char *certlist)
{
  char buf[1024] = { 0 };
  char certfile[PATH_MAX] = { 0 };
  char *cert_end = NULL;
  FILE *fp_smime_in = NULL, *fp_smime_err = NULL, *fp_out = NULL, *fp_tmp = NULL;
  struct Body *b_enc = NULL;
  bool err = false;
  int empty, off;
  pid_t pid;

  struct Buffer *tempfile = buf_pool_get();
  struct Buffer *smime_infile = buf_pool_get();

  buf_mktemp(tempfile);
  fp_out = mutt_file_fopen(buf_string(tempfile), "w+");
  if (!fp_out)
  {
    mutt_perror("%s", buf_string(tempfile));
    goto cleanup;
  }

  fp_smime_err = mutt_file_mkstemp();
  if (!fp_smime_err)
  {
    mutt_perror(_("Can't create temporary file"));
    goto cleanup;
  }

  buf_mktemp(smime_infile);
  fp_tmp = mutt_file_fopen(buf_string(smime_infile), "w+");
  if (!fp_tmp)
  {
    mutt_perror("%s", buf_string(smime_infile));
    goto cleanup;
  }

  *certfile = '\0';
  for (char *cert_start = certlist; cert_start; cert_start = cert_end)
  {
    cert_end = strchr(cert_start, ' ');
    if (cert_end)
      *cert_end = '\0';
    if (*cert_start)
    {
      off = mutt_str_len(certfile);
      const char *const c_smime_certificates = cs_subset_path(NeoMutt->sub, "smime_certificates");
      snprintf(certfile + off, sizeof(certfile) - off, "%s%s/%s",
               (off != 0) ? " " : "", NONULL(c_smime_certificates), cert_start);
    }
    if (cert_end)
      *cert_end++ = ' ';
  }

  /* write a MIME entity */
  mutt_write_mime_header(b, fp_tmp, NeoMutt->sub);
  fputc('\n', fp_tmp);
  mutt_write_mime_body(b, fp_tmp, NeoMutt->sub);
  mutt_file_fclose(&fp_tmp);

  pid = smime_invoke_encrypt(&fp_smime_in, NULL, NULL, -1, fileno(fp_out),
                             fileno(fp_smime_err), buf_string(smime_infile), certfile);
  if (pid == -1)
  {
    mutt_file_unlink(buf_string(smime_infile));
    goto cleanup;
  }

  mutt_file_fclose(&fp_smime_in);

  filter_wait(pid);
  mutt_file_unlink(buf_string(smime_infile));

  fflush(fp_out);
  rewind(fp_out);
  empty = (fgetc(fp_out) == EOF);
  mutt_file_fclose(&fp_out);

  fflush(fp_smime_err);
  rewind(fp_smime_err);
  while (fgets(buf, sizeof(buf) - 1, fp_smime_err))
  {
    err = true;
    fputs(buf, stdout);
  }
  mutt_file_fclose(&fp_smime_err);

  /* pause if there is any error output from SMIME */
  if (err)
    mutt_any_key_to_continue(NULL);

  if (empty)
  {
    /* fatal error while trying to encrypt message */
    if (!err)
      mutt_any_key_to_continue(_("No output from OpenSSL..."));
    mutt_file_unlink(buf_string(tempfile));
    goto cleanup;
  }

  b_enc = mutt_body_new();
  b_enc->type = TYPE_APPLICATION;
  b_enc->subtype = mutt_str_dup("pkcs7-mime");
  mutt_param_set(&b_enc->parameter, "name", "smime.p7m");
  mutt_param_set(&b_enc->parameter, "smime-type", "enveloped-data");
  b_enc->encoding = ENC_BASE64; /* The output of OpenSSL SHOULD be binary */
  b_enc->use_disp = true;
  b_enc->disposition = DISP_ATTACH;
  b_enc->d_filename = mutt_str_dup("smime.p7m");
  b_enc->filename = buf_strdup(tempfile);
  b_enc->unlink = true; /* delete after sending the message */
  b_enc->parts = NULL;
  b_enc->next = NULL;

cleanup:
  if (fp_out)
  {
    mutt_file_fclose(&fp_out);
    mutt_file_unlink(buf_string(tempfile));
  }
  mutt_file_fclose(&fp_smime_err);
  if (fp_tmp)
  {
    mutt_file_fclose(&fp_tmp);
    mutt_file_unlink(buf_string(smime_infile));
  }
  buf_pool_release(&tempfile);
  buf_pool_release(&smime_infile);

  return b_enc;
}

/**
 * openssl_md_to_smime_micalg - Change the algorithm names
 * @param md OpenSSL message digest name
 * @retval ptr SMIME Message Integrity Check algorithm
 *
 * The openssl -md doesn't want hyphens:
 *   md5, sha1,  sha224,  sha256,  sha384,  sha512
 * However, the micalg does:
 *   md5, sha-1, sha-224, sha-256, sha-384, sha-512
 *
 * @note The caller should free the returned string
 */
static char *openssl_md_to_smime_micalg(const char *md)
{
  if (!md)
    return NULL;

  char *micalg = NULL;
  if (mutt_istr_startswith(md, "sha"))
  {
    mutt_str_asprintf(&micalg, "sha-%s", md + 3);
  }
  else
  {
    micalg = mutt_str_dup(md);
  }

  return micalg;
}

/**
 * smime_class_sign_message - Cryptographically sign the Body of a message - Implements CryptModuleSpecs::sign_message() - @ingroup crypto_sign_message
 */
struct Body *smime_class_sign_message(struct Body *b, const struct AddressList *from)
{
  struct Body *b_sign = NULL;
  struct Body *rc = NULL;
  char buf[1024] = { 0 };
  struct Buffer *filetosign = NULL, *signedfile = NULL;
  FILE *fp_smime_in = NULL, *fp_smime_out = NULL, *fp_smime_err = NULL, *fp_sign = NULL;
  bool err = false;
  int empty = 0;
  pid_t pid;
  const char *intermediates = NULL;

  const char *const c_smime_sign_as = cs_subset_string(NeoMutt->sub, "smime_sign_as");
  const char *const c_smime_default_key = cs_subset_string(NeoMutt->sub, "smime_default_key");
  const char *signas = c_smime_sign_as ? c_smime_sign_as : c_smime_default_key;
  if (!signas || (*signas == '\0'))
  {
    mutt_error(_("Can't sign: No key specified. Use Sign As."));
    return NULL;
  }

  crypt_convert_to_7bit(b); /* Signed data _must_ be in 7-bit format. */

  filetosign = buf_pool_get();
  signedfile = buf_pool_get();

  buf_mktemp(filetosign);
  fp_sign = mutt_file_fopen(buf_string(filetosign), "w+");
  if (!fp_sign)
  {
    mutt_perror("%s", buf_string(filetosign));
    goto cleanup;
  }

  buf_mktemp(signedfile);
  fp_smime_out = mutt_file_fopen(buf_string(signedfile), "w+");
  if (!fp_smime_out)
  {
    mutt_perror("%s", buf_string(signedfile));
    goto cleanup;
  }

  mutt_write_mime_header(b, fp_sign, NeoMutt->sub);
  fputc('\n', fp_sign);
  mutt_write_mime_body(b, fp_sign, NeoMutt->sub);
  mutt_file_fclose(&fp_sign);

  const char *const c_smime_keys = cs_subset_path(NeoMutt->sub, "smime_keys");
  const char *const c_smime_certificates = cs_subset_path(NeoMutt->sub, "smime_certificates");
  buf_printf(&SmimeKeyToUse, "%s/%s", NONULL(c_smime_keys), signas);
  buf_printf(&SmimeCertToUse, "%s/%s", NONULL(c_smime_certificates), signas);

  struct SmimeKey *signas_key = smime_get_key_by_hash(signas, 1);
  if (!signas_key || mutt_str_equal("?", signas_key->issuer))
    intermediates = signas; /* so openssl won't complain in any case */
  else
    intermediates = signas_key->issuer;

  buf_printf(&SmimeIntermediateToUse, "%s/%s", NONULL(c_smime_certificates), intermediates);

  smime_key_free(&signas_key);

  pid = smime_invoke_sign(&fp_smime_in, NULL, &fp_smime_err, -1,
                          fileno(fp_smime_out), -1, buf_string(filetosign));
  if (pid == -1)
  {
    mutt_perror(_("Can't open OpenSSL subprocess"));
    mutt_file_unlink(buf_string(filetosign));
    goto cleanup;
  }
  fputs(SmimePass, fp_smime_in);
  fputc('\n', fp_smime_in);
  mutt_file_fclose(&fp_smime_in);

  filter_wait(pid);

  /* check for errors from OpenSSL */
  err = false;
  fflush(fp_smime_err);
  rewind(fp_smime_err);
  while (fgets(buf, sizeof(buf) - 1, fp_smime_err))
  {
    err = true;
    fputs(buf, stdout);
  }
  mutt_file_fclose(&fp_smime_err);

  fflush(fp_smime_out);
  rewind(fp_smime_out);
  empty = (fgetc(fp_smime_out) == EOF);
  mutt_file_fclose(&fp_smime_out);

  mutt_file_unlink(buf_string(filetosign));

  if (err)
    mutt_any_key_to_continue(NULL);

  if (empty)
  {
    mutt_any_key_to_continue(_("No output from OpenSSL..."));
    mutt_file_unlink(buf_string(signedfile));
    goto cleanup; /* fatal error while signing */
  }

  b_sign = mutt_body_new();
  b_sign->type = TYPE_MULTIPART;
  b_sign->subtype = mutt_str_dup("signed");
  b_sign->encoding = ENC_7BIT;
  b_sign->use_disp = false;
  b_sign->disposition = DISP_INLINE;

  mutt_generate_boundary(&b_sign->parameter);

  const char *const c_smime_sign_digest_alg = cs_subset_string(NeoMutt->sub, "smime_sign_digest_alg");
  char *micalg = openssl_md_to_smime_micalg(c_smime_sign_digest_alg);
  mutt_param_set(&b_sign->parameter, "micalg", micalg);
  FREE(&micalg);

  mutt_param_set(&b_sign->parameter, "protocol", "application/pkcs7-signature");

  b_sign->parts = b;
  rc = b_sign;

  b_sign->parts->next = mutt_body_new();
  b_sign = b_sign->parts->next;
  b_sign->type = TYPE_APPLICATION;
  b_sign->subtype = mutt_str_dup("pkcs7-signature");
  b_sign->filename = buf_strdup(signedfile);
  b_sign->d_filename = mutt_str_dup("smime.p7s");
  b_sign->use_disp = true;
  b_sign->disposition = DISP_ATTACH;
  b_sign->encoding = ENC_BASE64;
  b_sign->unlink = true; /* ok to remove this file after sending. */

cleanup:
  if (fp_sign)
  {
    mutt_file_fclose(&fp_sign);
    mutt_file_unlink(buf_string(filetosign));
  }
  if (fp_smime_out)
  {
    mutt_file_fclose(&fp_smime_out);
    mutt_file_unlink(buf_string(signedfile));
  }
  buf_pool_release(&filetosign);
  buf_pool_release(&signedfile);
  return rc;
}

/**
 * smime_invoke_verify - Use SMIME to verify a file
 * @param[out] fp_smime_in    stdin  for the command, or NULL (OPTIONAL)
 * @param[out] fp_smime_out   stdout for the command, or NULL (OPTIONAL)
 * @param[out] fp_smime_err   stderr for the command, or NULL (OPTIONAL)
 * @param[in]  fp_smime_infd  stdin  for the command, or -1 (OPTIONAL)
 * @param[in]  fp_smime_outfd stdout for the command, or -1 (OPTIONAL)
 * @param[in]  fp_smime_errfd stderr for the command, or -1 (OPTIONAL)
 * @param[in]  fname      Filename to pass to the command
 * @param[in]  sig_fname  Signature filename to pass to the command
 * @param[in]  opaque     If true, use `$smime_verify_opaque_command` else `$smime_verify_command`
 * @retval num PID of the created process
 * @retval -1  Error creating pipes or forking
 *
 * @note `fp_smime_in` has priority over `fp_smime_infd`.
 *       Likewise `fp_smime_out` and `fp_smime_err`.
 */
static pid_t smime_invoke_verify(FILE **fp_smime_in, FILE **fp_smime_out,
                                 FILE **fp_smime_err, int fp_smime_infd,
                                 int fp_smime_outfd, int fp_smime_errfd,
                                 const char *fname, const char *sig_fname, int opaque)
{
  const struct Expando *c_smime_verify_opaque_command =
      cs_subset_expando(NeoMutt->sub, "smime_verify_opaque_command");
  const struct Expando *c_smime_verify_command = cs_subset_expando(NeoMutt->sub, "smime_verify_command");
  return smime_invoke(fp_smime_in, fp_smime_out, fp_smime_err, fp_smime_infd, fp_smime_outfd,
                      fp_smime_errfd, fname, sig_fname, NULL, NULL, NULL, NULL, NULL,
                      (opaque ? c_smime_verify_opaque_command : c_smime_verify_command));
}

/**
 * smime_invoke_decrypt - Use SMIME to decrypt a file
 * @param[out] fp_smime_in    stdin  for the command, or NULL (OPTIONAL)
 * @param[out] fp_smime_out   stdout for the command, or NULL (OPTIONAL)
 * @param[out] fp_smime_err   stderr for the command, or NULL (OPTIONAL)
 * @param[in]  fp_smime_infd  stdin  for the command, or -1 (OPTIONAL)
 * @param[in]  fp_smime_outfd stdout for the command, or -1 (OPTIONAL)
 * @param[in]  fp_smime_errfd stderr for the command, or -1 (OPTIONAL)
 * @param[in]  fname      Filename to pass to the command
 * @retval num PID of the created process
 * @retval -1  Error creating pipes or forking
 *
 * @note `fp_smime_in` has priority over `fp_smime_infd`.
 *       Likewise `fp_smime_out` and `fp_smime_err`.
 */
static pid_t smime_invoke_decrypt(FILE **fp_smime_in, FILE **fp_smime_out,
                                  FILE **fp_smime_err, int fp_smime_infd, int fp_smime_outfd,
                                  int fp_smime_errfd, const char *fname)
{
  const struct Expando *c_smime_decrypt_command = cs_subset_expando(NeoMutt->sub, "smime_decrypt_command");
  return smime_invoke(fp_smime_in, fp_smime_out, fp_smime_err, fp_smime_infd,
                      fp_smime_outfd, fp_smime_errfd, fname, NULL, NULL, NULL,
                      buf_string(&SmimeKeyToUse), buf_string(&SmimeCertToUse),
                      NULL, c_smime_decrypt_command);
}

/**
 * smime_class_verify_one - Check a signed MIME part against a signature - Implements CryptModuleSpecs::verify_one() - @ingroup crypto_verify_one
 */
int smime_class_verify_one(struct Body *b, struct State *state, const char *tempfile)
{
  FILE *fp = NULL, *fp_smime_out = NULL, *fp_smime_err = NULL;
  pid_t pid;
  int badsig = -1;

  LOFF_T tmpoffset = 0;
  size_t tmplength = 0;
  int orig_type = b->type;

  struct Buffer *signedfile = buf_pool_get();

  buf_printf(signedfile, "%s.sig", tempfile);

  /* decode to a tempfile, saving the original destination */
  fp = state->fp_out;
  state->fp_out = mutt_file_fopen(buf_string(signedfile), "w");
  if (!state->fp_out)
  {
    mutt_perror("%s", buf_string(signedfile));
    goto cleanup;
  }
  /* decoding the attachment changes the size and offset, so save a copy
   * of the "real" values now, and restore them after processing */
  tmplength = b->length;
  tmpoffset = b->offset;

  /* if we are decoding binary bodies, we don't want to prefix each
   * line with the prefix or else the data will get corrupted.  */
  const char *save_prefix = state->prefix;
  state->prefix = NULL;

  mutt_decode_attachment(b, state);

  b->length = ftello(state->fp_out);
  b->offset = 0;
  mutt_file_fclose(&state->fp_out);

  /* restore final destination and substitute the tempfile for input */
  state->fp_out = fp;
  fp = state->fp_in;
  state->fp_in = mutt_file_fopen(buf_string(signedfile), "r");

  /* restore the prefix */
  state->prefix = save_prefix;

  b->type = orig_type;

  fp_smime_err = mutt_file_mkstemp();
  if (!fp_smime_err)
  {
    mutt_perror(_("Can't create temporary file"));
    goto cleanup;
  }

  crypt_current_time(state, "OpenSSL");

  pid = smime_invoke_verify(NULL, &fp_smime_out, NULL, -1, -1, fileno(fp_smime_err),
                            tempfile, buf_string(signedfile), 0);
  if (pid != -1)
  {
    fflush(fp_smime_out);
    mutt_file_fclose(&fp_smime_out);

    if (filter_wait(pid))
    {
      badsig = -1;
    }
    else
    {
      char *line = NULL;
      size_t linelen;

      fflush(fp_smime_err);
      rewind(fp_smime_err);

      line = mutt_file_read_line(line, &linelen, fp_smime_err, NULL, MUTT_RL_NO_FLAGS);
      if (linelen && mutt_istr_equal(line, "verification successful"))
        badsig = 0;

      FREE(&line);
    }
  }

  fflush(fp_smime_err);
  rewind(fp_smime_err);
  mutt_file_copy_stream(fp_smime_err, state->fp_out);
  mutt_file_fclose(&fp_smime_err);

  state_attach_puts(state, _("[-- End of OpenSSL output --]\n\n"));

  mutt_file_unlink(buf_string(signedfile));

  b->length = tmplength;
  b->offset = tmpoffset;

  /* restore the original source stream */
  mutt_file_fclose(&state->fp_in);
  state->fp_in = fp;

cleanup:
  buf_pool_release(&signedfile);
  return badsig;
}

/**
 * smime_handle_entity - Handle type application/pkcs7-mime
 * @param b           Body to handle
 * @param state       State to use
 * @param fp_out_file File for the result
 * @retval ptr Body for parsed MIME part
 *
 * This can either be a signed or an encrypted message.
 */
static struct Body *smime_handle_entity(struct Body *b, struct State *state, FILE *fp_out_file)
{
  struct Buffer *tmpfname = buf_pool_get();
  FILE *fp_smime_out = NULL, *fp_smime_in = NULL, *fp_smime_err = NULL;
  FILE *fp_tmp = NULL, *fp_out = NULL;
  struct Body *p = NULL;
  pid_t pid = -1;
  SecurityFlags type = mutt_is_application_smime(b);

  if (!(type & APPLICATION_SMIME))
    return NULL;

  /* Because of the mutt_body_handler() we avoid the buffer pool. */
  fp_smime_out = mutt_file_mkstemp();
  if (!fp_smime_out)
  {
    mutt_perror(_("Can't create temporary file"));
    goto cleanup;
  }

  fp_smime_err = mutt_file_mkstemp();
  if (!fp_smime_err)
  {
    mutt_perror(_("Can't create temporary file"));
    goto cleanup;
  }

  buf_mktemp(tmpfname);
  fp_tmp = mutt_file_fopen(buf_string(tmpfname), "w+");
  if (!fp_tmp)
  {
    mutt_perror("%s", buf_string(tmpfname));
    goto cleanup;
  }

  if (!mutt_file_seek(state->fp_in, b->offset, SEEK_SET))
  {
    goto cleanup;
  }

  mutt_file_copy_bytes(state->fp_in, fp_tmp, b->length);

  fflush(fp_tmp);
  mutt_file_fclose(&fp_tmp);

  if ((type & SEC_ENCRYPT) &&
      ((pid = smime_invoke_decrypt(&fp_smime_in, NULL, NULL, -1, fileno(fp_smime_out),
                                   fileno(fp_smime_err), buf_string(tmpfname))) == -1))
  {
    mutt_file_unlink(buf_string(tmpfname));
    if (state->flags & STATE_DISPLAY)
    {
      state_attach_puts(state, _("[-- Error: unable to create OpenSSL subprocess --]\n"));
    }
    goto cleanup;
  }
  else if ((type & SEC_SIGNOPAQUE) &&
           ((pid = smime_invoke_verify(&fp_smime_in, NULL, NULL, -1,
                                       fileno(fp_smime_out), fileno(fp_smime_err), NULL,
                                       buf_string(tmpfname), SEC_SIGNOPAQUE)) == -1))
  {
    mutt_file_unlink(buf_string(tmpfname));
    if (state->flags & STATE_DISPLAY)
    {
      state_attach_puts(state, _("[-- Error: unable to create OpenSSL subprocess --]\n"));
    }
    goto cleanup;
  }

  if (type & SEC_ENCRYPT)
  {
    if (!smime_class_valid_passphrase())
      smime_class_void_passphrase();
    fputs(SmimePass, fp_smime_in);
    fputc('\n', fp_smime_in);
  }

  mutt_file_fclose(&fp_smime_in);

  filter_wait(pid);
  mutt_file_unlink(buf_string(tmpfname));

  if (state->flags & STATE_DISPLAY)
  {
    fflush(fp_smime_err);
    rewind(fp_smime_err);

    const int c = fgetc(fp_smime_err);
    if (c != EOF)
    {
      ungetc(c, fp_smime_err);

      crypt_current_time(state, "OpenSSL");
      mutt_file_copy_stream(fp_smime_err, state->fp_out);
      state_attach_puts(state, _("[-- End of OpenSSL output --]\n\n"));
    }

    if (type & SEC_ENCRYPT)
    {
      state_attach_puts(state, _("[-- The following data is S/MIME encrypted --]\n"));
    }
    else
    {
      state_attach_puts(state, _("[-- The following data is S/MIME signed --]\n"));
    }
  }

  fflush(fp_smime_out);
  rewind(fp_smime_out);

  if (type & SEC_ENCRYPT)
  {
    /* void the passphrase, even if that wasn't the problem */
    if (fgetc(fp_smime_out) == EOF)
    {
      mutt_error(_("Decryption failed"));
      smime_class_void_passphrase();
    }
    rewind(fp_smime_out);
  }

  if (fp_out_file)
  {
    fp_out = fp_out_file;
  }
  else
  {
    fp_out = mutt_file_mkstemp();
    if (!fp_out)
    {
      mutt_perror(_("Can't create temporary file"));
      goto cleanup;
    }
  }
  char buf[8192] = { 0 };
  while (fgets(buf, sizeof(buf) - 1, fp_smime_out))
  {
    const size_t len = mutt_str_len(buf);
    if ((len > 1) && (buf[len - 2] == '\r'))
    {
      buf[len - 2] = '\n';
      buf[len - 1] = '\0';
    }
    fputs(buf, fp_out);
  }
  fflush(fp_out);
  rewind(fp_out);

  const long size = mutt_file_get_size_fp(fp_out);
  if (size == 0)
  {
    goto cleanup;
  }
  p = mutt_read_mime_header(fp_out, 0);
  if (p)
  {
    p->length = size - p->offset;

    mutt_parse_part(fp_out, p);

    if (state->flags & STATE_DISPLAY)
      mutt_protected_headers_handler(p, state);

    /* Store any protected headers in the parent so they can be
     * accessed for index updates after the handler recursion is done.
     * This is done before the handler to prevent a nested encrypted
     * handler from freeing the headers. */
    mutt_env_free(&b->mime_headers);
    b->mime_headers = p->mime_headers;
    p->mime_headers = NULL;

    if (state->fp_out)
    {
      rewind(fp_out);
      FILE *fp_tmp_buffer = state->fp_in;
      state->fp_in = fp_out;
      mutt_body_handler(p, state);
      state->fp_in = fp_tmp_buffer;
    }

    /* Embedded multipart signed protected headers override the
     * encrypted headers.  We need to do this after the handler so
     * they can be printed in the pager. */
    if (!(type & SMIME_SIGN) && mutt_is_multipart_signed(p) && p->parts &&
        p->parts->mime_headers)
    {
      mutt_env_free(&b->mime_headers);
      b->mime_headers = p->parts->mime_headers;
      p->parts->mime_headers = NULL;
    }
  }
  mutt_file_fclose(&fp_smime_out);

  if (!fp_out_file)
  {
    mutt_file_fclose(&fp_out);
    mutt_file_unlink(buf_string(tmpfname));
  }
  fp_out = NULL;

  if (state->flags & STATE_DISPLAY)
  {
    if (type & SEC_ENCRYPT)
      state_attach_puts(state, _("[-- End of S/MIME encrypted data --]\n"));
    else
      state_attach_puts(state, _("[-- End of S/MIME signed data --]\n"));
  }

  if (type & SEC_SIGNOPAQUE)
  {
    char *line = NULL;
    size_t linelen;

    rewind(fp_smime_err);

    line = mutt_file_read_line(line, &linelen, fp_smime_err, NULL, MUTT_RL_NO_FLAGS);
    if (linelen && mutt_istr_equal(line, "verification successful"))
      b->goodsig = true;
    FREE(&line);
  }
  else if (p)
  {
    b->goodsig = p->goodsig;
    b->badsig = p->badsig;
  }

cleanup:
  mutt_file_fclose(&fp_smime_out);
  mutt_file_fclose(&fp_smime_err);
  mutt_file_fclose(&fp_tmp);
  mutt_file_fclose(&fp_out);
  buf_pool_release(&tmpfname);
  return p;
}

/**
 * smime_class_decrypt_mime - Decrypt an encrypted MIME part - Implements CryptModuleSpecs::decrypt_mime() - @ingroup crypto_decrypt_mime
 */
int smime_class_decrypt_mime(FILE *fp_in, FILE **fp_out, struct Body *b, struct Body **b_dec)
{
  struct State state = { 0 };
  LOFF_T tmpoffset = b->offset;
  size_t tmplength = b->length;
  int rc = -1;

  if (!mutt_is_application_smime(b))
    return -1;

  if (b->parts)
    return -1;

  state.fp_in = fp_in;
  if (!mutt_file_seek(state.fp_in, b->offset, SEEK_SET))
  {
    return -1;
  }

  FILE *fp_tmp = mutt_file_mkstemp();
  if (!fp_tmp)
  {
    mutt_perror(_("Can't create temporary file"));
    return -1;
  }

  state.fp_out = fp_tmp;
  mutt_decode_attachment(b, &state);
  fflush(fp_tmp);
  b->length = ftello(state.fp_out);
  b->offset = 0;
  rewind(fp_tmp);
  state.fp_in = fp_tmp;
  state.fp_out = 0;

  *fp_out = mutt_file_mkstemp();
  if (!*fp_out)
  {
    mutt_perror(_("Can't create temporary file"));
    goto bail;
  }

  *b_dec = smime_handle_entity(b, &state, *fp_out);
  if (!*b_dec)
    goto bail;

  (*b_dec)->goodsig = b->goodsig;
  (*b_dec)->badsig = b->badsig;
  rc = 0;

bail:
  b->length = tmplength;
  b->offset = tmpoffset;
  mutt_file_fclose(&fp_tmp);
  if (*fp_out)
    rewind(*fp_out);

  return rc;
}

/**
 * smime_class_application_handler - Manage the MIME type "application/pgp" or "application/smime" - Implements CryptModuleSpecs::application_handler() - @ingroup crypto_application_handler
 */
int smime_class_application_handler(struct Body *b, struct State *state)
{
  int rc = -1;

  /* clear out any mime headers before the handler, so they can't be spoofed. */
  mutt_env_free(&b->mime_headers);

  struct Body *tattach = smime_handle_entity(b, state, NULL);
  if (tattach)
  {
    rc = 0;
    mutt_body_free(&tattach);
  }
  return rc;
}

/**
 * smime_class_send_menu - Ask the user whether to sign and/or encrypt the email - Implements CryptModuleSpecs::send_menu() - @ingroup crypto_send_menu
 */
SecurityFlags smime_class_send_menu(struct Email *e)
{
  struct SmimeKey *key = NULL;
  const char *prompt = NULL;
  const char *letters = NULL;
  const char *choices = NULL;
  int choice;

  if (!(WithCrypto & APPLICATION_SMIME))
    return e->security;

  e->security |= APPLICATION_SMIME;

  /* Opportunistic encrypt is controlling encryption.
   * NOTE: "Signing" and "Clearing" only adjust the sign bit, so we have different
   *       letter choices for those.  */
  const bool c_crypt_opportunistic_encrypt = cs_subset_bool(NeoMutt->sub, "crypt_opportunistic_encrypt");
  if (c_crypt_opportunistic_encrypt && (e->security & SEC_OPPENCRYPT))
  {
    /* L10N: S/MIME options (opportunistic encryption is on) */
    prompt = _("S/MIME (s)ign, encrypt (w)ith, sign (a)s, (c)lear, or (o)ppenc mode off?");
    /* L10N: S/MIME options (opportunistic encryption is on) */
    letters = _("swaco");
    choices = "SwaCo";
  }
  else if (c_crypt_opportunistic_encrypt)
  {
    /* Opportunistic encryption option is set, but is toggled off
     * for this message.  */
    /* L10N: S/MIME options (opportunistic encryption is off) */
    prompt = _("S/MIME (e)ncrypt, (s)ign, encrypt (w)ith, sign (a)s, (b)oth, (c)lear, or (o)ppenc mode?");
    /* L10N: S/MIME options (opportunistic encryption is off) */
    letters = _("eswabco");
    choices = "eswabcO";
  }
  else
  {
    /* Opportunistic encryption is unset */
    /* L10N: S/MIME options */
    prompt = _("S/MIME (e)ncrypt, (s)ign, encrypt (w)ith, sign (a)s, (b)oth, or (c)lear?");
    /* L10N: S/MIME options */
    letters = _("eswabc");
    choices = "eswabc";
  }

  choice = mw_multi_choice(prompt, letters);
  if (choice > 0)
  {
    switch (choices[choice - 1])
    {
      case 'a': /* sign (a)s */
        key = smime_ask_for_key(_("Sign as: "), KEYFLAG_CANSIGN, false);
        if (key)
        {
          cs_subset_str_string_set(NeoMutt->sub, "smime_sign_as", key->hash, NULL);
          smime_key_free(&key);

          e->security |= SEC_SIGN;

          /* probably need a different passphrase */
          crypt_smime_void_passphrase();
        }

        break;

      case 'b': /* (b)oth */
        e->security |= (SEC_ENCRYPT | SEC_SIGN);
        break;

      case 'c': /* (c)lear */
        e->security &= ~(SEC_ENCRYPT | SEC_SIGN);
        break;

      case 'C':
        e->security &= ~SEC_SIGN;
        break;

      case 'e': /* (e)ncrypt */
        e->security |= SEC_ENCRYPT;
        e->security &= ~SEC_SIGN;
        break;

      case 'O': /* oppenc mode on */
        e->security |= SEC_OPPENCRYPT;
        crypt_opportunistic_encrypt(e);
        break;

      case 'o': /* oppenc mode off */
        e->security &= ~SEC_OPPENCRYPT;
        break;

      case 'S': /* (s)ign in oppenc mode */
        e->security |= SEC_SIGN;
        break;

      case 's': /* (s)ign */
        e->security &= ~SEC_ENCRYPT;
        e->security |= SEC_SIGN;
        break;

      case 'w': /* encrypt (w)ith */
      {
        e->security |= SEC_ENCRYPT;
        do
        {
          struct Buffer *errmsg = buf_pool_get();
          int rc = CSR_SUCCESS;
          switch (mw_multi_choice(_("Choose algorithm family: (1) DES, (2) RC2, (3) AES, or (c)lear?"),
                                  // L10N: Options for: Choose algorithm family: (1) DES, (2) RC2, (3) AES, or (c)lear?
                                  _("123c")))
          {
            case 1:
              switch (choice = mw_multi_choice(_("(1) DES, (2) Triple-DES?"),
                                               // L10N: Options for: (1) DES, (2) Triple-DES
                                               _("12")))
              {
                case 1:
                  rc = cs_subset_str_string_set(NeoMutt->sub, "smime_encrypt_with",
                                                "des", errmsg);
                  break;
                case 2:
                  rc = cs_subset_str_string_set(NeoMutt->sub, "smime_encrypt_with",
                                                "des3", errmsg);
                  break;
              }
              break;

            case 2:
              switch (choice = mw_multi_choice(_("(1) RC2-40, (2) RC2-64, (3) RC2-128?"),
                                               // L10N: Options for: (1) RC2-40, (2) RC2-64, (3) RC2-128
                                               _("123")))
              {
                case 1:
                  rc = cs_subset_str_string_set(NeoMutt->sub, "smime_encrypt_with",
                                                "rc2-40", errmsg);
                  break;
                case 2:
                  rc = cs_subset_str_string_set(NeoMutt->sub, "smime_encrypt_with",
                                                "rc2-64", errmsg);
                  break;
                case 3:
                  rc = cs_subset_str_string_set(NeoMutt->sub, "smime_encrypt_with",
                                                "rc2-128", errmsg);
                  break;
              }
              break;

            case 3:
              switch (choice = mw_multi_choice(_("(1) AES128, (2) AES192, (3) AES256?"),
                                               // L10N: Options for: (1) AES128, (2) AES192, (3) AES256
                                               _("123")))
              {
                case 1:
                  rc = cs_subset_str_string_set(NeoMutt->sub, "smime_encrypt_with",
                                                "aes128", errmsg);
                  break;
                case 2:
                  rc = cs_subset_str_string_set(NeoMutt->sub, "smime_encrypt_with",
                                                "aes192", errmsg);
                  break;
                case 3:
                  rc = cs_subset_str_string_set(NeoMutt->sub, "smime_encrypt_with",
                                                "aes256", errmsg);
                  break;
              }
              break;

            case 4:
              rc = cs_subset_str_string_set(NeoMutt->sub, "smime_encrypt_with", NULL, errmsg);
              /* (c)lear */
              FALLTHROUGH;

            case -1: /* Ctrl-G or Enter */
              choice = 0;
              break;
          }

          if ((CSR_RESULT(rc) != CSR_SUCCESS) && !buf_is_empty(errmsg))
            mutt_error("%s", buf_string(errmsg));

          buf_pool_release(&errmsg);
        } while (choice == -1);
        break;
      }
    }
  }

  return e->security;
}
