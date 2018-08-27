/**
 * @file
 * Register crypto modules
 *
 * @authors
 * Copyright (C) 2017 Richard Russon <rich@flatcap.org>
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

#ifndef _NCRYPT_CRYPT_MOD_H
#define _NCRYPT_CRYPT_MOD_H

#include <stdbool.h>
#include <stdio.h>

struct Address;
struct Body;
struct Envelope;
struct Header;
struct State;

/**
 * struct CryptModuleSpecs - Crypto API
 *
 * A structure to describe a crypto module.
 */
struct CryptModuleSpecs
{
  int identifier; /**< Identifying bit */

  /**
   * init - Initialise the crypto module
   */
  void         (*init)(void);
  /**
   * void_passphrase - Forget the cached passphrase
   */
  void         (*void_passphrase)(void);
  /**
   * valid_passphrase - Ensure we have a valid passphrase
   * @retval 1 Success
   * @retval 0 Failed
   *
   * If the passphrase is within the expiry time (backend-specific), use it.
   * If not prompt the user again.
   */
  int          (*valid_passphrase)(void);
  /**
   * decrypt_mime - Decrypt an encrypted MIME part
   * @param[in]  fpin  File containing the encrypted part
   * @param[out] fpout File containing the decrypted part
   * @param[in]  b     Body of the email
   * @param[out] cur   Body containing the decrypted part
   * @retval  0 Success
   * @retval -1 Failure
   */
  int          (*decrypt_mime)(FILE *fpin, FILE **fpout, struct Body *b, struct Body **cur);
  /**
   * application_handler - Manage the MIME type "application/pgp" or "application/smime"
   * @param m Body of the email
   * @param s State of text being processed
   * @retval 0 Success
   * @retval -1 Error
   */
  int          (*application_handler)(struct Body *m, struct State *s);
  /**
   * encrypted_handler - Manage a PGP or S/MIME encrypted MIME part
   * @param m Body of the email
   * @param s State of text being processed
   * @retval 0 Success
   * @retval -1 Error
   */
  int          (*encrypted_handler)(struct Body *m, struct State *s);
  /**
   * find_keys - Find the keyids of the recipients of a message
   * @param addrlist    Address List
   * @param oppenc_mode If true, use opportunistic encryption
   * @retval ptr  Space-separated string of keys
   * @retval NULL At least one of the keys can't be found
   *
   * If oppenc_mode is true, only keys that can be determined without prompting
   * will be used.
   */
  char *       (*find_keys)(struct Address *addrlist, bool oppenc_mode);
  /**
   * sign_message - Cryptographically sign the Body of a message
   * @param a Body of the message
   * @retval ptr  New encrypted Body
   * @retval NULL Error
   */
  struct Body *(*sign_message)(struct Body *a);
  /**
   * verify_one - Check a signed MIME part against a signature
   * @param sigbdy Body of the signed mail
   * @param s      State of text being processed
   * @param tempf  File containing the key
   * @retval  0 Success
   * @retval -1 Error
   */
  int          (*verify_one)(struct Body *sigbdy, struct State *s, const char *tempf);
  /**
   * send_menu - Ask the user whether to sign and/or encrypt the email
   * @param msg Header of the email
   * @retval num Flags, e.g. #APPLICATION_PGP | #ENCRYPT
   */
  int          (*send_menu)(struct Header *msg);
  /**
   * set_sender - Set the sender of the email
   * @param sender Email address
   */
  void         (*set_sender)(const char *sender);

  /**
   * pgp_encrypt_message - PGP encrypt an email
   * @param a       Body of email to encrypt
   * @param keylist List of keys, or fingerprints (space separated)
   * @param sign    If true, sign the message too
   * @retval ptr  Encrypted Body
   * @retval NULL Error
   *
   * Encrypt the mail body to all the given keys.
   */
  struct Body *(*pgp_encrypt_message)(struct Body *a, char *keylist, bool sign);
  /**
   * pgp_make_key_attachment - Generate a public key attachment
   * @retval ptr  New Body containing the attachment
   * @retval NULL Error
   */
  struct Body *(*pgp_make_key_attachment)(void);
  /**
   * pgp_check_traditional - Look for inline (non-MIME) PGP content
   * @param fp       File pointer to the current attachment
   * @param b        Body of email to check
   * @param just_one If true, just check one email part
   * @retval 1 It's an inline PGP email
   * @retval 0 It's not inline, or an error
   */
  int          (*pgp_check_traditional)(FILE *fp, struct Body *b, bool just_one);
  /**
   * pgp_traditional_encryptsign - Create an inline PGP encrypted, signed email
   * @param a       Body of the email
   * @param flags   Flags, e.g. #ENCRYPT
   * @param keylist List of keys to encrypt to (space-separated)
   * @retval ptr  New encrypted/siged Body
   * @retval NULL Error
   */
  struct Body *(*pgp_traditional_encryptsign)(struct Body *a, int flags, char *keylist);
  /**
   * pgp_invoke_getkeys - Run a command to download a PGP key
   * @param addr Address to search for
   */
  void         (*pgp_invoke_getkeys)(struct Address *addr);
  /**
   * pgp_invoke_import - Import a key from a message into the user's public key ring
   * @param fname File containing the message
   */
  void         (*pgp_invoke_import)(const char *fname);
  /**
   * pgp_extract_key_from_attachment - Extract PGP key from an attachment
   * @param fp  File containing email
   * @param top Body of the email
   */
  void         (*pgp_extract_key_from_attachment)(FILE *fp, struct Body *top);

  /**
   * smime_getkeys - Get the S/MIME keys required to encrypt this email
   * @param env Envelope of the email
   */
  void         (*smime_getkeys)(struct Envelope *env);
  /**
   * smime_verify_sender - Does the sender match the certificate?
   * @param h Header of the email
   * @retval 0 Success
   * @retval 1 Failure
   */
  int          (*smime_verify_sender)(struct Header *h);
  /**
   * smime_build_smime_entity - Encrypt the email body to all recipients
   * @param a        Body of email
   * @param certlist List of key fingerprints (space separated)
   * @retval ptr  New S/MIME encrypted Body
   * @retval NULL Error
   */
  struct Body *(*smime_build_smime_entity)(struct Body *a, char *certlist);
  /**
   * smime_invoke_import - Add a certificate and update index file (externally)
   * @param infile  File containing certificate
   * @param mailbox Mailbox
   */
  void         (*smime_invoke_import)(char *infile, char *mailbox);
};

/* High Level crypto module interface */
void crypto_module_register(struct CryptModuleSpecs *specs);
struct CryptModuleSpecs *crypto_module_lookup(int identifier);

#endif /* _NCRYPT_CRYPT_MOD_H */
