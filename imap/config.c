/**
 * @file
 * Config used by libimap
 *
 * @authors
 * Copyright (C) 2020 Yousef Akbar <yousef@yhakbar.com>
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
 * @page imap_config Config used by IMAP
 *
 * Config used by libimap
 */

#include "config.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "mutt/lib.h"
#include "config/lib.h"
#include "auth.h"
#ifdef USE_SASL_CYRUS
#include "conn/lib.h"
#endif

/**
 * imap_auth_validator - Validate the "imap_authenticators" config variable - Implements ConfigDef::validator() - @ingroup cfg_def_validator
 */
static int imap_auth_validator(const struct ConfigDef *cdef, intptr_t value, struct Buffer *err)
{
  const struct Slist *imap_auth_methods = (const struct Slist *) value;
  if (!imap_auth_methods || (imap_auth_methods->count == 0))
    return CSR_SUCCESS;

  struct ListNode *np = NULL;
  STAILQ_FOREACH(np, &imap_auth_methods->head, entries)
  {
    if (imap_auth_is_valid(np->data))
      continue;
#ifdef USE_SASL_CYRUS
    if (sasl_auth_validator(np->data))
      continue;
#endif
    buf_printf(err, _("Option %s: %s is not a valid authenticator"), cdef->name, np->data);
    return CSR_ERR_INVALID;
  }

  return CSR_SUCCESS;
}

/**
 * ImapVars - Config definitions for the IMAP library
 */
static struct ConfigDef ImapVars[] = {
  // clang-format off
  { "imap_check_subscribed", DT_BOOL, false, 0, NULL,
    "(imap) When opening a mailbox, ask the server for a list of subscribed folders"
  },
  { "imap_condstore", DT_BOOL, false, 0, NULL,
    "(imap) Enable the CONDSTORE extension"
  },
  { "imap_authenticators", DT_SLIST|D_SLIST_SEP_COLON, 0, 0, imap_auth_validator,
    "(imap) List of allowed IMAP authentication methods (colon-separated)"
  },
  { "imap_delim_chars", DT_STRING, IP "/.", 0, NULL,
    "(imap) Characters that denote separators in IMAP folders"
  },
  { "imap_fetch_chunk_size", DT_LONG|D_INTEGER_NOT_NEGATIVE, 0, 0, NULL,
    "(imap) Download headers in blocks of this size"
  },
  { "imap_headers", DT_STRING, 0, 0, NULL,
    "(imap) Additional email headers to download when getting index"
  },
  { "imap_idle", DT_BOOL, false, 0, NULL,
    "(imap) Use the IMAP IDLE extension to check for new mail"
  },
  { "imap_login", DT_STRING|D_SENSITIVE, 0, 0, NULL,
    "(imap) Login name for the IMAP server (defaults to `$imap_user`)"
  },
  { "imap_oauth_refresh_command", DT_STRING|D_STRING_COMMAND|D_SENSITIVE, 0, 0, NULL,
    "(imap) External command to generate OAUTH refresh token"
  },
  { "imap_pass", DT_STRING|D_SENSITIVE, 0, 0, NULL,
    "(imap) Password for the IMAP server"
  },
  { "imap_pipeline_depth", DT_NUMBER|D_INTEGER_NOT_NEGATIVE, 15, 0, NULL,
    "(imap) Number of IMAP commands that may be queued up"
  },
  { "imap_rfc5161", DT_BOOL, true, 0, NULL,
    "(imap) Use the IMAP ENABLE extension to select capabilities"
  },
  { "imap_server_noise", DT_BOOL, true, 0, NULL,
    "(imap) Display server warnings as error messages"
  },
  { "imap_keep_alive", DT_NUMBER|D_INTEGER_NOT_NEGATIVE, 300, 0, NULL,
    "(imap) Time to wait before polling an open IMAP connection"
  },
  { "imap_list_subscribed", DT_BOOL, false, 0, NULL,
    "(imap) When browsing a mailbox, only display subscribed folders"
  },
  { "imap_passive", DT_BOOL, true, 0, NULL,
    "(imap) Reuse an existing IMAP connection to check for new mail"
  },
  { "imap_peek", DT_BOOL, true, 0, NULL,
    "(imap) Don't mark messages as read when fetching them from the server"
  },
  { "imap_poll_timeout", DT_NUMBER|D_INTEGER_NOT_NEGATIVE, 15, 0, NULL,
    "(imap) Maximum time to wait for a server response"
  },
  { "imap_qresync", DT_BOOL, false, 0, NULL,
    "(imap) Enable the QRESYNC extension"
  },
  { "imap_send_id", DT_BOOL, false, 0, NULL,
    "(imap) Send ID command when logging in"
  },
  { "imap_user", DT_STRING|D_SENSITIVE, 0, 0, NULL,
    "(imap) Username for the IMAP server"
  },

  { "imap_keepalive",   DT_SYNONYM, IP "imap_keep_alive",   IP "2023-05-31" },
  { "imap_servernoise", DT_SYNONYM, IP "imap_server_noise", IP "2021-02-11" },
  { NULL },
  // clang-format on
};

#if defined(USE_ZLIB)
/**
 * ImapVarsZlib - Config definitions for IMAP compression
 */
static struct ConfigDef ImapVarsZlib[] = {
  // clang-format off
  { "imap_deflate", DT_BOOL, true, 0, NULL,
    "(imap) Compress network traffic"
  },
  { NULL },
  // clang-format on
};
#endif

/**
 * config_init_imap - Register imap config variables - Implements ::module_init_config_t - @ingroup cfg_module_api
 */
bool config_init_imap(struct ConfigSet *cs)
{
  bool rc = cs_register_variables(cs, ImapVars);

#if defined(USE_ZLIB)
  rc |= cs_register_variables(cs, ImapVarsZlib);
#endif

  return rc;
}
