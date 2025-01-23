/**
 * @file
 * Config used by libnotmuch
 *
 * @authors
 * Copyright (C) 2020-2023 Richard Russon <rich@flatcap.org>
 * Copyright (C) 2021-2022 Austin Ray <austin@austinray.io>
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
 * @page nm_config Config used by libnotmuch
 *
 * Config used by libnotmuch
 */

#include "config.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "private.h"
#include "mutt/lib.h"
#include "config/lib.h"
#include "query.h"

#ifdef USE_NOTMUCH
/**
 * is_valid_notmuch_url - Checks that a URL is in required form
 * @param url URL to test
 * @retval true  url in form notmuch://[absolute path]
 * @retval false url is not in required form
 */
static bool is_valid_notmuch_url(const char *url)
{
  return mutt_istr_startswith(url, NmUrlProtocol) && (url[NmUrlProtocolLen] == '/');
}
#endif

/**
 * nm_default_url_validator - Validate the "nm_default_url" config variable - Implements ConfigDef::validator() - @ingroup cfg_def_validator
 *
 * Ensure nm_default_url is of the form notmuch://[absolute path]
 */
static int nm_default_url_validator(const struct ConfigDef *cdef,
                                    intptr_t value, struct Buffer *err)
{
#ifdef USE_NOTMUCH
  const char *url = (const char *) value;
  if (!is_valid_notmuch_url(url))
  {
    buf_printf(err, _("nm_default_url must be: notmuch://<absolute path> . Current: %s"), url);
    return CSR_ERR_INVALID;
  }
#endif
  return CSR_SUCCESS;
}

/**
 * nm_query_window_timebase_validator - Validate the "nm_query_window_timebase" config variable - Implements ConfigDef::validator() - @ingroup cfg_def_validator
 *
 * Ensure $nm_query_window_timebase matches allowed values.
 *
 * Allowed values:
 * - hour
 * - day
 * - week
 * - month
 * - year
 */
static int nm_query_window_timebase_validator(const struct ConfigDef *cdef,
                                              intptr_t value, struct Buffer *err)
{
#ifdef USE_NOTMUCH
  const char *timebase = (const char *) value;
  if (!nm_query_window_check_timebase(timebase))
  {
    buf_printf(
        // L10N: The values 'hour', 'day', 'week', 'month', 'year' are literal.
        //       They should not be translated.
        err, _("Invalid nm_query_window_timebase value (valid values are: "
               "hour, day, week, month, year)"));
    return CSR_ERR_INVALID;
  }
#endif
  return CSR_SUCCESS;
}

/**
 * NotmuchVars - Config definitions for the Notmuch library
 */
static struct ConfigDef NotmuchVars[] = {
  // clang-format off
  { "nm_config_file", DT_PATH|D_PATH_FILE, IP "auto", 0, NULL,
    "(notmuch) Configuration file for notmuch. Use 'auto' to detect configuration."
  },
  { "nm_config_profile", DT_STRING, 0, 0, NULL,
    "(notmuch) Configuration profile for notmuch."
  },
  { "nm_db_limit", DT_NUMBER|D_INTEGER_NOT_NEGATIVE, 0, 0, NULL,
    "(notmuch) Default limit for Notmuch queries"
  },
  { "nm_default_url", DT_STRING, 0, 0, nm_default_url_validator,
    "(notmuch) Path to the Notmuch database"
  },
  { "nm_exclude_tags", DT_STRING, 0, 0, NULL,
    "(notmuch) Exclude messages with these tags"
  },
  { "nm_flagged_tag", DT_STRING, IP "flagged", 0, NULL,
    "(notmuch) Tag to use for flagged messages"
  },
  { "nm_open_timeout", DT_NUMBER|D_INTEGER_NOT_NEGATIVE, 5, 0, NULL,
    "(notmuch) Database timeout"
  },
  { "nm_query_type", DT_STRING, IP "messages", 0, NULL,
    "(notmuch) Default query type: 'threads' or 'messages'"
  },
  { "nm_query_window_current_position", DT_NUMBER, 0, 0, NULL,
    "(notmuch) Position of current search window"
  },
  { "nm_query_window_current_search", DT_STRING, 0, 0, NULL,
    "(notmuch) Current search parameters"
  },
  { "nm_query_window_duration", DT_NUMBER|D_INTEGER_NOT_NEGATIVE, 0, 0, NULL,
    "(notmuch) Time duration of the current search window"
  },
  { "nm_query_window_enable", DT_BOOL, false, 0, NULL,
    "(notmuch) Enable query windows"
  },
  { "nm_query_window_or_terms", DT_STRING, 0, 0, NULL,
    "(notmuch) Additional notmuch search terms for messages to be shown regardless of date"
  },
  { "nm_query_window_timebase", DT_STRING, IP "week", 0, nm_query_window_timebase_validator,
    "(notmuch) Units for the time duration"
  },
  { "nm_record_tags", DT_STRING, 0, 0, NULL,
    "(notmuch) Tags to apply to the 'record' mailbox (sent mail)"
  },
  { "nm_replied_tag", DT_STRING, IP "replied", 0, NULL,
    "(notmuch) Tag to use for replied messages"
  },
  { "nm_unread_tag", DT_STRING, IP "unread", 0, NULL,
    "(notmuch) Tag to use for unread messages"
  },
  { "virtual_spool_file", DT_BOOL, false, 0, NULL,
    "(notmuch) Use the first virtual mailbox as a spool file"
  },

  { "vfolder_format",    D_INTERNAL_DEPRECATED|DT_STRING, 0, IP "2018-11-01" },

  { "nm_default_uri",    DT_SYNONYM, IP "nm_default_url",     IP "2021-02-11" },
  { "virtual_spoolfile", DT_SYNONYM, IP "virtual_spool_file", IP "2021-02-11" },
  { NULL },
  // clang-format on
};

/**
 * config_init_notmuch - Register notmuch config variables - Implements ::module_init_config_t - @ingroup cfg_module_api
 */
bool config_init_notmuch(struct ConfigSet *cs)
{
  bool rc = false;

#if defined(USE_NOTMUCH)
  rc |= cs_register_variables(cs, NotmuchVars);
#endif

  return rc;
}
