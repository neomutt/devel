/**
 * @file
 * Command line processing
 *
 * @authors
 * Copyright (C) 1996-2007,2010,2013 Michael R. Elkins <me@mutt.org>
 * Copyright (C) 1999-2007 Thomas Roessler <roessler@does-not-exist.org>
 * Copyright (C) 2004 g10 Code GmbH
 * Copyright (C) 2016-2025 Richard Russon <rich@flatcap.org>
 * Copyright (C) 2017-2023 Pietro Cerutti <gahr@gahr.ch>
 * Copyright (C) 2020 R Primus <rprimus@gmail.com>
 * Copyright (C) 2023 Dennis Schön <mail@dennis-schoen.de>
 * Copyright (C) 2024 Alejandro Colomar <alx@kernel.org>
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
 * @mainpage Code Docs
 *
 * <img style="float: left; padding-right: 0.5em;" src="structs.svg">
 * <img style="float: left; padding-right: 0.5em;" src="pages.svg">
 * <img style="float: left; padding-right: 0.5em;" src="globals.svg">
 * <img style="float: left; padding-right: 0.5em;" src="functions.svg">
 * <img style="float: left; padding-right: 0.5em;" src="enums.svg">
 * <img style="float: left; padding-right: 0.5em;" src="members.svg">
 * <img style="float: left; padding-right: 0.5em;" src="defines.svg">
 * <br>
 *
 * ## Libraries
 *
 * [Each library](pages.html) helps to untangle the code by grouping similar
 * functions and reducing dependencies.
 *
 * The goal is that each library is:
 * - Self-contained (it may rely on other libraries)
 * - Independently testable (i.e. without using NeoMutt)
 * - Fully documented
 * - Robust
 *
 * Libraries:
 * @ref lib_address, @ref lib_alias, @ref lib_attach, @ref lib_autocrypt,
 * @ref lib_bcache, @ref lib_browser, @ref lib_color, @ref lib_complete,
 * @ref lib_compmbox, @ref lib_compose, @ref lib_compress, @ref lib_config,
 * @ref lib_conn, @ref lib_convert, @ref lib_core, @ref lib_editor,
 * @ref lib_email, @ref lib_envelope, @ref lib_expando, @ref lib_gui,
 * @ref lib_hcache, @ref lib_helpbar, @ref lib_history, @ref lib_imap,
 * @ref lib_index, @ref lib_key, @ref lib_maildir, @ref lib_mh, @ref lib_mbox,
 * @ref lib_menu, @ref lib_mutt, @ref lib_ncrypt, @ref lib_nntp,
 * @ref lib_notmuch, @ref lib_pager, @ref lib_parse, @ref lib_pattern,
 * @ref pfile, @ref lib_pop, @ref lib_postpone, @ref lib_progress,
 * @ref lib_question, @ref lib_send, @ref lib_sidebar, @ref lib_spager,
 * @ref lib_store.
 *
 * ## Miscellaneous files
 *
 * These file form the main body of NeoMutt.
 *
 * | File            | Description                |
 * | :-------------- | :------------------------- |
 * | alternates.c    | @subpage neo_alternates    |
 * | commands.c      | @subpage neo_commands      |
 * | copy.c          | @subpage neo_copy          |
 * | editmsg.c       | @subpage neo_editmsg       |
 * | enriched.c      | @subpage neo_enriched      |
 * | external.c      | @subpage neo_external      |
 * | flags.c         | @subpage neo_flags         |
 * | globals.c       | @subpage neo_globals       |
 * | handler.c       | @subpage neo_handler       |
 * | help.c          | @subpage neo_help          |
 * | hook.c          | @subpage neo_hook          |
 * | mailcap.c       | @subpage neo_mailcap       |
 * | maillist.c      | @subpage neo_maillist      |
 * | main.c          | @subpage neo_main          |
 * | monitor.c       | @subpage neo_monitor       |
 * | muttlib.c       | @subpage neo_muttlib       |
 * | mutt_body.c     | @subpage neo_mutt_body     |
 * | mutt_config.c   | @subpage neo_mutt_config   |
 * | mutt_header.c   | @subpage neo_mutt_header   |
 * | mutt_logging.c  | @subpage neo_mutt_logging  |
 * | mutt_lua.c      | @subpage neo_mutt_lua      |
 * | mutt_mailbox.c  | @subpage neo_mutt_mailbox  |
 * | mutt_signal.c   | @subpage neo_mutt_signal   |
 * | mutt_socket.c   | @subpage neo_mutt_socket   |
 * | mutt_thread.c   | @subpage neo_mutt_thread   |
 * | mview.c         | @subpage neo_mview         |
 * | mx.c            | @subpage neo_mx            |
 * | recvcmd.c       | @subpage neo_recvcmd       |
 * | rfc3676.c       | @subpage neo_rfc3676       |
 * | score.c         | @subpage neo_score         |
 * | subjectrx.c     | @subpage neo_subjrx        |
 * | system.c        | @subpage neo_system        |
 * | timegm.c        | @subpage neo_timegm        |
 * | version.c       | @subpage neo_version       |
 * | wcscasecmp.c    | @subpage neo_wcscasecmp    |
 *
 * ## Building these Docs
 *
 * The config for building the docs is in the main source repo.
 *
 * Everything possible is turned on in the config file, so you'll need to
 * install a few dependencies like `dot` from the graphviz package.
 *
 * ## Installing the Docs
 *
 * These docs aren't in the main website repo -- they weigh in at 100MB.
 * Instead, they're stored in the [code repo](https://github.com/neomutt/code)
 */

/**
 * @page neo_main Command line processing
 *
 * Command line processing
 */

#define GNULIB_defined_setlocale

#include "config.h"
#include <errno.h>
#include <limits.h>
#include <locale.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>
#include "mutt/lib.h"
#include "address/lib.h"
#include "config/lib.h"
#include "email/lib.h"
#include "core/lib.h"
#include "alias/lib.h"
#include "conn/lib.h"
#include "gui/lib.h"
#include "mutt.h"
#include "attach/lib.h"
#include "browser/lib.h"
#include "color/lib.h"
#include "compmbox/lib.h"
#include "history/lib.h"
#include "imap/lib.h"
#include "index/lib.h"
#include "key/lib.h"
#include "menu/lib.h"
#include "ncrypt/lib.h"
#include "nntp/lib.h"
#include "notmuch/lib.h"
#include "parse/lib.h"
#include "pop/lib.h"
#include "postpone/lib.h"
#include "question/lib.h"
#include "send/lib.h"
#include "sidebar/lib.h"
#include "alternates.h"
#include "commands.h"
#include "external.h"
#include "globals.h"
#include "hook.h"
#include "mutt_logging.h"
#include "mutt_mailbox.h"
#include "muttlib.h"
#include "mx.h"
#include "nntp/adata.h" // IWYU pragma: keep
#include "protos.h"
#include "subjectrx.h"
#include "version.h"
#ifdef ENABLE_NLS
#include <libintl.h>
#endif
#ifdef USE_AUTOCRYPT
#include "autocrypt/lib.h"
#endif
#if defined(USE_DEBUG_NOTIFY) || defined(USE_DEBUG_BACKTRACE)
#include "debug/lib.h"
#endif
#ifndef DOMAIN
#include "conn/lib.h"
#endif
#ifdef USE_LUA
#include "mutt_lua.h"
#endif

bool StartupComplete = false; ///< When the config has been read

// clang-format off
typedef uint8_t CliFlags;         ///< Flags for command line options, e.g. #MUTT_CLI_IGNORE
#define MUTT_CLI_NO_FLAGS      0  ///< No flags are set
#define MUTT_CLI_IGNORE  (1 << 0) ///< -z Open first mailbox if it has mail
#define MUTT_CLI_MAILBOX (1 << 1) ///< -Z Open first mailbox if is has new mail
#define MUTT_CLI_NOSYSRC (1 << 2) ///< -n Do not read the system-wide config file
#define MUTT_CLI_RO      (1 << 3) ///< -R Open mailbox in read-only mode
#define MUTT_CLI_SELECT  (1 << 4) ///< -y Start with a list of all mailboxes
#define MUTT_CLI_NEWS    (1 << 5) ///< -g/-G Start with a list of all newsgroups
// clang-format on

/**
 * execute_commands - Execute a set of NeoMutt commands
 * @param p List of command strings
 * @retval  0 Success, all the commands succeeded
 * @retval -1 Error
 */
static int execute_commands(struct ListHead *p)
{
  int rc = 0;
  struct Buffer *err = buf_pool_get();

  struct ListNode *np = NULL;
  STAILQ_FOREACH(np, p, entries)
  {
    enum CommandResult rc2 = parse_rc_line(np->data, err);
    if (rc2 == MUTT_CMD_ERROR)
      mutt_error(_("Error in command line: %s"), buf_string(err));
    else if (rc2 == MUTT_CMD_WARNING)
      mutt_warning(_("Warning in command line: %s"), buf_string(err));

    if ((rc2 == MUTT_CMD_ERROR) || (rc2 == MUTT_CMD_WARNING))
    {
      buf_pool_release(&err);
      return -1;
    }
  }
  buf_pool_release(&err);

  return rc;
}

/**
 * find_cfg - Find a config file
 * @param home         User's home directory
 * @param xdg_cfg_home XDG home directory
 * @retval ptr  Success, first matching directory
 * @retval NULL Error, no matching directories
 */
static char *find_cfg(const char *home, const char *xdg_cfg_home)
{
  const char *names[] = {
    "neomuttrc",
    "muttrc",
    NULL,
  };

  const char *locations[][2] = {
    { xdg_cfg_home, "neomutt/" },
    { xdg_cfg_home, "mutt/" },
    { home, ".neomutt/" },
    { home, ".mutt/" },
    { home, "." },
    { NULL, NULL },
  };

  for (int i = 0; locations[i][0] || locations[i][1]; i++)
  {
    if (!locations[i][0])
      continue;

    for (int j = 0; names[j]; j++)
    {
      char buf[256] = { 0 };

      snprintf(buf, sizeof(buf), "%s/%s%s", locations[i][0], locations[i][1], names[j]);
      if (access(buf, F_OK) == 0)
        return mutt_str_dup(buf);
    }
  }

  return NULL;
}

#ifndef DOMAIN
/**
 * getmailname - Try to retrieve the FQDN from mailname files
 * @retval ptr Heap allocated string with the FQDN
 * @retval NULL No valid mailname file could be read
 */
static char *getmailname(void)
{
  char *mailname = NULL;
  static const char *mn_files[] = { "/etc/mailname", "/etc/mail/mailname" };

  for (size_t i = 0; i < mutt_array_size(mn_files); i++)
  {
    FILE *fp = mutt_file_fopen(mn_files[i], "r");
    if (!fp)
      continue;

    size_t len = 0;
    mailname = mutt_file_read_line(NULL, &len, fp, NULL, MUTT_RL_NO_FLAGS);
    mutt_file_fclose(&fp);
    if (mailname && *mailname)
      break;

    FREE(&mailname);
  }

  return mailname;
}
#endif

/**
 * get_hostname - Find the Fully-Qualified Domain Name
 * @param cs Config Set
 * @retval true  Success
 * @retval false Error, failed to find any name
 *
 * Use several methods to try to find the Fully-Qualified domain name of this host.
 * If the user has already configured a hostname, this function will use it.
 */
static bool get_hostname(struct ConfigSet *cs)
{
  const char *short_host = NULL;
  struct utsname utsname = { 0 };

  const char *const c_hostname = cs_subset_string(NeoMutt->sub, "hostname");
  if (c_hostname)
  {
    short_host = c_hostname;
  }
  else
  {
    /* The call to uname() shouldn't fail, but if it does, the system is horribly
     * broken, and the system's networking configuration is in an unreliable
     * state.  We should bail.  */
    if ((uname(&utsname)) == -1)
    {
      mutt_perror(_("unable to determine nodename via uname()"));
      return false; // TEST09: can't test
    }

    short_host = utsname.nodename;
  }

  /* some systems report the FQDN instead of just the hostname */
  char *dot = strchr(short_host, '.');
  if (dot)
    ShortHostname = mutt_strn_dup(short_host, dot - short_host);
  else
    ShortHostname = mutt_str_dup(short_host);

  // All the code paths from here alloc memory for the fqdn
  char *fqdn = mutt_str_dup(c_hostname);
  if (!fqdn)
  {
    mutt_debug(LL_DEBUG1, "Setting $hostname\n");
    /* now get FQDN.  Use configured domain first, DNS next, then uname */
#ifdef DOMAIN
    /* we have a compile-time domain name, use that for `$hostname` */
    mutt_str_asprintf(&fqdn, "%s.%s", NONULL(ShortHostname), DOMAIN);
#else
    fqdn = getmailname();
    if (!fqdn)
    {
      struct Buffer *domain = buf_pool_get();
      if (getdnsdomainname(domain) == 0)
      {
        mutt_str_asprintf(&fqdn, "%s.%s", NONULL(ShortHostname), buf_string(domain));
      }
      else
      {
        /* DNS failed, use the nodename.  Whether or not the nodename had a '.'
         * in it, we can use the nodename as the FQDN.  On hosts where DNS is
         * not being used, e.g. small network that relies on hosts files, a
         * short host name is all that is required for SMTP to work correctly.
         * It could be wrong, but we've done the best we can, at this point the
         * onus is on the user to provide the correct hostname if the nodename
         * won't work in their network.  */
        fqdn = mutt_str_dup(utsname.nodename);
      }
      buf_pool_release(&domain);
      mutt_debug(LL_DEBUG1, "Hostname: %s\n", NONULL(fqdn));
    }
#endif
  }

  if (fqdn)
  {
    config_str_set_initial(cs, "hostname", fqdn);
    FREE(&fqdn);
  }

  return true;
}

/**
 * mutt_init - Initialise NeoMutt
 * @param cs          Config Set
 * @param dlevel      Command line debug level
 * @param dfile       Command line debug file
 * @param skip_sys_rc If true, don't read the system config file
 * @param commands    List of config commands to execute
 * @retval 0 Success
 * @retval 1 Error
 */
static int mutt_init(struct ConfigSet *cs, const char *dlevel, const char *dfile,
                     bool skip_sys_rc, struct ListHead *commands)
{
  bool need_pause = false;
  int rc = 1;
  struct Buffer *err = buf_pool_get();
  struct Buffer *buf = buf_pool_get();

#ifdef NEOMUTT_DIRECT_COLORS
  /* Test if we run in a terminal which supports direct colours.
   *
   * The user/terminal can indicate their capability independent of the
   * terminfo file by setting the COLORTERM environment variable to "truecolor"
   * or "24bit" (case sensitive).
   *
   * Note: This is to test is less about whether the terminal understands
   * direct color commands but more about whether ncurses believes it can send
   * them to the terminal, e.g. ncurses ignores COLORTERM.
   */
  if (COLORS == 16777216) // 2^24
  {
    /* Ncurses believes the Terminal supports it check the environment variable
     * to respect the user's choice */
    const char *env_colorterm = mutt_str_getenv("COLORTERM");
    if (env_colorterm && (mutt_str_equal(env_colorterm, "truecolor") ||
                          mutt_str_equal(env_colorterm, "24bit")))
    {
      config_str_set_initial(cs, "color_directcolor", "yes");
    }
  }
#endif

  /* "$spool_file" precedence: config file, environment */
  const char *p = mutt_str_getenv("MAIL");
  if (!p)
    p = mutt_str_getenv("MAILDIR");
  if (!p)
  {
#ifdef HOMESPOOL
    buf_concat_path(buf, NONULL(HomeDir), MAILPATH);
#else
    buf_concat_path(buf, MAILPATH, NONULL(Username));
#endif
    p = buf_string(buf);
  }
  config_str_set_initial(cs, "spool_file", p);

  p = mutt_str_getenv("REPLYTO");
  if (p)
  {
    struct Buffer *token = buf_pool_get();

    buf_printf(buf, "Reply-To: %s", p);
    buf_seek(buf, 0);
    parse_my_hdr(token, buf, 0, err); /* adds to UserHeader */
    buf_pool_release(&token);
  }

  p = mutt_str_getenv("EMAIL");
  if (p)
    config_str_set_initial(cs, "from", p);

  /* "$mailcap_path" precedence: config file, environment, code */
  struct Buffer *mc = buf_pool_get();
  struct Slist *sl_mc = NULL;
  const char *env_mc = mutt_str_getenv("MAILCAPS");
  if (env_mc)
  {
    sl_mc = slist_parse(env_mc, D_SLIST_SEP_COLON);
  }
  else
  {
    cs_str_initial_get(cs, "mailcap_path", mc);
    sl_mc = slist_parse(buf_string(mc), D_SLIST_SEP_COLON);
    buf_reset(mc);
  }
  slist_to_buffer(sl_mc, mc);
  config_str_set_initial(cs, "mailcap_path", buf_string(mc));
  slist_free(&sl_mc);
  buf_pool_release(&mc);

  /* "$tmp_dir" precedence: config file, environment, code */
  const char *env_tmp = mutt_str_getenv("TMPDIR");
  if (env_tmp)
    config_str_set_initial(cs, "tmp_dir", env_tmp);

  /* "$visual", "$editor" precedence: config file, environment, code */
  const char *env_ed = mutt_str_getenv("VISUAL");
  if (!env_ed)
    env_ed = mutt_str_getenv("EDITOR");
  if (!env_ed)
    env_ed = "vi";
  config_str_set_initial(cs, "editor", env_ed);

  const char *charset = mutt_ch_get_langinfo_charset();
  config_str_set_initial(cs, "charset", charset);
  mutt_ch_set_charset(charset);
  FREE(&charset);

  char name[256] = { 0 };
  const char *c_real_name = cs_subset_string(NeoMutt->sub, "real_name");
  if (!c_real_name)
  {
    struct passwd *pw = getpwuid(getuid());
    if (pw)
    {
      c_real_name = mutt_gecos_name(name, sizeof(name), pw);
    }
  }
  config_str_set_initial(cs, "real_name", c_real_name);

#ifdef HAVE_GETSID
  /* Unset suspend by default if we're the session leader */
  if (getsid(0) == getpid())
    config_str_set_initial(cs, "suspend", "no");
#endif

  /* RFC2368, "4. Unsafe headers"
   * The creator of a mailto URL can't expect the resolver of a URL to
   * understand more than the "subject" and "body" headers. Clients that
   * resolve mailto URLs into mail messages should be able to correctly
   * create RFC822-compliant mail messages using the "subject" and "body"
   * headers.  */
  add_to_stailq(&MailToAllow, "body");
  add_to_stailq(&MailToAllow, "subject");
  /* Cc, In-Reply-To, and References help with not breaking threading on
   * mailing lists, see https://github.com/neomutt/neomutt/issues/115 */
  add_to_stailq(&MailToAllow, "cc");
  add_to_stailq(&MailToAllow, "in-reply-to");
  add_to_stailq(&MailToAllow, "references");

  if (STAILQ_EMPTY(&Muttrc))
  {
    const char *xdg_cfg_home = mutt_str_getenv("XDG_CONFIG_HOME");

    if (!xdg_cfg_home && HomeDir)
    {
      buf_printf(buf, "%s/.config", HomeDir);
      xdg_cfg_home = buf_string(buf);
    }

    char *config = find_cfg(HomeDir, xdg_cfg_home);
    if (config)
    {
      mutt_list_insert_tail(&Muttrc, config);
    }
  }
  else
  {
    struct ListNode *np = NULL;
    STAILQ_FOREACH(np, &Muttrc, entries)
    {
      buf_strcpy(buf, np->data);
      FREE(&np->data);
      buf_expand_path(buf);
      np->data = buf_strdup(buf);
      if (access(np->data, F_OK))
      {
        mutt_perror("%s", np->data);
        goto done; // TEST10: neomutt -F missing
      }
    }
  }

  struct ListNode *np = NULL;
  STAILQ_FOREACH(np, &Muttrc, entries)
  {
    if (np->data && !mutt_str_equal(np->data, "/dev/null"))
    {
      cs_str_string_set(cs, "alias_file", np->data, NULL);
      break;
    }
  }

  /* Process the global rc file if it exists and the user hasn't explicitly
   * requested not to via "-n".  */
  if (!skip_sys_rc)
  {
    do
    {
      if (mutt_set_xdg_path(XDG_CONFIG_DIRS, buf))
        break;

      buf_printf(buf, "%s/neomuttrc", SYSCONFDIR);
      if (access(buf_string(buf), F_OK) == 0)
        break;

      buf_printf(buf, "%s/Muttrc", SYSCONFDIR);
      if (access(buf_string(buf), F_OK) == 0)
        break;

      buf_printf(buf, "%s/neomuttrc", PKGDATADIR);
      if (access(buf_string(buf), F_OK) == 0)
        break;

      buf_printf(buf, "%s/Muttrc", PKGDATADIR);
    } while (false);

    if (access(buf_string(buf), F_OK) == 0)
    {
      if (source_rc(buf_string(buf), err) != 0)
      {
        mutt_error("%s", buf_string(err));
        need_pause = true; // TEST11: neomutt (error in /etc/neomuttrc)
      }
    }
  }

  /* Read the user's initialization file.  */
  STAILQ_FOREACH(np, &Muttrc, entries)
  {
    if (np->data)
    {
      if (source_rc(np->data, err) != 0)
      {
        mutt_error("%s", buf_string(err));
        need_pause = true; // TEST12: neomutt (error in ~/.neomuttrc)
      }
    }
  }

  if (execute_commands(commands) != 0)
    need_pause = true; // TEST13: neomutt -e broken

  if (!get_hostname(cs))
    goto done;

  /* The command line overrides the config */
  if (dlevel)
    cs_str_reset(cs, "debug_level", NULL);
  if (dfile)
    cs_str_reset(cs, "debug_file", NULL);

  if (mutt_log_start() < 0)
  {
    mutt_perror("log file");
    goto done;
  }

  if (need_pause && !OptNoCurses)
  {
    log_queue_flush(log_disp_terminal);
    if (mutt_any_key_to_continue(NULL) == 'q')
      goto done; // TEST14: neomutt -e broken (press 'q')
  }

  const char *const c_tmp_dir = cs_subset_path(NeoMutt->sub, "tmp_dir");
  if (mutt_file_mkdir(c_tmp_dir, S_IRWXU) < 0)
  {
    mutt_error(_("Can't create %s: %s"), c_tmp_dir, strerror(errno));
    goto done;
  }

  rc = 0;

done:
  buf_pool_release(&err);
  buf_pool_release(&buf);
  return rc;
}

/**
 * get_elem_queries - Lookup the HashElems for a set of queries
 * @param[in]  queries List of query strings
 * @param[out] hea     Array for Config HashElems
 * @retval 0 Success, all queries exist
 * @retval 1 Error
 */
static int get_elem_queries(struct ListHead *queries, struct HashElemArray *hea)
{
  int rc = 0;
  struct ListNode *np = NULL;
  STAILQ_FOREACH(np, queries, entries)
  {
    struct HashElem *he = cs_subset_lookup(NeoMutt->sub, np->data);
    if (!he)
    {
      mutt_warning(_("Unknown option %s"), np->data);
      rc = 1;
      continue;
    }

    if (he->type & D_INTERNAL_DEPRECATED)
    {
      mutt_warning(_("Option %s is deprecated"), np->data);
      rc = 1;
      continue;
    }

    ARRAY_ADD(hea, he);
  }

  return rc; // TEST16: neomutt -Q charset
}

/**
 * reset_tilde - Temporary measure
 * @param cs Config Set
 */
static void reset_tilde(struct ConfigSet *cs)
{
  static const char *names[] = { "folder", "mbox", "postponed", "record" };

  struct Buffer *value = buf_pool_get();
  for (size_t i = 0; i < mutt_array_size(names); i++)
  {
    struct HashElem *he = cs_get_elem(cs, names[i]);
    if (!he)
      continue;
    buf_reset(value);
    cs_he_initial_get(cs, he, value);
    buf_expand_path_regex(value, false);
    config_he_set_initial(cs, he, value->data);
  }
  buf_pool_release(&value);
}

#ifdef ENABLE_NLS
/**
 * localise_config - Localise some config
 * @param cs Config Set
 */
static void localise_config(struct ConfigSet *cs)
{
  static const char *names[] = {
    "attribution_intro",
    "compose_format",
    "forward_attribution_intro",
    "forward_attribution_trailer",
    "reply_regex",
    "status_format",
    "ts_icon_format",
    "ts_status_format",
  };

  struct Buffer *value = buf_pool_get();
  for (size_t i = 0; i < mutt_array_size(names); i++)
  {
    struct HashElem *he = cs_get_elem(cs, names[i]);
    if (!he)
      continue;
    buf_reset(value);
    cs_he_initial_get(cs, he, value);

    // Lookup the translation
    const char *l10n = gettext(buf_string(value));
    config_he_set_initial(cs, he, l10n);
  }
  buf_pool_release(&value);
}
#endif

/**
 * usage - Display NeoMutt command line
 * @retval true Text displayed
 */
static bool usage(void)
{
  puts(mutt_make_version());

  // clang-format off
  /* L10N: Try to limit to 80 columns */
  puts(_("usage:"));
  puts(_("  neomutt [-CEn] [-e <command>] [-F <config>] [-H <draft>] [-i <include>]\n"
         "          [-b <address>] [-c <address>] [-s <subject>] [-a <file> [...] --]\n"
         "          <address> [...]"));
  puts(_("  neomutt [-Cn] [-e <command>] [-F <config>] [-b <address>] [-c <address>]\n"
         "          [-s <subject>] [-a <file> [...] --] <address> [...] < message"));
  puts(_("  neomutt [-nRy] [-e <command>] [-F <config>] [-f <mailbox>] [-m <type>]"));
  puts(_("  neomutt [-n] [-e <command>] [-F <config>] -A <alias>"));
  puts(_("  neomutt [-n] [-e <command>] [-F <config>] -B"));
  puts(_("  neomutt [-n] [-e <command>] [-F <config>] -D [-D] [-O] [-S]"));
  puts(_("  neomutt [-n] [-e <command>] [-F <config>] -d <level> -l <file>"));
  puts(_("  neomutt [-n] [-e <command>] [-F <config>] -G"));
  puts(_("  neomutt [-n] [-e <command>] [-F <config>] -g <server>"));
  puts(_("  neomutt [-n] [-e <command>] [-F <config>] -p"));
  puts(_("  neomutt [-n] [-e <command>] [-F <config>] -Q <variable> [-O]"));
  puts(_("  neomutt [-n] [-e <command>] [-F <config>] -Z"));
  puts(_("  neomutt [-n] [-e <command>] [-F <config>] -z [-f <mailbox>]"));
  puts(_("  neomutt -v[v]\n"));

  /* L10N: Try to limit to 80 columns.  If more space is needed add an indented line */
  puts(_("options:"));
  puts(_("  --            Special argument forces NeoMutt to stop option parsing and treat\n"
         "                remaining arguments as addresses even if they start with a dash"));
  puts(_("  -A <alias>    Print an expanded version of the given alias to stdout and exit"));
  puts(_("  -a <file>     Attach one or more files to a message (must be the last option)\n"
         "                Add any addresses after the '--' argument"));
  puts(_("  -B            Run in batch mode (do not start the ncurses UI)"));
  puts(_("  -b <address>  Specify a blind carbon copy (Bcc) recipient"));
  puts(_("  -c <address>  Specify a carbon copy (Cc) recipient"));
  puts(_("  -C            Enable Command-line Crypto (signing/encryption)"));
  puts(_("  -D            Dump all config variables as 'name=value' pairs to stdout"));
  puts(_("  -D -D         (or -DD) Like -D, but only show changed config"));
  puts(_("  -D -O         Like -D, but show one-liner documentation"));
  puts(_("  -D -S         Like -D, but hide the value of sensitive variables"));
  puts(_("  -d <level>    Log debugging output to a file (default is \"~/.neomuttdebug0\")\n"
         "                The level can range from 1-5 and affects verbosity"));
  puts(_("  -E            Edit draft (-H) or include (-i) file during message composition"));
  puts(_("  -e <command>  Specify a command to be run after reading the config files"));
  puts(_("  -F <config>   Specify an alternative initialization file to read"));
  puts(_("  -f <mailbox>  Specify a mailbox (as defined with 'mailboxes' command) to load"));
  puts(_("  -G            Start NeoMutt with a listing of subscribed newsgroups"));
  puts(_("  -g <server>   Like -G, but start at specified news server"));
  puts(_("  -H <draft>    Specify a draft file with header and body for message composing"));
  puts(_("  -h            Print this help message and exit"));
  puts(_("  -i <include>  Specify an include file to be embedded in the body of a message"));
  puts(_("  -l <file>     Specify a file for debugging output (default \"~/.neomuttdebug0\")"));
  puts(_("  -m <type>     Specify a default mailbox format type for newly created folders\n"
         "                The type is either MH, MMDF, Maildir or mbox (case-insensitive)"));
  puts(_("  -n            Do not read the system-wide configuration file"));
  puts(_("  -p            Resume a prior postponed message, if any"));
  puts(_("  -Q <variable> Query a configuration variable and print its value to stdout\n"
         "                (after the config has been read and any commands executed)\n"
         "                Add -O for one-liner documentation"));
  puts(_("  -R            Open mailbox in read-only mode"));
  puts(_("  -s <subject>  Specify a subject (must be enclosed in quotes if it has spaces)"));
  puts(_("  -v            Print the NeoMutt version and compile-time definitions and exit"));
  puts(_("  -vv           Print the NeoMutt license and copyright information and exit"));
  puts(_("  -y            Start NeoMutt with a listing of all defined mailboxes"));
  puts(_("  -Z            Open the first mailbox with new message or exit immediately with\n"
         "                exit code 1 if none is found in all defined mailboxes"));
  puts(_("  -z            Open the first or specified (-f) mailbox if it holds any message\n"
         "                or exit immediately with exit code 1 otherwise"));
  // clang-format on

  fflush(stdout);
  return !ferror(stdout);
}

/**
 * start_curses - Start the Curses UI
 * @retval 0 Success
 * @retval 1 Failure
 */
static int start_curses(void)
{
  km_init(); /* must come before mutt_init */

  /* should come before initscr() so that ncurses 4.2 doesn't try to install
   * its own SIGWINCH handler */
  mutt_signal_init();

  if (!initscr())
  {
    mutt_error(_("Error initializing terminal"));
    return 1;
  }

  colors_init();
  keypad(stdscr, true);
  cbreak();
  noecho();
  nonl();
  typeahead(-1); /* simulate smooth scrolling */
  meta(stdscr, true);
  init_extended_keys();
  /* Now that curses is set up, we drop back to normal screen mode.
   * This simplifies displaying error messages to the user.
   * The first call to refresh() will swap us back to curses screen mode. */
  endwin();
  return 0;
}

/**
 * init_locale - Initialise the Locale/NLS settings
 */
static void init_locale(void)
{
  setlocale(LC_ALL, "");

#ifdef ENABLE_NLS
  const char *domdir = mutt_str_getenv("TEXTDOMAINDIR");
  if (domdir)
    bindtextdomain(PACKAGE, domdir);
  else
    bindtextdomain(PACKAGE, MUTTLOCALEDIR);
  textdomain(PACKAGE);
#endif
#ifndef LOCALES_HACK
  /* Do we have a locale definition? */
  if (mutt_str_getenv("LC_ALL") || mutt_str_getenv("LANG") || mutt_str_getenv("LC_CTYPE"))
  {
    OptLocales = true;
  }
#endif
}

/**
 * get_user_info - Find the user's name, home and shell
 * @param cs Config Set
 * @retval true Success
 *
 * Find the login name, real name, home directory and shell.
 */
static bool get_user_info(struct ConfigSet *cs)
{
  const char *shell = mutt_str_getenv("SHELL");

  /* Get some information about the user */
  struct passwd *pw = getpwuid(getuid());
  if (pw)
  {
    if (!Username)
      Username = mutt_str_dup(pw->pw_name);
    if (!HomeDir)
      HomeDir = mutt_str_dup(pw->pw_dir);
    if (!shell)
      shell = pw->pw_shell;
  }

  if (!Username)
  {
    mutt_error(_("unable to determine username"));
    return false; // TEST05: neomutt (unset $USER, delete user from /etc/passwd)
  }

  if (!HomeDir)
  {
    mutt_error(_("unable to determine home directory"));
    return false; // TEST06: neomutt (unset $HOME, delete user from /etc/passwd)
  }

  if (shell)
    config_str_set_initial(cs, "shell", shell);

  return true;
}

/**
 * log_translation - Log the translation being used
 *
 * Read the header info from the translation file.
 *
 * @note Call bindtextdomain() first
 */
static void log_translation(void)
{
  const char *header = ""; // Do not merge these two lines
  header = _(header);      // otherwise the .po files will end up badly ordered
  const char *label = "Language:"; // the start of the lookup/needle
  const char *lang = mutt_istr_find(header, label);
  int len = 64;
  if (lang)
  {
    lang += strlen(label); // skip label
    SKIPWS(lang);
    char *nl = strchr(lang, '\n');
    if (nl)
      len = (nl - lang);
  }
  else
  {
    lang = "NONE";
  }

  mutt_debug(LL_DEBUG1, "Translation: %.*s\n", len, lang);
}

/**
 * log_gui - Log info about the GUI
 */
static void log_gui(void)
{
  const char *term = mutt_str_getenv("TERM");
  const char *color_term = mutt_str_getenv("COLORTERM");
  bool true_color = false;
#ifdef NEOMUTT_DIRECT_COLORS
  true_color = true;
#endif

  mutt_debug(LL_DEBUG1, "GUI:\n");
  mutt_debug(LL_DEBUG1, "    Curses: %s\n", curses_version());
  mutt_debug(LL_DEBUG1, "    COLORS=%d\n", COLORS);
  mutt_debug(LL_DEBUG1, "    COLOR_PAIRS=%d\n", COLOR_PAIRS);
  mutt_debug(LL_DEBUG1, "    TERM=%s\n", NONULL(term));
  mutt_debug(LL_DEBUG1, "    COLORTERM=%s\n", NONULL(color_term));
  mutt_debug(LL_DEBUG1, "    True color support: %s\n", true_color ? "YES" : "NO");
  mutt_debug(LL_DEBUG1, "    Screen: %dx%d\n", RootWindow->state.cols,
             RootWindow->state.rows);
}

/**
 * main_timeout_observer - Notification that a timeout has occurred - Implements ::observer_t - @ingroup observer_api
 */
static int main_timeout_observer(struct NotifyCallback *nc)
{
  static time_t last_run = 0;

  if (nc->event_type != NT_TIMEOUT)
    return 0;

  const short c_timeout = cs_subset_number(NeoMutt->sub, "timeout");
  if (c_timeout <= 0)
    goto done;

  time_t now = mutt_date_now();
  if (now < (last_run + c_timeout))
    goto done;

  // Limit hook to running under the Index or Pager
  struct MuttWindow *focus = window_get_focus();
  struct MuttWindow *dlg = dialog_find(focus);
  if (!dlg || (dlg->type != WT_DLG_INDEX))
    goto done;

  last_run = now;
  mutt_timeout_hook();

done:
  mutt_debug(LL_DEBUG5, "timeout done\n");
  return 0;
}

/**
 * main - Start NeoMutt
 * @param argc Number of command line arguments
 * @param argv List of command line arguments
 * @param envp Copy of the environment
 * @retval 0 Success
 * @retval 1 Error
 */
int
#ifdef ENABLE_FUZZ_TESTS
disabled_main
#else
main
#endif
(int argc, char *argv[], char *envp[])
{
  char *subject = NULL;
  char *include_file = NULL;
  char *draft_file = NULL;
  char *new_type = NULL;
  char *dlevel = NULL;
  char *dfile = NULL;
  const char *cli_nntp = NULL;
  struct Email *e = NULL;
  struct ListHead attach = STAILQ_HEAD_INITIALIZER(attach);
  struct ListHead commands = STAILQ_HEAD_INITIALIZER(commands);
  struct ListHead queries = STAILQ_HEAD_INITIALIZER(queries);
  struct ListHead alias_queries = STAILQ_HEAD_INITIALIZER(alias_queries);
  struct ListHead cc_list = STAILQ_HEAD_INITIALIZER(cc_list);
  struct ListHead bcc_list = STAILQ_HEAD_INITIALIZER(bcc_list);
  SendFlags sendflags = SEND_NO_FLAGS;
  CliFlags flags = MUTT_CLI_NO_FLAGS;
  int version = 0;
  int i;
  bool explicit_folder = false;
  bool dump_variables = false;
  bool dump_changed = false;
  bool one_liner = false;
  bool hide_sensitive = false;
  bool batch_mode = false;
  bool edit_infile = false;
  int double_dash = argc, nargc = 1;
  int rc = 1;
  bool repeat_error = false;
  struct Buffer *folder = buf_pool_get();
  struct Buffer *expanded_infile = buf_pool_get();
  struct Buffer *tempfile = buf_pool_get();
  struct ConfigSet *cs = NULL;

  MuttLogger = log_disp_terminal;

  /* sanity check against stupid administrators */
  if (getegid() != getgid())
  {
    mutt_error("%s: I don't want to run with privileges!", (argc != 0) ? argv[0] : "neomutt");
    goto main_exit; // TEST01: neomutt (as root, chgrp mail neomutt; chmod +s neomutt)
  }

  init_locale();

  EnvList = envlist_init(envp);
  for (optind = 1; optind < double_dash;)
  {
    /* We're getopt'ing POSIXLY, so we'll be here every time getopt()
     * encounters a non-option.  That could be a file to attach
     * (all non-options between -a and --) or it could be an address
     * (which gets collapsed to the front of argv).  */
    for (; optind < argc; optind++)
    {
      if ((argv[optind][0] == '-') && (argv[optind][1] != '\0'))
      {
        if ((argv[optind][1] == '-') && (argv[optind][2] == '\0'))
          double_dash = optind; /* quit outer loop after getopt */
        break;                  /* drop through to getopt */
      }

      /* non-option, either an attachment or address */
      if (!STAILQ_EMPTY(&attach))
        mutt_list_insert_tail(&attach, mutt_str_dup(argv[optind]));
      else
        argv[nargc++] = argv[optind];
    }

    i = getopt(argc, argv, "+A:a:Bb:F:f:Cc:Dd:l:Ee:g:GH:i:hm:nOpQ:RSs:TvyzZ");
    if (i != EOF)
    {
      switch (i)
      {
        case 'A':
          mutt_list_insert_tail(&alias_queries, mutt_str_dup(optarg));
          break;
        case 'a':
          mutt_list_insert_tail(&attach, mutt_str_dup(optarg));
          break;
        case 'B':
          batch_mode = true;
          break;
        case 'b':
          mutt_list_insert_tail(&bcc_list, mutt_str_dup(optarg));
          break;
        case 'C':
          sendflags |= SEND_CLI_CRYPTO;
          break;
        case 'c':
          mutt_list_insert_tail(&cc_list, mutt_str_dup(optarg));
          break;
        case 'D':
          if (dump_variables)
            dump_changed = true;
          else
            dump_variables = true;
          break;
        case 'd':
          dlevel = optarg;
          break;
        case 'E':
          edit_infile = true;
          break;
        case 'e':
          mutt_list_insert_tail(&commands, mutt_str_dup(optarg));
          break;
        case 'F':
          mutt_list_insert_tail(&Muttrc, mutt_str_dup(optarg));
          break;
        case 'f':
          buf_strcpy(folder, optarg);
          explicit_folder = true;
          break;
        case 'g': /* Specify a news server */
          cli_nntp = optarg;
          FALLTHROUGH;

        case 'G': /* List of newsgroups */
          flags |= MUTT_CLI_SELECT | MUTT_CLI_NEWS;
          break;
        case 'H':
          draft_file = optarg;
          break;
        case 'i':
          include_file = optarg;
          break;
        case 'l':
          dfile = optarg;
          break;
        case 'm':
          new_type = optarg;
          break;
        case 'n':
          flags |= MUTT_CLI_NOSYSRC;
          break;
        case 'O':
          one_liner = true;
          break;
        case 'p':
          sendflags |= SEND_POSTPONED;
          break;
        case 'Q':
          mutt_list_insert_tail(&queries, mutt_str_dup(optarg));
          break;
        case 'R':
          flags |= MUTT_CLI_RO; /* read-only mode */
          break;
        case 'S':
          hide_sensitive = true;
          break;
        case 's':
          subject = optarg;
          break;
        case 'v':
          version++;
          break;
        case 'y': /* My special hack mode */
          flags |= MUTT_CLI_SELECT;
          break;
        case 'Z':
          flags |= MUTT_CLI_MAILBOX | MUTT_CLI_IGNORE;
          break;
        case 'z':
          flags |= MUTT_CLI_IGNORE;
          break;
        default:
          OptNoCurses = true;
          if (usage())
            goto main_ok; // TEST03: neomutt -9
          else
            goto main_curses;
      }
    }
  }

  /* collapse remaining argv */
  while (optind < argc)
    argv[nargc++] = argv[optind++];
  optind = 1;
  argc = nargc;

  if (version > 0)
  {
    log_queue_flush(log_disp_terminal);
    bool done;
    if (version == 1)
      done = print_version(stdout);
    else
      done = print_copyright();
    OptNoCurses = true;
    if (done)
      goto main_ok; // TEST04: neomutt -v
    else
      goto main_curses;
  }

  mutt_str_replace(&Username, mutt_str_getenv("USER"));
  mutt_str_replace(&HomeDir, mutt_str_getenv("HOME"));

  cs = cs_new(500);
  if (!cs)
    goto main_curses;

  NeoMutt = neomutt_new(cs);
  init_config(cs);

  // Change the current umask, and save the original one
  NeoMutt->user_default_umask = umask(077);
  subjrx_init();
  attach_init();
  alternates_init();

#ifdef USE_DEBUG_NOTIFY
  notify_observer_add(NeoMutt->notify, NT_ALL, debug_all_observer, NULL);
#endif

  if (!get_user_info(cs))
    goto main_exit;

  reset_tilde(cs);
#ifdef ENABLE_NLS
  localise_config(cs);
#endif

  if (dfile)
    config_str_set_initial(cs, "debug_file", dfile);

  if (dlevel)
  {
    short num = 0;
    if (!mutt_str_atos_full(dlevel, &num) || (num < LL_MESSAGE) || (num >= LL_MAX))
    {
      mutt_error(_("Error: value '%s' is invalid for -d"), dlevel);
      goto main_exit; // TEST07: neomutt -d xyz
    }

    config_str_set_initial(cs, "debug_level", dlevel);
  }

  mutt_log_prep();
  MuttLogger = log_disp_queue;
  log_translation();
  mutt_debug(LL_DEBUG1, "user's umask %03o\n", NeoMutt->user_default_umask);
  mutt_debug(LL_DEBUG3, "umask set to 077\n");

  if (!STAILQ_EMPTY(&cc_list) || !STAILQ_EMPTY(&bcc_list))
  {
    e = email_new();
    e->env = mutt_env_new();

    struct ListNode *np = NULL;
    STAILQ_FOREACH(np, &bcc_list, entries)
    {
      mutt_addrlist_parse(&e->env->bcc, np->data);
    }

    STAILQ_FOREACH(np, &cc_list, entries)
    {
      mutt_addrlist_parse(&e->env->cc, np->data);
    }

    mutt_list_free(&bcc_list);
    mutt_list_free(&cc_list);
  }

  /* Check for a batch send. */
  if (!isatty(0) || !STAILQ_EMPTY(&queries) || !STAILQ_EMPTY(&alias_queries) ||
      dump_variables || batch_mode)
  {
    OptNoCurses = true;
    sendflags |= SEND_BATCH;
    MuttLogger = log_disp_terminal;
    log_queue_flush(log_disp_terminal);
  }

  /* Check to make sure stdout is available in curses mode. */
  if (!OptNoCurses && !isatty(1))
    goto main_curses;

  /* This must come before mutt_init() because curses needs to be started
   * before calling the init_pair() function to set the color scheme.  */
  if (!OptNoCurses)
  {
    int crc = start_curses();
    if (crc != 0)
      goto main_curses; // TEST08: can't test -- fake term?
  }

  /* Always create the mutt_windows because batch mode has some shared code
   * paths that end up referencing them. */
  rootwin_new();

  if (!OptNoCurses)
  {
    /* check whether terminal status is supported (must follow curses init) */
    TsSupported = mutt_ts_capability();
    mutt_resize_screen();
    log_gui();
  }

  mutt_grouplist_init();
  alias_init();
  commands_init();
  hooks_init();
  mutt_comp_init();
  imap_init();
#ifdef USE_LUA
  mutt_lua_init();
#endif
  driver_tags_init();

  menu_init();
  sb_init();
#ifdef USE_NOTMUCH
  nm_init();
#endif

  /* set defaults and read init files */
  int rc2 = mutt_init(cs, dlevel, dfile, flags & MUTT_CLI_NOSYSRC, &commands);
  if (rc2 != 0)
    goto main_curses;

  mutt_hist_init();
  mutt_hist_read_file();

#ifdef USE_NOTMUCH
  const bool c_virtual_spool_file = cs_subset_bool(NeoMutt->sub, "virtual_spool_file");
  if (c_virtual_spool_file)
  {
    /* Find the first virtual folder and open it */
    struct MailboxList ml = STAILQ_HEAD_INITIALIZER(ml);
    neomutt_mailboxlist_get_all(&ml, NeoMutt, MUTT_NOTMUCH);
    struct MailboxNode *mp = STAILQ_FIRST(&ml);
    if (mp)
      cs_str_string_set(cs, "spool_file", mailbox_path(mp->mailbox), NULL);
    neomutt_mailboxlist_clear(&ml);
  }
#endif

  mutt_init_abort_key();

  /* "$news_server" precedence: command line, config file, environment, system file */
  if (!cli_nntp)
    cli_nntp = cs_subset_string(NeoMutt->sub, "news_server");

  if (!cli_nntp)
    cli_nntp = mutt_str_getenv("NNTPSERVER");

  if (!cli_nntp)
  {
    char buf[1024] = { 0 };
    cli_nntp = mutt_file_read_keyword(SYSCONFDIR "/nntpserver", buf, sizeof(buf));
  }

  if (cli_nntp)
    config_str_set_initial(cs, "news_server", cli_nntp);

  /* Initialize crypto backends.  */
  crypt_init();

  if (new_type && !config_str_set_initial(cs, "mbox_type", new_type))
    goto main_curses;

  if (dump_variables || !STAILQ_EMPTY(&queries))
  {
    const bool tty = isatty(STDOUT_FILENO);

    ConfigDumpFlags cdflags = CS_DUMP_NO_FLAGS;
    if (tty)
      cdflags |= CS_DUMP_LINK_DOCS;
    if (hide_sensitive)
      cdflags |= CS_DUMP_HIDE_SENSITIVE;
    if (one_liner)
      cdflags |= CS_DUMP_SHOW_DOCS;

    struct HashElemArray hea = ARRAY_HEAD_INITIALIZER;
    if (dump_variables)
    {
      enum GetElemListFlags gel_flags = dump_changed ? GEL_CHANGED_CONFIG : GEL_ALL_CONFIG;
      hea = get_elem_list(cs, gel_flags);
      rc = 0;
    }
    else
    {
      rc = get_elem_queries(&queries, &hea);
    }

    dump_config(cs, &hea, cdflags, stdout);
    ARRAY_FREE(&hea);
    goto main_curses;
  }

  if (!STAILQ_EMPTY(&alias_queries))
  {
    rc = 0;
    for (; optind < argc; optind++)
      mutt_list_insert_tail(&alias_queries, mutt_str_dup(argv[optind]));
    struct ListNode *np = NULL;
    STAILQ_FOREACH(np, &alias_queries, entries)
    {
      struct AddressList *al = alias_lookup(np->data);
      if (al)
      {
        /* output in machine-readable form */
        mutt_addrlist_to_intl(al, NULL);
        struct Buffer *buf = buf_pool_get();
        mutt_addrlist_write(al, buf, false);
        printf("%s\n", buf_string(buf));
        buf_pool_release(&buf);
      }
      else
      {
        rc = 1;
        printf("%s\n", NONULL(np->data)); // TEST19: neomutt -A unknown
      }
    }
    mutt_list_free(&alias_queries);
    goto main_curses; // TEST20: neomutt -A alias
  }

  if (!OptNoCurses)
  {
    mutt_curses_set_color_by_id(MT_COLOR_NORMAL);
    clear();
    MuttLogger = log_disp_curses;
    log_queue_flush(log_disp_curses);
    log_queue_set_max_size(100);
  }

#ifdef USE_AUTOCRYPT
  /* Initialize autocrypt after curses messages are working,
   * because of the initial account setup screens. */
  const bool c_autocrypt = cs_subset_bool(NeoMutt->sub, "autocrypt");
  if (c_autocrypt)
    mutt_autocrypt_init(!(sendflags & SEND_BATCH));
#endif

  /* Create the `$folder` directory if it doesn't exist. */
  const char *const c_folder = cs_subset_string(NeoMutt->sub, "folder");
  if (!OptNoCurses && c_folder)
  {
    struct stat st = { 0 };
    struct Buffer *fpath = buf_pool_get();

    buf_strcpy(fpath, c_folder);
    buf_expand_path(fpath);
    bool skip = false;
    /* we're not connected yet - skip mail folder creation */
    skip |= (imap_path_probe(buf_string(fpath), NULL) == MUTT_IMAP);
    skip |= (pop_path_probe(buf_string(fpath), NULL) == MUTT_POP);
    skip |= (nntp_path_probe(buf_string(fpath), NULL) == MUTT_NNTP);
    if (!skip && (stat(buf_string(fpath), &st) == -1) && (errno == ENOENT))
    {
      char msg2[256] = { 0 };
      snprintf(msg2, sizeof(msg2), _("%s does not exist. Create it?"), c_folder);
      if (query_yesorno(msg2, MUTT_YES) == MUTT_YES)
      {
        if ((mkdir(buf_string(fpath), 0700) == -1) && (errno != EEXIST))
          mutt_error(_("Can't create %s: %s"), c_folder, strerror(errno)); // TEST21: neomutt -n -F /dev/null (and ~/Mail doesn't exist)
      }
    }
    buf_pool_release(&fpath);
  }

  if (batch_mode)
  {
    goto main_ok; // TEST22: neomutt -B
  }
  StartupComplete = true;

  notify_observer_add(NeoMutt->sub->notify, NT_CONFIG, main_hist_observer, NULL);
  notify_observer_add(NeoMutt->sub->notify, NT_CONFIG, main_log_observer, NULL);
  notify_observer_add(NeoMutt->sub->notify, NT_CONFIG, main_config_observer, NULL);
  notify_observer_add(NeoMutt->notify, NT_TIMEOUT, main_timeout_observer, NULL);

  if (sendflags & SEND_POSTPONED)
  {
    if (!OptNoCurses)
      mutt_flushinp();
    if (mutt_send_message(SEND_POSTPONED, NULL, NULL, NULL, NULL, NeoMutt->sub) == 0)
      rc = 0;
    // TEST23: neomutt -p (postponed message, cancel)
    // TEST24: neomutt -p (no postponed message)
    log_queue_empty();
    repeat_error = true;
    goto main_curses;
  }
  else if (subject || e || draft_file || include_file ||
           !STAILQ_EMPTY(&attach) || (optind < argc))
  {
    FILE *fp_in = NULL;
    FILE *fp_out = NULL;
    char *infile = NULL;
    char *bodytext = NULL;
    const char *bodyfile = NULL;
    int rv = 0;

    if (!OptNoCurses)
      mutt_flushinp();

    if (!e)
      e = email_new();
    if (!e->env)
      e->env = mutt_env_new();

    for (i = optind; i < argc; i++)
    {
      if (url_check_scheme(argv[i]) == U_MAILTO)
      {
        if (!mutt_parse_mailto(e->env, &bodytext, argv[i]))
        {
          mutt_error(_("Failed to parse mailto: link"));
          email_free(&e);
          goto main_curses; // TEST25: neomutt mailto:?
        }
      }
      else
      {
        mutt_addrlist_parse(&e->env->to, argv[i]);
      }
    }

    const bool c_auto_edit = cs_subset_bool(NeoMutt->sub, "auto_edit");
    if (!draft_file && c_auto_edit && TAILQ_EMPTY(&e->env->to) &&
        TAILQ_EMPTY(&e->env->cc))
    {
      mutt_error(_("No recipients specified"));
      email_free(&e);
      goto main_curses; // TEST26: neomutt -s test (with auto_edit=yes)
    }

    if (subject)
    {
      /* prevent header injection */
      mutt_filter_commandline_header_value(subject);
      mutt_env_set_subject(e->env, subject);
    }

    if (draft_file)
    {
      infile = draft_file;
      include_file = NULL;
    }
    else if (include_file)
    {
      infile = include_file;
    }
    else
    {
      edit_infile = false;
    }

    if (infile || bodytext)
    {
      /* Prepare fp_in and expanded_infile. */
      if (infile)
      {
        if (mutt_str_equal("-", infile))
        {
          if (edit_infile)
          {
            mutt_error(_("Can't use -E flag with stdin"));
            email_free(&e);
            goto main_curses; // TEST27: neomutt -E -H -
          }
          fp_in = stdin;
        }
        else
        {
          buf_strcpy(expanded_infile, infile);
          buf_expand_path(expanded_infile);
          fp_in = mutt_file_fopen(buf_string(expanded_infile), "r");
          if (!fp_in)
          {
            mutt_perror("%s", buf_string(expanded_infile));
            email_free(&e);
            goto main_curses; // TEST28: neomutt -E -H missing
          }
        }
      }

      if (edit_infile)
      {
        /* If editing the infile, keep it around afterwards so
         * it doesn't get unlinked, and we can rebuild the draft_file */
        sendflags |= SEND_NO_FREE_HEADER;
      }
      else
      {
        /* Copy input to a tempfile, and re-point fp_in to the tempfile.
         * Note: stdin is always copied to a tempfile, ensuring draft_file
         * can stat and get the correct st_size below.  */
        buf_mktemp(tempfile);

        fp_out = mutt_file_fopen(buf_string(tempfile), "w");
        if (!fp_out)
        {
          mutt_file_fclose(&fp_in);
          mutt_perror("%s", buf_string(tempfile));
          email_free(&e);
          goto main_curses; // TEST29: neomutt -H existing-file (where tmpdir=/path/to/FILE blocking tmpdir)
        }
        if (fp_in)
        {
          mutt_file_copy_stream(fp_in, fp_out);
          if (fp_in == stdin)
            sendflags |= SEND_CONSUMED_STDIN;
          else
            mutt_file_fclose(&fp_in);
        }
        else if (bodytext)
        {
          fputs(bodytext, fp_out);
        }
        mutt_file_fclose(&fp_out);

        fp_in = mutt_file_fopen(buf_string(tempfile), "r");
        if (!fp_in)
        {
          mutt_perror("%s", buf_string(tempfile));
          email_free(&e);
          goto main_curses; // TEST30: can't test
        }
      }

      /* Parse the draft_file into the full Email/Body structure.
       * Set SEND_DRAFT_FILE so mutt_send_message doesn't overwrite
       * our e->body.  */
      if (draft_file)
      {
        struct Envelope *opts_env = e->env;
        struct stat st = { 0 };

        sendflags |= SEND_DRAFT_FILE;

        /* Set up a tmp Email with just enough information so that
         * mutt_prepare_template() can parse the message in fp_in.  */
        struct Email *e_tmp = email_new();
        e_tmp->offset = 0;
        e_tmp->body = mutt_body_new();
        if (fstat(fileno(fp_in), &st) != 0)
        {
          mutt_perror("%s", draft_file);
          email_free(&e);
          email_free(&e_tmp);
          goto main_curses; // TEST31: can't test
        }
        e_tmp->body->length = st.st_size;

        if (mutt_prepare_template(fp_in, NULL, e, e_tmp, false) < 0)
        {
          mutt_error(_("Can't parse message template: %s"), draft_file);
          email_free(&e);
          email_free(&e_tmp);
          goto main_curses;
        }

        /* Scan for neomutt header to set `$resume_draft_files` */
        struct ListNode *np = NULL, *tmp = NULL;
        const bool c_resume_edited_draft_files = cs_subset_bool(NeoMutt->sub, "resume_edited_draft_files");
        STAILQ_FOREACH_SAFE(np, &e->env->userhdrs, entries, tmp)
        {
          if (mutt_istr_startswith(np->data, "X-Mutt-Resume-Draft:"))
          {
            if (c_resume_edited_draft_files)
              cs_str_native_set(cs, "resume_draft_files", true, NULL);

            STAILQ_REMOVE(&e->env->userhdrs, np, ListNode, entries);
            FREE(&np->data);
            FREE(&np);
          }
        }

        mutt_addrlist_copy(&e->env->to, &opts_env->to, false);
        mutt_addrlist_copy(&e->env->cc, &opts_env->cc, false);
        mutt_addrlist_copy(&e->env->bcc, &opts_env->bcc, false);
        if (opts_env->subject)
          mutt_env_set_subject(e->env, opts_env->subject);

        mutt_env_free(&opts_env);
        email_free(&e_tmp);
      }
      /* Editing the include_file: pass it directly in.
       * Note that SEND_NO_FREE_HEADER is set above so it isn't unlinked.  */
      else if (edit_infile)
        bodyfile = buf_string(expanded_infile);
      // For bodytext and unedited include_file: use the tempfile.
      else
        bodyfile = buf_string(tempfile);

      mutt_file_fclose(&fp_in);
    }

    FREE(&bodytext);

    if (!STAILQ_EMPTY(&attach))
    {
      struct Body *b = e->body;

      while (b && b->next)
        b = b->next;

      struct ListNode *np = NULL;
      STAILQ_FOREACH(np, &attach, entries)
      {
        if (b)
        {
          b->next = mutt_make_file_attach(np->data, NeoMutt->sub);
          b = b->next;
        }
        else
        {
          b = mutt_make_file_attach(np->data, NeoMutt->sub);
          e->body = b;
        }
        if (!b)
        {
          mutt_error(_("%s: unable to attach file"), np->data);
          mutt_list_free(&attach);
          email_free(&e);
          goto main_curses; // TEST32: neomutt john@example.com -a missing
        }
      }
      mutt_list_free(&attach);
    }

    rv = mutt_send_message(sendflags, e, bodyfile, NULL, NULL, NeoMutt->sub);
    /* We WANT the "Mail sent." and any possible, later error */
    log_queue_empty();
    if (ErrorBufMessage)
      mutt_message("%s", ErrorBuf);

    if (edit_infile)
    {
      if (draft_file)
      {
        if (truncate(buf_string(expanded_infile), 0) == -1)
        {
          mutt_perror("%s", buf_string(expanded_infile));
          email_free(&e);
          goto main_curses; // TEST33: neomutt -H read-only -s test john@example.com -E
        }
        fp_out = mutt_file_fopen(buf_string(expanded_infile), "a");
        if (!fp_out)
        {
          mutt_perror("%s", buf_string(expanded_infile));
          email_free(&e);
          goto main_curses; // TEST34: can't test
        }

        /* If the message was sent or postponed, these will already
         * have been done.  */
        if (rv < 0)
        {
          if (e->body->next)
            e->body = mutt_make_multipart(e->body);
          mutt_encode_descriptions(e->body, true, NeoMutt->sub);
          mutt_prepare_envelope(e->env, false, NeoMutt->sub);
          mutt_env_to_intl(e->env, NULL, NULL);
        }

        const bool c_crypt_protected_headers_read = cs_subset_bool(NeoMutt->sub, "crypt_protected_headers_read");
        mutt_rfc822_write_header(fp_out, e->env, e->body, MUTT_WRITE_HEADER_POSTPONE, false,
                                 c_crypt_protected_headers_read &&
                                     mutt_should_hide_protected_subject(e),
                                 NeoMutt->sub);
        const bool c_resume_edited_draft_files = cs_subset_bool(NeoMutt->sub, "resume_edited_draft_files");
        if (c_resume_edited_draft_files)
          fprintf(fp_out, "X-Mutt-Resume-Draft: 1\n");
        fputc('\n', fp_out);
        if ((mutt_write_mime_body(e->body, fp_out, NeoMutt->sub) == -1))
        {
          mutt_file_fclose(&fp_out);
          email_free(&e);
          goto main_curses; // TEST35: can't test
        }
        mutt_file_fclose(&fp_out);
      }

      email_free(&e);
    }

    /* !edit_infile && draft_file will leave the tempfile around */
    if (!buf_is_empty(tempfile))
      unlink(buf_string(tempfile));

    rootwin_cleanup();

    if (rv != 0)
      goto main_curses; // TEST36: neomutt -H existing -s test john@example.com -E (cancel sending)
  }
  else if (sendflags & SEND_BATCH)
  {
    /* This guards against invoking `neomutt < /dev/null` and accidentally
     * sending an email due to a my_hdr or other setting.  */
    mutt_error(_("No recipients specified"));
    goto main_curses;
  }
  else
  {
    if (flags & MUTT_CLI_MAILBOX)
    {
      const bool c_imap_passive = cs_subset_bool(NeoMutt->sub, "imap_passive");
      cs_subset_str_native_set(NeoMutt->sub, "imap_passive", false, NULL);
      const CheckStatsFlags csflags = MUTT_MAILBOX_CHECK_IMMEDIATE;
      if (mutt_mailbox_check(NULL, csflags) == 0)
      {
        mutt_message(_("No mailbox with new mail"));
        repeat_error = true;
        goto main_curses; // TEST37: neomutt -Z (no new mail)
      }
      buf_reset(folder);
      mutt_mailbox_next(NULL, folder);
      cs_subset_str_native_set(NeoMutt->sub, "imap_passive", c_imap_passive, NULL);
    }
    else if (flags & MUTT_CLI_SELECT)
    {
      if (flags & MUTT_CLI_NEWS)
      {
        const char *const c_news_server = cs_subset_string(NeoMutt->sub, "news_server");
        OptNews = true;
        CurrentNewsSrv = nntp_select_server(NULL, c_news_server, false);
        if (!CurrentNewsSrv)
          goto main_curses; // TEST38: neomutt -G (unset news_server)
      }
      else if (TAILQ_EMPTY(&NeoMutt->accounts))
      {
        mutt_error(_("No incoming mailboxes defined"));
        goto main_curses; // TEST39: neomutt -n -F /dev/null -y
      }
      buf_reset(folder);
      dlg_browser(folder, MUTT_SEL_FOLDER | MUTT_SEL_MAILBOX, NULL, NULL, NULL);
      if (buf_is_empty(folder))
      {
        goto main_ok; // TEST40: neomutt -y (quit selection)
      }
    }

    if (buf_is_empty(folder))
    {
      const char *const c_spool_file = cs_subset_string(NeoMutt->sub, "spool_file");
      if (c_spool_file)
      {
        // Check if `$spool_file` corresponds a mailboxes' description.
        struct Mailbox *m_desc = mailbox_find_name(c_spool_file);
        if (m_desc)
          buf_strcpy(folder, m_desc->realpath);
        else
          buf_strcpy(folder, c_spool_file);
      }
      else if (c_folder)
      {
        buf_strcpy(folder, c_folder);
      }
      /* else no folder */
    }

    if (OptNews)
    {
      OptNews = false;
      buf_alloc(folder, PATH_MAX);
      nntp_expand_path(folder->data, folder->dsize, &CurrentNewsSrv->conn->account);
    }
    else
    {
      buf_expand_path(folder);
    }

    mutt_str_replace(&CurrentFolder, buf_string(folder));
    mutt_str_replace(&LastFolder, buf_string(folder));

    if (flags & MUTT_CLI_IGNORE)
    {
      /* check to see if there are any messages in the folder */
      switch (mx_path_is_empty(folder))
      {
        case -1:
          mutt_perror("%s", buf_string(folder));
          goto main_curses; // TEST41: neomutt -z -f missing
        case 1:
          mutt_error(_("Mailbox is empty"));
          goto main_curses; // TEST42: neomutt -z -f /dev/null
      }
    }

    struct Mailbox *m_cur = mailbox_find(buf_string(folder));
    // Take a copy of the name just in case the hook alters m_cur
    const char *name = m_cur ? mutt_str_dup(m_cur->name) : NULL;
    mutt_folder_hook(buf_string(folder), name);
    FREE(&name);
    mutt_startup_shutdown_hook(MUTT_STARTUP_HOOK);
    mutt_debug(LL_NOTIFY, "NT_GLOBAL_STARTUP\n");
    notify_send(NeoMutt->notify, NT_GLOBAL, NT_GLOBAL_STARTUP, NULL);

    notify_send(NeoMutt->notify_resize, NT_RESIZE, 0, NULL);
    window_redraw(NULL);

    repeat_error = true;
    struct Mailbox *m = mx_resolve(buf_string(folder));
    const bool c_read_only = cs_subset_bool(NeoMutt->sub, "read_only");
    if (!mx_mbox_open(m, ((flags & MUTT_CLI_RO) || c_read_only) ? MUTT_READONLY : MUTT_OPEN_NO_FLAGS))
    {
      if (m->account)
        account_mailbox_remove(m->account, m);

      mailbox_free(&m);
      mutt_error(_("Unable to open mailbox %s"), buf_string(folder));
      repeat_error = false;
    }
    if (m || !explicit_folder)
    {
      struct MuttWindow *dlg = index_pager_init();
      dialog_push(dlg);

      mutt_curses_set_cursor(MUTT_CURSOR_INVISIBLE);
      m = dlg_index(dlg, m);
      mutt_curses_set_cursor(MUTT_CURSOR_VISIBLE);
      mailbox_free(&m);

      dialog_pop();
      mutt_window_free(&dlg);
      log_queue_empty();
      repeat_error = false;
    }
    imap_logout_all();
#ifdef USE_SASL_CYRUS
    mutt_sasl_cleanup();
#endif
#ifdef USE_SASL_GNU
    mutt_gsasl_cleanup();
#endif
#ifdef USE_AUTOCRYPT
    mutt_autocrypt_cleanup();
#endif
    // TEST43: neomutt (no change to mailbox)
    // TEST44: neomutt (change mailbox)
  }

main_ok:
  rc = 0;
main_curses:
  mutt_endwin();
  mutt_temp_attachments_cleanup();
  /* Repeat the last message to the user */
  if (repeat_error && ErrorBufMessage)
    puts(ErrorBuf);
main_exit:
  if (NeoMutt && NeoMutt->sub)
  {
    notify_observer_remove(NeoMutt->sub->notify, main_hist_observer, NULL);
    notify_observer_remove(NeoMutt->sub->notify, main_log_observer, NULL);
    notify_observer_remove(NeoMutt->sub->notify, main_config_observer, NULL);
    notify_observer_remove(NeoMutt->notify, main_timeout_observer, NULL);
  }
  mutt_list_free(&commands);
  MuttLogger = log_disp_queue;
  buf_pool_release(&folder);
  buf_pool_release(&expanded_infile);
  buf_pool_release(&tempfile);
  mutt_list_free(&queries);
  crypto_module_cleanup();
  rootwin_cleanup();
  buf_pool_cleanup();
  envlist_free(&EnvList);
  mutt_browser_cleanup();
  external_cleanup();
  menu_cleanup();
  crypt_cleanup();
  mutt_ch_cache_cleanup();

  source_stack_cleanup();

  alias_cleanup();
  sb_cleanup();

  mutt_regexlist_free(&MailLists);
  mutt_regexlist_free(&NoSpamList);
  mutt_regexlist_free(&SubscribedLists);
  mutt_regexlist_free(&UnMailLists);
  mutt_regexlist_free(&UnSubscribedLists);

  mutt_grouplist_cleanup();
  driver_tags_cleanup();

  /* Lists of strings */
  mutt_list_free(&AlternativeOrderList);
  mutt_list_free(&AutoViewList);
  mutt_list_free(&HeaderOrderList);
  mutt_list_free(&Ignore);
  mutt_list_free(&MailToAllow);
  mutt_list_free(&MimeLookupList);
  mutt_list_free(&Muttrc);
  mutt_list_free(&UnIgnore);
  mutt_list_free(&UserHeader);

  colors_cleanup();

  FREE(&CurrentFolder);
  FREE(&HomeDir);
  FREE(&LastFolder);
  FREE(&ShortHostname);
  FREE(&Username);

  mutt_replacelist_free(&SpamList);

  mutt_delete_hooks(MUTT_HOOK_NO_FLAGS);

  mutt_hist_cleanup();
  mutt_keys_cleanup();

  mutt_regexlist_free(&NoSpamList);
  commands_cleanup();

  subjrx_cleanup();
  attach_cleanup();
  alternates_cleanup();
  mutt_keys_cleanup();
  mutt_prex_cleanup();
  config_cache_cleanup();
  neomutt_free(&NeoMutt);
  cs_free(&cs);
  log_queue_flush(log_disp_terminal);
  mutt_log_stop();
  return rc;
}
