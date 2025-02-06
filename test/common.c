/**
 * @file
 * Common code for file tests
 *
 * @authors
 * Copyright (C) 2020-2024 Richard Russon <rich@flatcap.org>
 * Copyright (C) 2023 Anna Figueiredo Gomes <navi@vlhl.dev>
 * Copyright (C) 2023 Dennis Schön <mail@dennis-schoen.de>
 * Copyright (C) 2023 Pietro Cerutti <gahr@gahr.ch>
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

#define TEST_NO_MAIN
#include "config.h"
#include "acutest.h"
#include <limits.h>
#include <locale.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include "mutt/lib.h"
#include "config/lib.h"
#include "core/lib.h"
#include "complete/lib.h"
#include "copy.h"
#include "mx.h"

struct AddressList;
struct Email;
struct Envelope;
struct MuttWindow;
struct PagerView;

bool StartupComplete = true;

char *HomeDir = NULL;
char *ShortHostname = "example";
bool MonitorContextChanged = false;

#define TEST_DIR "NEOMUTT_TEST_DIR"

const struct CompleteOps CompleteMailboxOps = { 0 };

static struct ConfigDef Vars[] = {
  // clang-format off
  { "assumed_charset", DT_SLIST|D_SLIST_SEP_COLON|D_SLIST_ALLOW_EMPTY, 0, 0, NULL, },
  { "charset", DT_STRING|D_NOT_EMPTY|D_CHARSET_SINGLE, IP "utf-8", 0, NULL, },
  { "maildir_field_delimiter", DT_STRING, IP ":", 0, NULL, },
  { "tmp_dir", DT_PATH|D_PATH_DIR|D_NOT_EMPTY, IP TMPDIR, 0, NULL, },
  { NULL },
  // clang-format on
};

#define CONFIG_INIT_TYPE(CS, NAME)                                             \
  extern const struct ConfigSetType Cst##NAME;                                 \
  cs_register_type(CS, &Cst##NAME)

const char *get_test_dir(void)
{
  return mutt_str_getenv(TEST_DIR);
}

static void init_tmp_dir(struct NeoMutt *n)
{
  char buf[PATH_MAX] = { 0 };

  snprintf(buf, sizeof(buf), "%s/tmp", mutt_str_getenv(TEST_DIR));

  struct HashElem *he = cs_get_elem(n->sub->cs, "tmp_dir");
  cs_he_initial_set(n->sub->cs, he, buf, NULL);
  cs_str_reset(n->sub->cs, "tmp_dir", NULL);
}

void test_gen_path(struct Buffer *buf, const char *fmt)
{
  buf_printf(buf, NONULL(fmt), NONULL(get_test_dir()));
}

bool test_neomutt_create(void)
{
  struct ConfigSet *cs = cs_new(50);
  CONFIG_INIT_TYPE(cs, Address);
  CONFIG_INIT_TYPE(cs, Bool);
  CONFIG_INIT_TYPE(cs, Enum);
  CONFIG_INIT_TYPE(cs, Expando);
  CONFIG_INIT_TYPE(cs, Long);
  CONFIG_INIT_TYPE(cs, Mbtable);
  CONFIG_INIT_TYPE(cs, MyVar);
  CONFIG_INIT_TYPE(cs, Number);
  CONFIG_INIT_TYPE(cs, Path);
  CONFIG_INIT_TYPE(cs, Quad);
  CONFIG_INIT_TYPE(cs, Regex);
  CONFIG_INIT_TYPE(cs, Slist);
  CONFIG_INIT_TYPE(cs, Sort);
  CONFIG_INIT_TYPE(cs, String);

  NeoMutt = neomutt_new(cs);
  TEST_CHECK(NeoMutt != NULL);

  TEST_CHECK(cs_register_variables(cs, Vars));

  init_tmp_dir(NeoMutt);

  return NeoMutt;
}

void test_neomutt_destroy(void)
{
  if (!NeoMutt)
    return;

  struct ConfigSet *cs = NeoMutt->sub->cs;
  neomutt_free(&NeoMutt);
  cs_free(&cs);
}

void test_init(void)
{
  setenv("TZ", "UTC", 1); // Default to UTC

  const char *path = get_test_dir();
  bool success = false;

  TEST_CASE("Common setup");
  if (!TEST_CHECK(path != NULL))
  {
    TEST_MSG("Environment variable '%s' isn't set", TEST_DIR);
    goto done;
  }

  size_t len = strlen(path);
  if (!TEST_CHECK(path[len - 1] != '/'))
  {
    TEST_MSG("Environment variable '%s' mustn't end with a '/'", TEST_DIR);
    goto done;
  }

  struct stat st = { 0 };

  if (!TEST_CHECK(stat(path, &st) == 0))
  {
    TEST_MSG("Test dir '%s' doesn't exist", path);
    goto done;
  }

  if (!TEST_CHECK(S_ISDIR(st.st_mode) == true))
  {
    TEST_MSG("Test dir '%s' isn't a directory", path);
    goto done;
  }

  if (!TEST_CHECK((setlocale(LC_ALL, "C.UTF-8") != NULL) ||
                  (setlocale(LC_ALL, "en_US.UTF-8") != NULL)))
  {
    TEST_MSG("Can't set locale to C.UTF-8 or en_US.UTF-8");
    goto done;
  }

  test_neomutt_create();
  success = true;
done:
  if (!success)
  {
    TEST_MSG("See: https://github.com/neomutt/neomutt-test-files#test-files");
    exit(1);
  }
}

void test_fini(void)
{
  config_cache_cleanup();
  test_neomutt_destroy();
  buf_pool_cleanup();
}

struct IndexSharedData *index_shared_data_new(void)
{
  return NULL;
}

struct MuttWindow *add_panel_pager(struct MuttWindow *parent, bool status_on_top)
{
  return NULL;
}

enum QuadOption query_yesorno(const char *msg, enum QuadOption def)
{
  return MUTT_YES;
}

struct Mailbox *get_current_mailbox(void)
{
  return NULL;
}

struct MailboxView *get_current_mailbox_view(void)
{
  return NULL;
}

struct Menu *get_current_menu(void)
{
  return NULL;
}

int mutt_do_pager(struct PagerView *pview, struct Email *e)
{
  return 0;
}

void buf_pretty_mailbox(struct Buffer *buf)
{
}

void buf_expand_path_regex(struct Buffer *buf, bool regex)
{
}

struct HashTable *mutt_make_id_hash(struct Mailbox *m)
{
  return NULL;
}

void mx_alloc_memory(struct Mailbox *m, int req_size)
{
}

struct Mailbox *mx_path_resolve(const char *path)
{
  return NULL;
}

bool mx_mbox_ac_link(struct Mailbox *m)
{
  return false;
}

void mutt_encode_path(struct Buffer *buf, const char *src)
{
}

void mutt_set_header_color(struct Mailbox *m, struct Email *e)
{
}

enum CommandResult parse_unmailboxes(struct Buffer *buf, struct Buffer *s,
                                     intptr_t data, struct Buffer *err)
{
  return MUTT_CMD_SUCCESS;
}

enum CommandResult parse_mailboxes(struct Buffer *buf, struct Buffer *s,
                                   intptr_t data, struct Buffer *err)
{
  return MUTT_CMD_SUCCESS;
}

struct Message *mx_msg_open_new(struct Mailbox *m, const struct Email *e, MsgOpenFlags flags)
{
  return NULL;
}

int mutt_copy_message(FILE *fp_out, struct Email *e, struct Message *msg,
                      CopyMessageFlags cmflags, CopyHeaderFlags chflags, int wraplen)
{
  return 0;
}

/**
 * log_disp_null - Discard log lines - Implements ::log_dispatcher_t - @ingroup logging_api
 */
int log_disp_null(time_t stamp, const char *file, int line, const char *function,
                  enum LogLevel level, const char *format, ...)
{
  return 0;
}

bool check_for_mailing_list(struct AddressList *al, const char *pfx, char *buf, int buflen)
{
  return false;
}

typedef uint8_t MuttThreadFlags;
int mutt_traverse_thread(struct Email *e, MuttThreadFlags flag)
{
  return 0;
}

int mutt_thread_style(void)
{
  return 0;
}

const char *mutt_get_name(const char *s)
{
  return NULL;
}

void subjrx_apply_mods(struct Envelope *env)
{
}

#ifdef USE_DEBUG_BACKTRACE
void show_backtrace(void)
{
}
#endif
