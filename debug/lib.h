/**
 * @file
 * Convenience wrapper for the debug headers
 *
 * @authors
 * Copyright (C) 2019-2024 Richard Russon <rich@flatcap.org>
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
 * @page lib_debug Debug Code
 *
 * Debugging code
 *
 * | File                | Description                |
 * | :------------------ | :------------------------- |
 * | debug/backtrace.c   | @subpage debug_backtrace   |
 * | debug/common.c      | @subpage debug_common      |
 * | debug/email.c       | @subpage debug_email       |
 * | debug/graphviz.c    | @subpage debug_graphviz    |
 * | debug/keymap.c      | @subpage debug_keymap      |
 * | debug/logging.c     | @subpage debug_logging     |
 * | debug/names.c       | @subpage debug_names       |
 * | debug/notify.c      | @subpage debug_notify      |
 * | debug/pager.c       | @subpage debug_pager       |
 * | debug/window.c      | @subpage debug_window      |
 */

#ifndef MUTT_DEBUG_LIB_H
#define MUTT_DEBUG_LIB_H

#include <stdbool.h>
#include <stddef.h>
#include <time.h>
#include "mutt/lib.h"
#include "email/lib.h"
#include "core/lib.h"
#include "expando/lib.h"
#include "menu/lib.h"

struct AddressList;
struct AttachCtx;
struct AttachPtr;
struct MailboxView;
struct MuttWindow;
struct PagerPrivateData;

// Common
void        add_flag               (struct Buffer *buf, bool is_set, const char *name);

// Backtrace
void show_backtrace(void);

// Email
char        body_name              (const struct Body *b);
void        dump_addr_list         (char *buf, size_t buflen, const struct AddressList *al, const char *name);
void        dump_attach            (const struct AttachPtr *att);
void        dump_body              (const struct Body *body);
void        dump_body_next         (struct Buffer *buf, const struct Body *b);
void        dump_body_one_line     (const struct Body *b);
void        dump_email             (const struct Email *e);
void        dump_envelope          (const struct Envelope *env);
void        dump_list_head         (const struct ListHead *list, const char *name);
void        dump_param_list        (const struct ParameterList *pl);

// Expando
const char *name_expando_domain           (enum ExpandoDomain did);
const char *name_expando_node_type        (enum ExpandoNodeType type);
const char *name_expando_pad_type         (enum ExpandoPadType type);
const char *name_expando_uid              (enum ExpandoDomain did, int uid);
const char *name_expando_uid_alias        (int uid);
const char *name_expando_uid_all          (int uid);
const char *name_expando_uid_attach       (int uid);
const char *name_expando_uid_autocrypt    (int uid);
const char *name_expando_uid_body         (int uid);
const char *name_expando_uid_compose      (int uid);
const char *name_expando_uid_compress     (int uid);
const char *name_expando_uid_email        (int uid);
const char *name_expando_uid_envelope     (int uid);
const char *name_expando_uid_folder       (int uid);
const char *name_expando_uid_global       (int uid);
const char *name_expando_uid_history      (int uid);
const char *name_expando_uid_index        (int uid);
const char *name_expando_uid_mailbox      (int uid);
const char *name_expando_uid_menu         (int uid);
const char *name_expando_uid_nntp         (int uid);
const char *name_expando_uid_pattern      (int uid);
const char *name_expando_uid_pgp          (int uid);
const char *name_expando_uid_pgp_cmd      (int uid);
const char *name_expando_uid_pgp_key      (int uid);
const char *name_expando_uid_pgp_key_gpgme(int uid);
const char *name_expando_uid_sidebar      (int uid);
const char *name_expando_uid_smime_cmd    (int uid);
const char *name_format_justify           (enum FormatJustify just);

// Graphviz
void        dump_graphviz             (const char *title, struct MailboxView *mv);
void        dump_graphviz_attach_ctx  (struct AttachCtx *actx);
void        dump_graphviz_body        (struct Body *b);
void        dump_graphviz_email       (struct Email *e, const char *title);
void        dump_graphviz_expando_node(struct ExpandoNode *node);

// Keymap
void        dump_keybindings        (void);

// Logging
extern bool DebugLogColor;
extern bool DebugLogLevel;
extern bool DebugLogTimestamp;

extern int log_disp_debug           (time_t stamp, const char *file, int line, const char *function, enum LogLevel level, const char *format, ...);

// Names
const char *name_color_id           (int cid);
const char *name_content_disposition(enum ContentDisposition disp);
const char *name_content_encoding   (enum ContentEncoding enc);
const char *name_content_type       (enum ContentType type);
const char *name_mailbox_type       (enum MailboxType type);
const char *name_menu_type          (enum MenuType mt);
const char *name_notify_config      (int id);
const char *name_notify_global      (int id);
const char *name_notify_mailbox     (int id);
const char *name_notify_mview       (int id);
const char *name_notify_type        (enum NotifyType type);
const char *name_window_size        (const struct MuttWindow *win);
const char *name_window_type        (const struct MuttWindow *win);

// Notify
int debug_all_observer(struct NotifyCallback *nc);

// Pager
#ifdef USE_DEBUG_COLOR
void dump_pager(struct PagerPrivateData *priv);
#else
static inline void dump_pager(struct PagerPrivateData *priv) {}
#endif

// Window
struct MuttWindow *debug_win_barrier_wrap(struct MuttWindow *win_child, int width, int height);
void               debug_win_blanket     (struct MuttWindow *win, int cid, char ch);
void               debug_win_dump        (void);

#endif /* MUTT_DEBUG_LIB_H */
