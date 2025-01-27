/**
 * @file
 * GUI manage the main index (list of emails)
 *
 * @authors
 * Copyright (C) 2018-2023 Richard Russon <rich@flatcap.org>
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
 * @page lib_index Index
 *
 * Display a list of Emails
 *
 * | File                   | Description                   |
 * | :--------------------- | :---------------------------- |
 * | index/config.c         | @subpage index_config         |
 * | index/dlg_index.c      | @subpage index_dlg_index      |
 * | index/expando_index.c  | @subpage index_expando_index  |
 * | index/expando_status.c | @subpage index_expando_status |
 * | index/functions.c      | @subpage index_functions      |
 * | index/ibar.c           | @subpage index_ibar           |
 * | index/index.c          | @subpage index_index          |
 * | index/ipanel.c         | @subpage index_ipanel         |
 * | index/private_data.c   | @subpage index_private_data   |
 * | index/shared_data.c    | @subpage index_shared_data    |
 * | index/status.c         | @subpage index_status         |
 */

#ifndef MUTT_INDEX_LIB_H
#define MUTT_INDEX_LIB_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include "mutt/lib.h"
#include "core/lib.h"
#include "expando/lib.h"    // IWYU pragma: keep
#include "expando_index.h"  // IWYU pragma: keep
#include "expando_status.h" // IWYU pragma: keep
#include "functions.h"      // IWYU pragma: keep
#include "shared_data.h"    // IWYU pragma: keep
#include "status.h"         // IWYU pragma: keep

struct Email;
struct MailboxView;
struct Menu;
struct MuttWindow;

// Observers of #NT_INDEX will be passed an #IndexSharedData.
typedef uint8_t NotifyIndex;         ///< Flags, e.g. #NT_INDEX_ACCOUNT
#define NT_INDEX_NO_FLAGS        0   ///< No flags are set
#define NT_INDEX_ADD       (1 << 0)  ///< New Index Shared Data has been created
#define NT_INDEX_DELETE    (1 << 1)  ///< Index Shared Data is about to be freed
#define NT_INDEX_SUBSET    (1 << 2)  ///< Config Subset has changed
#define NT_INDEX_ACCOUNT   (1 << 3)  ///< Account has changed
#define NT_INDEX_MVIEW     (1 << 4)  ///< MailboxView has changed
#define NT_INDEX_MAILBOX   (1 << 5)  ///< Mailbox has changed
#define NT_INDEX_EMAIL     (1 << 6)  ///< Email has changed

typedef uint8_t CheckFlags;       ///< Flags, e.g. #CHECK_IN_MAILBOX
#define CHECK_NO_FLAGS         0  ///< No flags are set
#define CHECK_IN_MAILBOX (1 << 0) ///< Is there a mailbox open?
#define CHECK_MSGCOUNT   (1 << 1) ///< Are there any messages?
#define CHECK_VISIBLE    (1 << 2) ///< Is the selected message visible in the index?
#define CHECK_READONLY   (1 << 3) ///< Is the mailbox readonly?
#define CHECK_ATTACH     (1 << 4) ///< Is the user in message-attach mode?

extern const struct Mapping IndexNewsHelp[];

extern const struct ExpandoDefinition StatusFormatDef[];

void                    change_folder_mailbox   (struct Menu *menu, struct Mailbox *m, int *oldcount, struct IndexSharedData *shared, bool read_only);
struct Mailbox *        change_folder_notmuch   (struct Menu *menu, char *buf, int buflen, int *oldcount, struct IndexSharedData *shared, bool read_only);
void                    change_folder_string    (struct Menu *menu, struct Buffer *buf, int *oldcount, struct IndexSharedData *shared, bool read_only);
bool                    check_acl               (struct Mailbox *m, AclFlags acl, const char *msg);
void                    collapse_all            (struct MailboxView *mv, struct Menu *menu, int toggle);
struct Mailbox *        dlg_index               (struct MuttWindow *dlg, struct Mailbox *m);
int                     find_first_message      (struct MailboxView *mv);
int                     find_next_undeleted     (struct MailboxView *mv, int msgno, bool uncollapse);
int                     find_previous_undeleted (struct MailboxView *mv, int msgno, bool uncollapse);
struct Mailbox *        get_current_mailbox     (void);
struct MailboxView *    get_current_mailbox_view(void);
struct Menu *           get_current_menu        (void);
void                    index_change_folder     (struct MuttWindow *dlg, struct Mailbox *m);
const struct AttrColor *index_color             (struct Menu *menu, int line);
int                     index_make_entry        (struct Menu *menu, int line, int max_cols, struct Buffer *buf);
struct MuttWindow *     index_pager_init        (void);
int                     mutt_dlgindex_observer  (struct NotifyCallback *nc);
void                    mutt_draw_statusline    (struct MuttWindow *win, int max_cols, const char *buf, size_t buflen);
void                    email_set_color         (struct Mailbox *m, struct Email *e);
void                    resort_index            (struct MailboxView *mv, struct Menu *menu);
void                    update_index            (struct Menu *menu, struct MailboxView *mv, enum MxStatus check, int oldcount, const struct IndexSharedData *shared);

int mutt_make_string(struct Buffer *buf, size_t max_cols, const struct Expando *exp,
                     struct Mailbox *m, int inpgr, struct Email *e,
                     MuttFormatFlags flags, const char *progress);

#endif /* MUTT_INDEX_LIB_H */
