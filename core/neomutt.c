/**
 * @file
 * Container for Accounts, Notifications
 *
 * @authors
 * Copyright (C) 2019 Richard Russon <rich@flatcap.org>
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
 * @page core_neomutt NeoMutt object
 *
 * Container for Accounts, Notifications
 */

#include "config.h"
#include <stddef.h>
#include "mutt/lib.h"
#include "config/lib.h"
#include "neomutt.h"
#include "account.h"
#include "mailbox.h"

struct NeoMutt NeoMutt; ///< Global NeoMutt object

/**
 * neomutt_new - Create the main NeoMutt object
 * @param cs Config Set
 * @retval ptr New NeoMutt
 */
void neomutt_init(struct NeoMutt *n, struct ConfigSet *cs)
{
  memset(n, 0, sizeof(*n));
  if (!cs)
    return;

  TAILQ_INIT(&n->accounts);
  n->notify = notify_new();
  n->sub = cs_subset_new(NULL, NULL, n->notify);
  n->sub->cs = cs;
  n->sub->scope = SET_SCOPE_NEOMUTT;
  n->initialised = true;
}

/**
 * neomutt_clear - Free a NeoMutt's contents
 * @param[out] ptr NeoMutt to clear
 */
void neomutt_clear(struct NeoMutt *n)
{
  if (!n || !n->initialised)
    return;

  neomutt_account_remove(n, NULL);
  cs_subset_free(&n->sub);
  notify_free(&n->notify);

  memset(n, 0, sizeof(*n));
}

/**
 * neomutt_account_add - Add an Account to the global list
 * @param n NeoMutt
 * @param a Account to add
 * @retval true Account was added
 */
bool neomutt_account_add(struct NeoMutt *n, struct Account *a)
{
  if (!n || !a)
    return false;

  TAILQ_INSERT_TAIL(&n->accounts, a, entries);
  notify_set_parent(a->notify, n->notify);

  mutt_debug(LL_NOTIFY, "NT_ACCOUNT_ADD: %s %p\n",
             mailbox_get_type_name(a->type), (void *) a);
  struct EventAccount ev_a = { a };
  notify_send(n->notify, NT_ACCOUNT, NT_ACCOUNT_ADD, &ev_a);
  return true;
}

/**
 * neomutt_account_remove - Remove an Account from the global list
 * @param n NeoMutt
 * @param a Account to remove
 * @retval true Account was removed
 *
 * @note If a is NULL, all the Accounts will be removed
 */
bool neomutt_account_remove(struct NeoMutt *n, const struct Account *a)
{
  if (!n || TAILQ_EMPTY(&n->accounts))
    return false;

  if (!a)
  {
    mutt_debug(LL_NOTIFY, "NT_ACCOUNT_DELETE_ALL\n");
    struct EventAccount ev_a = { NULL };
    notify_send(n->notify, NT_ACCOUNT, NT_ACCOUNT_DELETE_ALL, &ev_a);
  }

  bool result = false;
  struct Account *np = NULL;
  struct Account *tmp = NULL;
  TAILQ_FOREACH_SAFE(np, &n->accounts, entries, tmp)
  {
    if (a && (np != a))
      continue;

    TAILQ_REMOVE(&n->accounts, np, entries);
    account_free(&np);
    result = true;
    if (a)
      break;
  }
  return result;
}

/**
 * neomutt_mailboxlist_clear - Free a Mailbox List
 * @param ml Mailbox List to free
 *
 * @note The Mailboxes aren't freed
 */
void neomutt_mailboxlist_clear(struct MailboxList *ml)
{
  if (!ml)
    return;

  struct MailboxNode *mn = NULL;
  struct MailboxNode *tmp = NULL;
  STAILQ_FOREACH_SAFE(mn, ml, entries, tmp)
  {
    STAILQ_REMOVE(ml, mn, MailboxNode, entries);
    FREE(&mn);
  }
}

/**
 * neomutt_mailboxlist_get_all - Get a List of all Mailboxes
 * @param head List to store the Mailboxes
 * @param n    NeoMutt
 * @param type Type of Account to match, see #MailboxType
 * @retval num Number of Mailboxes in the List
 *
 * @note If type is #MUTT_MAILBOX_ANY then all Mailbox types will be matched
 */
size_t neomutt_mailboxlist_get_all(struct MailboxList *head, struct NeoMutt *n,
                                   enum MailboxType type)
{
  if (!n)
    return 0;

  size_t count = 0;
  struct Account *a = NULL;
  struct MailboxNode *mn = NULL;

  TAILQ_FOREACH(a, &n->accounts, entries)
  {
    if ((type > MUTT_UNKNOWN) && (a->type != type))
      continue;

    STAILQ_FOREACH(mn, &a->mailboxes, entries)
    {
      struct MailboxNode *mn2 = mutt_mem_calloc(1, sizeof(*mn2));
      mn2->mailbox = mn->mailbox;
      STAILQ_INSERT_TAIL(head, mn2, entries);
      count++;
    }
  }

  return count;
}
