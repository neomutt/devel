/**
 * @file
 * Notification API
 *
 * @authors
 * Copyright (C) 2019-2023 Richard Russon <rich@flatcap.org>
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
 * @page mutt_notify Notification API
 *
 * Notification API
 */

#include "config.h"
#include <stdbool.h>
#include <stddef.h>
#include "notify.h"
#include "logging2.h"
#include "memory.h"
#include "notify_type.h"
#include "observer.h"
#include "queue.h"

/// Lookup table for NotifyType
/// Must be the same size and order as #NotifyType
static const char *NotifyTypeNames[] = {
  "NT_ALL",      "NT_ACCOUNT", "NT_ALIAS",   "NT_ALTERN", "NT_ATTACH",
  "NT_BINDING",  "NT_COLOR",   "NT_COMMAND", "NT_CONFIG", "NT_EMAIL",
  "NT_ENVELOPE", "NT_GLOBAL",  "NT_HEADER",  "NT_INDEX",  "NT_MAILBOX",
  "NT_MVIEW",    "NT_MENU",    "NT_RESIZE",  "NT_PAGER",  "NT_SCORE",
  "NT_SPAGER",   "NT_SUBJRX",  "NT_TIMEOUT", "NT_WINDOW",
};

/**
 * struct Notify - Notification API
 */
struct Notify
{
  struct Notify *parent;         ///< Parent of the notification object
  struct ObserverList observers; ///< List of observers of this object
};

/**
 * notify_new - Create a new notifications handler
 * @retval ptr New notification handler
 */
struct Notify *notify_new(void)
{
  struct Notify *notify = MUTT_MEM_CALLOC(1, struct Notify);

  STAILQ_INIT(&notify->observers);

  return notify;
}

/**
 * notify_free - Free a notification handler
 * @param ptr Notification handler to free
 */
void notify_free(struct Notify **ptr)
{
  if (!ptr || !*ptr)
    return;

  struct Notify *notify = *ptr;
  // NOTIFY observers

  notify_observer_remove_all(notify);

  FREE(ptr);
}

/**
 * notify_set_parent - Set the parent notification handler
 * @param notify Notification handler to alter
 * @param parent Parent notification handler
 *
 * Notifications are passed up the tree of handlers.
 */
void notify_set_parent(struct Notify *notify, struct Notify *parent)
{
  if (!notify)
    return;

  notify->parent = parent;
}

/**
 * send - Send out a notification message
 * @param source        Source of the event, e.g. #Account
 * @param current       Current handler, e.g. #NeoMutt
 * @param event_type    Type of event, e.g. #NT_ACCOUNT
 * @param event_subtype Subtype, e.g. #NT_ACCOUNT_ADD
 * @param event_data    Private data associated with the event type
 * @retval true Successfully sent
 *
 * Notifications are sent to all observers of the object, then propagated up
 * the handler tree.  For example a "new email" notification would be sent to
 * the Mailbox that owns it, the Account (owning the Mailbox) and finally the
 * NeoMutt object.
 *
 * @note If Observers call `notify_observer_remove()`, then we garbage-collect
 *       any dead list entries after we've finished.
 */
static bool send(struct Notify *source, struct Notify *current,
                 enum NotifyType event_type, int event_subtype, void *event_data)
{
  if (!source || !current)
    return false;

  mutt_debug(LL_NOTIFY, "send: %d, %p\n", event_type, event_data);
  struct ObserverNode *np = NULL;
  STAILQ_FOREACH(np, &current->observers, entries)
  {
    struct Observer *o = np->observer;
    if (!o)
      continue;

    if ((o->type == NT_ALL) || (event_type == o->type))
    {
      struct NotifyCallback nc = { current, event_type, event_subtype,
                                   event_data, o->global_data };
      if (o->callback(&nc) < 0)
      {
        mutt_debug(LL_DEBUG1, "failed to send notification: %s/%d, global %p, event %p\n",
                   NotifyTypeNames[event_type], event_subtype, o->global_data, event_data);
      }
    }
  }

  if (current->parent)
    return send(source, current->parent, event_type, event_subtype, event_data);

  // Garbage collection time
  struct ObserverNode *tmp = NULL;
  STAILQ_FOREACH_SAFE(np, &current->observers, entries, tmp)
  {
    if (np->observer)
      continue;

    STAILQ_REMOVE(&current->observers, np, ObserverNode, entries);
    FREE(&np);
  }

  return true;
}

/**
 * notify_send - Send out a notification message
 * @param notify        Notification handler
 * @param event_type    Type of event, e.g. #NT_ACCOUNT
 * @param event_subtype Subtype, e.g. #NT_ACCOUNT_ADD
 * @param event_data    Private data associated with the event
 * @retval true Successfully sent
 *
 * See send() for more details.
 */
bool notify_send(struct Notify *notify, enum NotifyType event_type,
                 int event_subtype, void *event_data)
{
  mutt_debug(LL_NOTIFY, "sending: %s/%d\n", NotifyTypeNames[event_type], event_subtype);
  return send(notify, notify, event_type, event_subtype, event_data);
}

/**
 * notify_observer_add - Add an observer to an object
 * @param notify      Notification handler
 * @param type        Notification type to observe, e.g. #NT_WINDOW
 * @param callback    Function to call on a matching event, see ::observer_t
 * @param global_data Private data associated with the observer
 * @retval true Successful
 *
 * New observers are added to the front of the list, giving them higher
 * priority than existing observers.
 */
bool notify_observer_add(struct Notify *notify, enum NotifyType type,
                         observer_t callback, void *global_data)
{
  if (!notify || !callback)
    return false;

  struct ObserverNode *np = NULL;
  STAILQ_FOREACH(np, &notify->observers, entries)
  {
    if (!np->observer)
      continue; // LCOV_EXCL_LINE

    if ((np->observer->callback == callback) && (np->observer->global_data == global_data))
      return true;
  }

  struct Observer *o = MUTT_MEM_CALLOC(1, struct Observer);
  o->type = type;
  o->callback = callback;
  o->global_data = global_data;

  np = MUTT_MEM_CALLOC(1, struct ObserverNode);
  np->observer = o;
  STAILQ_INSERT_HEAD(&notify->observers, np, entries);

  return true;
}

/**
 * notify_observer_remove - Remove an observer from an object
 * @param notify      Notification handler
 * @param callback    Function to call on a matching event, see ::observer_t
 * @param global_data Private data to match specific callback
 * @retval true Successful
 *
 * @note This function frees the Observer, but doesn't free the ObserverNode.
 *       If `send()` is present higher up the call stack,
 *       removing multiple entries from the list will cause it to crash.
 */
bool notify_observer_remove(struct Notify *notify, const observer_t callback,
                            const void *global_data)
{
  if (!notify || !callback)
    return false;

  struct ObserverNode *np = NULL;
  STAILQ_FOREACH(np, &notify->observers, entries)
  {
    if (!np->observer)
      continue; // LCOV_EXCL_LINE

    if ((np->observer->callback == callback) && (np->observer->global_data == global_data))
    {
      FREE(&np->observer);
      return true;
    }
  }

  return false;
}

/**
 * notify_observer_remove_all - Remove all the observers from an object
 * @param notify Notification handler
 */
void notify_observer_remove_all(struct Notify *notify)
{
  if (!notify)
    return;

  struct ObserverNode *np = NULL;
  struct ObserverNode *tmp = NULL;
  STAILQ_FOREACH_SAFE(np, &notify->observers, entries, tmp)
  {
    STAILQ_REMOVE(&notify->observers, np, ObserverNode, entries);
    FREE(&np->observer);
    FREE(&np);
  }
}
