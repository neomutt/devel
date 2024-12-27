/**
 * @file
 * Notification Types
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

#ifndef MUTT_MUTT_NOTIFY_TYPE_H
#define MUTT_MUTT_NOTIFY_TYPE_H

/**
 * enum NotifyType - Notification Types
 *
 * Each type lists the associated Event object
 *
 * @note If you alter this, update #NotifyTypeNames to match
 */
enum NotifyType
{
  NT_ALL = 0,   ///< Register for all notifications
  NT_ACCOUNT,   ///< Account has changed,           #NotifyAccount,     #EventAccount
  NT_ALIAS,     ///< Alias has changed,             #NotifyAlias,       #EventAlias
  NT_ALTERN,    ///< Alternates command changed,    #NotifyAlternates
  NT_ATTACH,    ///< Attachment command changed,    #NotifyAttach
  NT_BINDING,   ///< Key binding has changed,       #NotifyBinding,     #EventBinding
  NT_COLOR,     ///< Colour has changed,            #NotifyColor,       #EventColor
  NT_COMMAND,   ///< A Command has been executed,   #Command
  NT_CONFIG,    ///< Config has changed,            #NotifyConfig,      #EventConfig
  NT_EMAIL,     ///< Email has changed,             #NotifyEmail,       #EventEmail
  NT_ENVELOPE,  ///< Envelope has changed,          #NotifyEnvelope
  NT_GLOBAL,    ///< Not object-related,            #NotifyGlobal
  NT_HEADER,    ///< A header has changed,          #NotifyHeader,      #EventHeader
  NT_INDEX,     ///< Index data has changed,        #NotifyIndex,       #IndexSharedData
  NT_MAILBOX,   ///< Mailbox has changed,           #NotifyMailbox,     #EventMailbox
  NT_MVIEW,     ///< MailboxView has changed,       #NotifyMview,       #EventMview
  NT_MENU,      ///< Menu has changed,              #MenuRedrawFlags
  NT_RESIZE,    ///< Window has been resized
  NT_PAGER,     ///< Pager data has changed,        #NotifyPager,       #PagerPrivateData
  NT_SCORE,     ///< Email scoring has changed
  NT_SPAGER,    ///< Simple Pager has changed,      #NotifySimplePager, #EventSimplePager
  NT_SUBJRX,    ///< Subject Regex has changed,     #NotifySubjRx
  NT_TIMEOUT,   ///< Timeout has occurred
  NT_WINDOW,    ///< MuttWindow has changed,        #NotifyWindow,      #EventWindow
};

#endif /* MUTT_MUTT_NOTIFY_TYPE_H */
