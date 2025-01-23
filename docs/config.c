#include "config.h"
#include "makedoc_defs.h"

#ifndef ISPELL
#define ISPELL "ispell"
#endif

/*++*/
// clang-format off
{ "abort_backspace", DT_BOOL, true },
/*
** .pp
** If \fIset\fP, hitting backspace against an empty prompt aborts the
** prompt.
*/

{ "abort_key", DT_STRING, "\007" },
/*
** .pp
** Specifies the key that can be used to abort prompts.  The format is the
** same as used in "bind" commands.  The default is equivalent to "Ctrl-G".
** Note that the specified key should not be used in other bindings, as the
** abort operation has higher precedence and the binding will not have the
** desired effect.
** .pp
** Example:
** .ts
** set abort_key = "<Esc>"
** .te
** .pp
** Please note that when using <Esc> as the abort key, you may also want to
** set the environment variable ESCDELAY to a low value or even 0 which will
** reduce the time that ncurses waits to distinguish singular <Esc> key
** presses from the start of a terminal escape sequence. The default time is
** 1000 milliseconds and thus quite noticeable.
*/

{ "abort_noattach", DT_QUAD, MUTT_NO },
/*
** .pp
** If set to \fIyes\fP, when composing messages containing the regular
** expression specified by $$abort_noattach_regex and no attachments are
** given, composition will be aborted. If set to \fIno\fP, composing messages
** as such will never be aborted.
** .pp
** Example:
** .ts
** set abort_noattach_regex = "\\<attach(|ed|ments?)\\>"
** .te
*/

{ "abort_noattach_regex", DT_REGEX, "\\<(attach|attached|attachments?)\\>" },
/*
** .pp
** Specifies a regular expression to match against the body of the message, to
** determine if an attachment was mentioned but mistakenly forgotten.  If it
** matches, $$abort_noattach will be consulted to determine if message sending
** will be aborted.
** .pp
** Like other regular expressions in NeoMutt, the search is case sensitive
** if the pattern contains at least one upper case letter, and case
** insensitive otherwise.
*/

{ "abort_nosubject", DT_QUAD, MUTT_ASKYES },
/*
** .pp
** If set to \fIyes\fP, when composing messages and no subject is given
** at the subject prompt, composition will be aborted.  If set to
** \fIno\fP, composing messages with no subject given at the subject
** prompt will never be aborted.
*/

{ "abort_unmodified", DT_QUAD, MUTT_YES },
/*
** .pp
** If set to \fIyes\fP, composition will automatically abort after
** editing the message body if no changes are made to the file (this
** check only happens after the \fIfirst\fP edit of the file).  When set
** to \fIno\fP, composition will never be aborted.
*/

{ "account_command", D_STRING_COMMAND, 0 },
/*
** .pp
** If set, this command is used to retrieve account credentials. The command
** is invoked passing a number of \fI--key value\fP arguments with the
** specifics of the account to lookup. The command writes to standard output a
** number of \fIkey: value\fP lines. Currently supported arguments are
** \fI--hostname\fP, \fI--username\fP, and \fI--type\fP, where type can be
** any of \fIimap\fP, \fIimaps\fP, \fIpop\fP, \fIpops\fP, \fIsmtp\fP,
** \fIsmtps\fP, \fInntp\fP, and \fInntps\fP. Currently supported output lines
** are \fIlogin\fP, \fIusername\fP, and \fIpassword\fP.
*/

{ "alias_file", DT_PATH, "~/.neomuttrc" },
/*
** .pp
** The default file in which to save aliases created by the
** \fI$<create-alias>\fP function. Entries added to this file are
** encoded in the character set specified by $$config_charset if it
** is \fIset\fP or the current character set otherwise.
** .pp
** \fBNote:\fP NeoMutt will not automatically source this file; you must
** explicitly use the "$source" command for it to be executed in case
** this option points to a dedicated alias file.
** .pp
** The default for this option is the currently used neomuttrc file, or
** "~/.neomuttrc" if no user neomuttrc was found.
*/

{ "alias_format", DT_STRING, "%3i %f%t %-15a %-56A | %C%> %Y" },
/*
** .pp
** Specifies the format of the data displayed for the "$alias" menu.  The
** following \fIprintf(3)\fP-style sequences are available:
** .dl
** .dt %a  .dd Alias name
** .dt %A  .dd Full Address (Name and Email)
** .dt %C  .dd Comment
** .dt %E  .dd Email Address
** .dt %f  .dd Flags - currently, a "d" for an alias marked for deletion
** .dt %i  .dd Index number
** .dt %N  .dd Real name
** .dt %t  .dd Alias is tagged (selected)
** .dt %Y  .dd User-defined tags (labels)
** .dt %>X .dd right justify the rest of the string and pad with character "X"
** .dt %|X .dd pad to the end of the line with character "X"
** .dt %*X .dd soft-fill with character "X" as pad
** .de
** .pp
** For an explanation of "soft-fill", see the $$index_format documentation.
** .pp
** The following sequences are deprecated; they will be removed in the future.
** .dl
** .dt %c  .dd Use %C instead
** .dt %n  .dd Use %i instead
** .dt %r  .dd Use %A instead
** .de
*/

{ "alias_sort", DT_SORT, ALIAS_SORT_ALIAS },
/*
** .pp
** Specifies how the entries in the "alias" menu are sorted.  The
** following are legal values:
** .il
** .dd address (sort alphabetically by email address)
** .dd alias (sort alphabetically by alias name)
** .dd unsorted (leave in order specified in .neomuttrc)
** .ie
** .pp
** Note: This also affects the entries of the address query menu, thus
** potentially overruling the order of entries as generated by $$query_command.
*/

{ "allow_8bit", DT_BOOL, true },
/*
** .pp
** Controls whether 8-bit data is converted to 7-bit using either Quoted-
** Printable or Base64 encoding when sending mail.
*/

{ "allow_ansi", DT_BOOL, false },
/*
** .pp
** Controls whether ANSI color codes in messages (and color tags in
** rich text messages) are to be interpreted.
** Messages containing these codes are rare, but if this option is \fIset\fP,
** their text will be colored accordingly. Note that this may override
** your color choices, and even present a security problem, since a
** message could include a line like
** .ts
** [-- PGP output follows ...
** .te
** .pp
** and give it the same color as your attachment color (see also
** $$crypt_timestamp).
*/

{ "arrow_cursor", DT_BOOL, false },
/*
** .pp
** When \fIset\fP, an arrow ("->") will be used to indicate the current entry
** in menus instead of highlighting the whole line.  On slow network or modem
** links this will make response faster because there is less that has to
** be redrawn on the screen when moving to the next or previous entries
** in the menu.
*/

{ "arrow_string", DT_STRING, "->" },
/*
** .pp
** Specifies the string of arrow_cursor when arrow_cursor enabled.
*/

{ "ascii_chars", DT_BOOL, false },
/*
** .pp
** If \fIset\fP, NeoMutt will use plain ASCII characters when displaying thread
** and attachment trees, instead of the default \fIACS\fP characters.
*/

{ "ask_bcc", DT_BOOL, false },
/*
** .pp
** If \fIset\fP, NeoMutt will prompt you for blind-carbon-copy (Bcc) recipients
** before editing an outgoing message.
*/

{ "ask_cc", DT_BOOL, false },
/*
** .pp
** If \fIset\fP, NeoMutt will prompt you for carbon-copy (Cc) recipients before
** editing the body of an outgoing message.
*/

{ "ask_followup_to", DT_BOOL, false },
/*
** .pp
** If set, NeoMutt will prompt you for follow-up groups before editing
** the body of an outgoing message.
*/

{ "ask_x_comment_to", DT_BOOL, false },
/*
** .pp
** If set, NeoMutt will prompt you for x-comment-to field before editing
** the body of an outgoing message.
*/

{ "assumed_charset", DT_SLIST, 0 },
/*
** .pp
** This variable is a colon-separated list of character encoding
** schemes for messages without character encoding indication.
** Header field values and message body content without character encoding
** indication would be assumed that they are written in one of this list.
** By default, all the header fields and message body without any charset
** indication are assumed to be in "us-ascii".
** .pp
** For example, Japanese users might prefer this:
** .ts
** set assumed_charset="iso-2022-jp:euc-jp:shift_jis:utf-8"
** .te
** .pp
** However, only the first content is valid for the message body.
*/

{ "attach_charset", DT_SLIST, 0 },
/*
** .pp
** This variable is a colon-separated list of character encoding
** schemes for text file attachments. NeoMutt uses this setting to guess
** which encoding files being attached are encoded in to convert them to
** a proper character set given in $$send_charset.
** .pp
** If \fIunset\fP, the value of $$charset will be used instead.
** For example, the following configuration would work for Japanese
** text handling:
** .ts
** set attach_charset="iso-2022-jp:euc-jp:shift_jis:utf-8"
** .te
** .pp
** Note: for Japanese users, "iso-2022-*" must be put at the head
** of the value as shown above if included.
*/

{ "attach_format", DT_STRING, "%u%D%I %t%4n %T%d %> [%.7m/%.10M, %.6e%<C?, %C>, %s] " },
/*
** .pp
** This variable describes the format of the "attachment" menu.  The
** following \fIprintf(3)\fP-style sequences are understood:
** .dl
** .dt %C  .dd Charset
** .dt %c  .dd Requires charset conversion ("n" or "c")
** .dt %D  .dd Deleted flag
** .dt %d  .dd Description (if none, falls back to %F)
** .dt %e  .dd MIME content-transfer-encoding
** .dt %f  .dd Filename
** .dt %F  .dd Filename in content-disposition header (if none, falls back to %f)
** .dt %I  .dd Disposition ("I" for inline, "A" for attachment)
** .dt %m  .dd Major MIME type
** .dt %M  .dd MIME subtype
** .dt %n  .dd Attachment number
** .dt %Q  .dd "Q", if MIME part qualifies for attachment counting
** .dt %s  .dd Size (see $formatstrings-size)
** .dt %T  .dd Graphic tree characters
** .dt %t  .dd Tagged flag
** .dt %u  .dd Unlink (=to delete) flag
** .dt %X  .dd Number of qualifying MIME parts in this part and its children
**             (please see the "$attachments" section for possible speed effects)
** .dt %>X .dd Right justify the rest of the string and pad with character "X"
** .dt %|X .dd Pad to the end of the line with character "X"
** .dt %*X .dd Soft-fill with character "X" as pad
** .de
** .pp
** For an explanation of "soft-fill", see the $$index_format documentation.
*/

{ "attach_save_dir", DT_PATH, "./" },
/*
** .pp
** The directory where attachments are saved.
*/

{ "attach_save_without_prompting", DT_BOOL, false },
/*
** .pp
** This variable, when set to true, will cause attachments to be saved to
** the 'attach_save_dir' location without prompting the user for the filename.
** .pp
*/

{ "attach_sep", DT_STRING, "\n" },
/*
** .pp
** The separator to add between attachments when operating (saving,
** printing, piping, etc) on a list of tagged attachments.
*/

{ "attach_split", DT_BOOL, true },
/*
** .pp
** If this variable is \fIunset\fP, when operating (saving, printing, piping,
** etc) on a list of tagged attachments, NeoMutt will concatenate the
** attachments and will operate on them as a single attachment. The
** $$attach_sep separator is added after each attachment. When \fIset\fP,
** NeoMutt will operate on the attachments one by one.
*/

{ "attribution_intro", DT_STRING, "On %d, %n wrote:" },
/*
** .pp
** This is the string that will precede a replied-to message which is
** quoted in the main body of the reply (this is the case when $$include is
** set).
** .pp
** For a full listing of defined \fIprintf(3)\fP-like sequences see the section
** on $$index_format.  See also $$attribution_locale.
*/

{ "attribution_locale", DT_STRING, 0 },
/*
** .pp
** The locale used by \fIstrftime(3)\fP to format dates in the
** attribution strings.  Legal values are the strings your system
** accepts for the locale environment variable \fI$$$LC_TIME\fP.
** .pp
** This variable is to allow the attribution date format to be
** customized by recipient or folder using hooks.  By default, NeoMutt
** will use your locale environment, so there is no need to set
** this except to override that default.
** .pp
** Affected variables are: $$attribution_intro, $$attribution_trailer,
** $$forward_attribution_intro, $$forward_attribution_trailer, $$indent_string.
*/

{ "attribution_trailer", DT_STRING, 0 },
/*
** .pp
** Similar to the $$attribution_intro variable, this is the string that will
** come after a replied-to message which is quoted in the main body of the reply
** (this is the case when $$include is set).
** .pp
** For a full listing of defined \fIprintf(3)\fP-like sequences see the section
** on $$index_format.  See also $$attribution_locale.
*/

{ "auto_edit", DT_BOOL, false },
/*
** .pp
** When \fIset\fP along with $$edit_headers, NeoMutt will skip the initial
** send-menu (prompting for subject and recipients) and allow you to
** immediately begin editing the body of your
** message.  The send-menu may still be accessed once you have finished
** editing the body of your message.
** .pp
** \fBNote:\fP when this option is \fIset\fP, you can't use send-hooks that depend
** on the recipients when composing a new (non-reply) message, as the initial
** list of recipients is empty.
** .pp
** Also see $$fast_reply.
*/

{ "auto_subscribe", DT_BOOL, false },
/*
** .pp
** When \fIset\fP, NeoMutt assumes the presence of a List-Post header
** means the recipient is subscribed to the list.  Unless the mailing list
** is in the "unsubscribe" or "unlist" lists, it will be added
** to the "$subscribe" list.  Parsing and checking these things slows
** header reading down, so this option is disabled by default.
*/

{ "auto_tag", DT_BOOL, false },
/*
** .pp
** When \fIset\fP, functions in the \fIindex\fP menu which affect a message
** will be applied to all tagged messages (if there are any).  When
** unset, you must first use the \fI<tag-prefix>\fP function (bound to ";"
** by default) to make the next function apply to all tagged messages.
*/

#ifdef USE_AUTOCRYPT
{ "autocrypt", DT_BOOL, false },
/*
** .pp
** When \fIset\fP, enables autocrypt, which provides
** passive encryption protection with keys exchanged via headers.
** See "$autocryptdoc" for more details.
** (Autocrypt only)
*/

{ "autocrypt_acct_format", DT_STRING, "%4n %-30a %20p %10s" },
/*
** .pp
** This variable describes the format of the "autocrypt account" menu.
** The following \fIprintf(3)\fP-style sequences are understood
** .dl
** .dt %a  .dd email address
** .dt %k  .dd gpg keyid
** .dt %n  .dd current entry number
** .dt %p  .dd prefer-encrypt flag
** .dt %s  .dd status flag (active/inactive)
** .dt %>X .dd right justify the rest of the string and pad with character "X"
** .dt %|X .dd pad to the end of the line with character "X"
** .dt %*X .dd soft-fill with character "X" as pad
** .de
** .pp
** (Autocrypt only)
*/

{ "autocrypt_dir", DT_PATH, "~/.mutt/autocrypt" },
/*
** .pp
** This variable sets where autocrypt files are stored, including the GPG
** keyring and SQLite database.  See "$autocryptdoc" for more details.
** (Autocrypt only)
*/

{ "autocrypt_reply", DT_BOOL, true },
/*
** .pp
** When \fIset\fP, replying to an autocrypt email automatically
** enables autocrypt in the reply.  You may want to unset this if you're using
** the same key for autocrypt as normal web-of-trust, so that autocrypt
** isn't forced on for all encrypted replies.
** (Autocrypt only)
*/
#endif

{ "beep", DT_BOOL, true },
/*
** .pp
** When this variable is \fIset\fP, NeoMutt will beep when an error occurs.
*/

{ "beep_new", DT_BOOL, false },
/*
** .pp
** When this variable is \fIset\fP, NeoMutt will beep whenever it prints a message
** notifying you of new mail.  This is independent of the setting of the
** $$beep variable.
*/

{ "bounce", DT_QUAD, MUTT_ASKYES },
/*
** .pp
** Controls whether you will be asked to confirm bouncing messages.
** If set to \fIyes\fP you don't get asked if you want to bounce a
** message. Setting this variable to \fIno\fP is not generally useful,
** and thus not recommended, because you are unable to bounce messages.
*/

{ "bounce_delivered", DT_BOOL, true },
/*
** .pp
** When this variable is \fIset\fP, NeoMutt will include Delivered-To headers when
** bouncing messages.  Postfix users may wish to \fIunset\fP this variable.
*/

{ "braille_friendly", DT_BOOL, false },
/*
** .pp
** When this variable is \fIset\fP, NeoMutt will place the cursor at the beginning
** of the current line in menus, even when the $$arrow_cursor variable
** is \fIunset\fP, making it easier for blind persons using Braille displays to
** follow these menus.  The option is \fIunset\fP by default because many
** visual terminals don't permit making the cursor invisible.
*/

{ "browser_abbreviate_mailboxes", DT_BOOL, true },
/*
** .pp
** When this variable is \fIset\fP, NeoMutt will abbreviate mailbox
** names in the browser mailbox list, using '~' and '='
** shortcuts.
** .pp
** The default \fI"alpha"\fP setting of $$browser_sort uses
** locale-based sorting (using \fIstrcoll(3)\fP), which ignores some
** punctuation.  This can lead to some situations where the order
** doesn't make intuitive sense.  In those cases, it may be
** desirable to \fIunset\fP this variable.
*/

{ "browser_sort", DT_SORT, BROWSER_SORT_ALPHA },
/*
** .pp
** Specifies how to sort entries in the file browser.  By default, the
** entries are sorted alphabetically.  Valid values:
** .il
** .dd alpha (alphabetically by name)
** .dd count (total message count)
** .dd date
** .dd desc (description)
** .dd new (new message count)
** .dd size
** .dd unsorted
** .ie
** .pp
** You may optionally use the "reverse-" prefix to specify reverse sorting
** order (example: "\fIset browser_sort=reverse-date\fP").
** .pp
** The "unread" value is a synonym for "new".
*/

{ "browser_sort_dirs_first", DT_BOOL, false },
/*
** .pp
** If this variable is \fIset\fP, the browser will group directories before
** files.
*/

{ "catchup_newsgroup", DT_QUAD, MUTT_ASKYES },
/*
** .pp
** If this variable is \fIset\fP, NeoMutt will mark all articles in newsgroup
** as read when you quit the newsgroup (catchup newsgroup).
*/

#ifdef USE_SSL
{ "certificate_file", DT_PATH, "~/.mutt_certificates" },
/*
** .pp
** This variable specifies the file where the certificates you trust
** are saved. When an unknown certificate is encountered, you are asked
** if you accept it or not. If you accept it, the certificate can also
** be saved in this file and further connections are automatically
** accepted.
** .pp
** You can also manually add CA certificates in this file. Any server
** certificate that is signed with one of these CA certificates is
** also automatically accepted.
** .pp
** Example:
** .ts
** set certificate_file=~/.neomutt/certificates
** .te
** .pp
** (OpenSSL and GnuTLS only)
*/
#endif

{ "change_folder_next", DT_BOOL, false },
/*
** .pp
** When this variable is \fIset\fP, the \fI<change-folder>\fP function
** mailbox suggestion will start at the next folder in your "$mailboxes"
** list, instead of starting at the first folder in the list.
*/

{ "charset", DT_STRING, 0 },
/*
** .pp
** Character set your terminal uses to display and enter textual data.
** It is also the fallback for $$send_charset.
** .pp
** Upon startup NeoMutt tries to derive this value from environment variables
** such as \fI$$$LC_CTYPE\fP or \fI$$$LANG\fP.
** .pp
** \fBNote:\fP It should only be set in case NeoMutt isn't able to determine the
** character set used correctly.
*/

{ "check_mbox_size", DT_BOOL, false },
/*
** .pp
** When this variable is \fIset\fP, NeoMutt will use file size attribute instead of
** access time when checking for new mail in mbox and mmdf folders.
** .pp
** This variable is \fIunset\fP by default and should only be enabled when
** new mail detection for these folder types is unreliable or doesn't work.
** .pp
** Note that enabling this variable should happen before any "$mailboxes"
** directives occur in configuration files regarding mbox or mmdf folders
** because NeoMutt needs to determine the initial new mail status of such a
** mailbox by performing a fast mailbox scan when it is defined.
** Afterwards the new mail status is tracked by file size changes.
*/

{ "check_new", DT_BOOL, true },
/*
** .pp
** \fBNote:\fP this option only affects \fImaildir\fP and \fIMH\fP style
** mailboxes.
** .pp
** When \fIset\fP, NeoMutt will check for new mail delivered while the
** mailbox is open.  Especially with MH mailboxes, this operation can
** take quite some time since it involves scanning the directory and
** checking each file to see if it has already been looked at.  If
** this variable is \fIunset\fP, no check for new mail is performed
** while the mailbox is open.
*/

{ "collapse_all", DT_BOOL, false },
/*
** .pp
** When \fIset\fP, NeoMutt will collapse all threads when entering a folder.
*/

{ "collapse_flagged", DT_BOOL, true },
/*
** .pp
** When \fIunset\fP, NeoMutt will not collapse a thread if it contains any
** flagged messages.
*/

{ "collapse_unread", DT_BOOL, true },
/*
** .pp
** When \fIunset\fP, NeoMutt will not collapse a thread if it contains any
** unread messages.
*/

{ "color_directcolor", DT_BOOL, false },
/*
** .pp
** When \fIset\fP, NeoMutt will use and allow 24bit colours (aka truecolor aka
** directcolor).  For colours to work properly support from the terminal is
** required as well as a properly set TERM environment variable advertising the
** terminals directcolor capability, e.g. "TERM=xterm-direct".
** .pp
** NeoMutt tries to detect whether the terminal supports 24bit colours and
** enables this variable if it does.  If this fails for some reason, you can
** force 24bit colours by setting this variable manually.  You may also try to
** force a certain TERM environment variable by starting NeoMutt from
** a terminal as follows (this results in wrong colours if the terminal does
** not implement directcolors):
** .ts
** TERM=xterm-direct neomutt
** .te
** .pp
** Note: This variable must be set before using any `color` commands.
** .pp
*/

{ "compose_confirm_detach_first", DT_BOOL, true },
/*
** .pp
** When \fIset\fP, NeoMutt will prompt for confirmation when trying to use
** \fI<detach-file>\fP on the first entry in the compose menu. This is to help
** prevent irreversible loss of the typed message by accidentally hitting 'D' in
** the menu.
** .pp
** Note: NeoMutt only prompts for the first entry.  It doesn't keep track of
** which message is the typed message if the entries are reordered, or if the
** first entry was already deleted.
*/

{ "compose_format", DT_STRING, "-- NeoMutt: Compose  [Approx. msg size: %l   Atts: %a]%>-" },
/*
** .pp
** Controls the format of the status line displayed in the "compose"
** menu.  This string is similar to $$status_format, but has its own
** set of \fIprintf(3)\fP-like sequences:
** .dl
** .dt %a  .dd Total number of attachments
** .dt %h  .dd Local hostname
** .dt %l  .dd Approximate size (in bytes) of the current message (see $formatstrings-size)
** .dt %v  .dd NeoMutt version string
** .dt %>X .dd right justify the rest of the string and pad with character "X"
** .dt %|X .dd pad to the end of the line with character "X"
** .dt %*X .dd soft-fill with character "X" as pad
** .de
** .pp
** See the text describing the $$status_format option for more
** information on how to set $$compose_format.
*/

{ "compose_preview_min_rows", DT_NUMBER, 5 },
/*
** .pp
** This variable specifies the minimum number of rows that have to be
** available for the message preview window to shown.
*/

{ "compose_preview_above_attachments", DT_BOOL, false },
/*
** .pp
** Show the message preview above the attachments list.
** By default it is shown below it.
*/

{ "compose_show_preview", DT_BOOL, true },
/*
** .pp
** When \fIset\fP, Neomutt will display a preview of message in the compose view.
*/

{ "compose_show_user_headers", DT_BOOL, true },
/*
** .pp
** When \fIset\fP, Neomutt will display user-defined headers (set via $my_hdr
** or from editing with edit-headers).
*/

{ "config_charset", DT_STRING, 0 },
/*
** .pp
** When defined, NeoMutt will recode commands in rc files from this
** encoding to the current character set as specified by $$charset
** and aliases written to $$alias_file from the current character set.
** .pp
** Please note that if setting $$charset it must be done before
** setting $$config_charset.
** .pp
** Recoding should be avoided as it may render unconvertible
** characters as question marks which can lead to undesired
** side effects (for example in regular expressions).
*/

{ "confirm_append", DT_BOOL, true },
/*
** .pp
** When \fIset\fP, NeoMutt will prompt for confirmation when appending messages to
** an existing mailbox.
*/

{ "confirm_create", DT_BOOL, true },
/*
** .pp
** When \fIset\fP, NeoMutt will prompt for confirmation when saving messages to a
** mailbox which does not yet exist before creating it.
*/

{ "content_type", DT_STRING, "text/plain" },
/*
** .pp
** Sets the default Content-Type for the body of newly composed messages.
*/

{ "copy", DT_QUAD, MUTT_YES },
/*
** .pp
** This variable controls whether or not copies of your outgoing messages
** will be saved for later references.  Also see $$record,
** $$save_name, $$force_name and "$fcc-hook".
*/

{ "copy_decode_weed", DT_BOOL, false },
/*
** .pp
** Controls whether NeoMutt will weed headers when invoking the
** \fI<decode-copy>\fP or \fI<decode-save>\fP functions.
*/

{ "count_alternatives", DT_BOOL, false },
/*
** .pp
** When \fIset\fP, NeoMutt will recurse inside multipart/alternatives while
** performing attachment searching and counting(see $attachments).
** .pp
** Traditionally, multipart/alternative parts have simply represented
** different encodings of the main content of the email.  Unfortunately,
** some mail clients have started to place email attachments inside
** one of alternatives.  Setting this will allow NeoMutt to find
** and count matching attachments hidden there, and include them
** in the index via %X or through ~X pattern matching.
*/

{ "crypt_auto_encrypt", DT_BOOL, false },
/*
** .pp
** Setting this variable will cause NeoMutt to always attempt to PGP
** encrypt outgoing messages.  This is probably only useful in
** connection to the "$send-hook" command.  It can be overridden
** by use of the pgp menu, when encryption is not required or
** signing is requested as well.  If $$smime_is_default is \fIset\fP,
** then OpenSSL is used instead to create S/MIME messages and
** settings can be overridden by use of the smime menu instead.
** (Crypto only)
*/

{ "crypt_auto_pgp", DT_BOOL, true },
/*
** .pp
** This variable controls whether or not NeoMutt may automatically enable
** PGP encryption/signing for messages.  See also $$crypt_auto_encrypt,
** $$crypt_reply_encrypt,
** $$crypt_auto_sign, $$crypt_reply_sign and $$smime_is_default.
*/

{ "crypt_auto_sign", DT_BOOL, false },
/*
** .pp
** Setting this variable will cause NeoMutt to always attempt to
** cryptographically sign outgoing messages.  This can be overridden
** by use of the pgp menu, when signing is not required or
** encryption is requested as well. If $$smime_is_default is \fIset\fP,
** then OpenSSL is used instead to create S/MIME messages and settings can
** be overridden by use of the smime menu instead of the pgp menu.
** (Crypto only)
*/

{ "crypt_auto_smime", DT_BOOL, true },
/*
** .pp
** This variable controls whether or not NeoMutt may automatically enable
** S/MIME encryption/signing for messages. See also $$crypt_auto_encrypt,
** $$crypt_reply_encrypt,
** $$crypt_auto_sign, $$crypt_reply_sign and $$smime_is_default.
*/

{ "crypt_chars", DT_MBTABLE, "SPsK " },
/*
** .pp
** Controls the characters used in cryptography flags.
** .dl
** .dt \fBCharacter\fP .dd \fBDefault\fP .dd \fBDescription\fP
** .dt 1 .dd S .dd The mail is signed, and the signature is successfully verified.
** .dt 2 .dd P .dd The mail is PGP encrypted.
** .dt 3 .dd s .dd The mail is signed.
** .dt 4 .dd K .dd The mail contains a PGP public key.
** .dt 5 .dd <space> .dd The mail has no crypto info.
** .de
*/

{ "crypt_confirm_hook", DT_BOOL, true },
/*
** .pp
** If set, then you will be prompted for confirmation of keys when using
** the \fIcrypt-hook\fP command.  If unset, no such confirmation prompt will
** be presented.  This is generally considered unsafe, especially where
** typos are concerned.
*/

{ "crypt_opportunistic_encrypt", DT_BOOL, false },
/*
** .pp
** Setting this variable will cause NeoMutt to automatically enable and
** disable encryption, based on whether all message recipient keys
** can be located by NeoMutt.
** .pp
** When this option is enabled, NeoMutt will enable/disable encryption
** each time the TO, CC, and BCC lists are edited.  If
** $$edit_headers is set, NeoMutt will also do so each time the message
** is edited.
** .pp
** While this is set, encryption can't be manually enabled/disabled.
** The pgp or smime menus provide a selection to temporarily disable
** this option for the current message.
** .pp
** If $$crypt_auto_encrypt or $$crypt_reply_encrypt enable encryption for
** a message, this option will be disabled for that message.  It can
** be manually re-enabled in the pgp or smime menus.
** (Crypto only)
*/

{ "crypt_opportunistic_encrypt_strong_keys", DT_BOOL, false },
/*
** .pp
** When set, this modifies the behavior of $$crypt_opportunistic_encrypt
** to only search for "strong keys", that is, keys with full validity
** according to the web-of-trust algorithm.  A key with marginal or no
** validity will not enable opportunistic encryption.
** .pp
** For S/MIME, the behavior depends on the backend.  Classic S/MIME will
** filter for certificates with the 't'(trusted) flag in the .index file.
** The GPGME backend will use the same filters as with OpenPGP, and depends
** on GPGME's logic for assigning the GPGME_VALIDITY_FULL and
** GPGME_VALIDITY_ULTIMATE validity flag.
*/

{ "crypt_protected_headers_read", DT_BOOL, true },
/*
** .pp
** When set, NeoMutt will display protected headers ("Memory Hole") in the pager,
** When set, NeoMutt will display protected headers in the pager,
** and will update the index and header cache with revised headers.
** .pp
** Protected headers are stored inside the encrypted or signed part of an
** an email, to prevent disclosure or tampering.
** For more information see https://github.com/autocrypt/protected-headers
** Currently NeoMutt only supports the Subject header.
** .pp
** Encrypted messages using protected headers often substitute the exposed
** Subject header with a dummy value (see $$crypt_protected_headers_subject).
** NeoMutt will update its concept of the correct subject \fBafter\fP the
** message is opened, i.e. via the \fI<display-message>\fP function.
** If you reply to a message before opening it, NeoMutt will end up using
** the dummy Subject header, so be sure to open such a message first.
** (Crypto only)
*/

{ "crypt_protected_headers_save", DT_BOOL, false },
/*
** .pp
** When $$crypt_protected_headers_read is set, and a message with a
** protected Subject is opened, NeoMutt will save the updated Subject
** into the header cache by default.  This allows searching/limiting
** based on the protected Subject header if the mailbox is
** re-opened, without having to re-open the message each time.
** However, for mbox/mh mailbox types, or if header caching is not
** set up, you would need to re-open the message each time the
** mailbox was reopened before you could see or search/limit on the
** protected subject again.
** .pp
** When this variable is set, NeoMutt additionally saves the protected
** Subject back \fBin the clear-text message headers\fP.  This
** provides better usability, but with the tradeoff of reduced
** security.  The protected Subject header, which may have
** previously been encrypted, is now stored in clear-text in the
** message headers.  Copying the message elsewhere, via NeoMutt or
** external tools, could expose this previously encrypted data.
** Please make sure you understand the consequences of this before
** you enable this variable.
** (Crypto only)
*/

{ "crypt_protected_headers_subject", DT_STRING, "..." },
/*
** .pp
** When $$crypt_protected_headers_write is set, and the message is marked
** for encryption, this will be substituted into the Subject field in the
** message headers.
** .pp
** To prevent a subject from being substituted, unset this variable, or set it
** to the empty string.
** (Crypto only)
*/

{ "crypt_protected_headers_weed", DT_BOOL, false },
/*
** .pp
** Controls whether NeoMutt will weed protected header fields.
** (Crypto only)
*/

{ "crypt_protected_headers_write", DT_BOOL, true },
/*
** .pp
** When set, NeoMutt will generate protected headers for signed and encrypted
** emails.
** .pp
** Protected headers are stored inside the encrypted or signed part of an
** an email, to prevent disclosure or tampering.
** For more information see https://github.com/autocrypt/protected-headers
** .pp
** Currently NeoMutt only supports the Subject header.
** (Crypto only)
*/

{ "crypt_reply_encrypt", DT_BOOL, true },
/*
** .pp
** If \fIset\fP, automatically PGP or OpenSSL encrypt replies to messages which are
** encrypted.
** (Crypto only)
*/

{ "crypt_reply_sign", DT_BOOL, false },
/*
** .pp
** If \fIset\fP, automatically PGP or OpenSSL sign replies to messages which are
** signed.
** .pp
** \fBNote:\fP this does not work on messages that are encrypted
** \fIand\fP signed!
** (Crypto only)
*/

{ "crypt_reply_sign_encrypted", DT_BOOL, false },
/*
** .pp
** If \fIset\fP, automatically PGP or OpenSSL sign replies to messages
** which are encrypted. This makes sense in combination with
** $$crypt_reply_encrypt, because it allows you to sign all
** messages which are automatically encrypted.  This works around
** the problem noted in $$crypt_reply_sign, that NeoMutt is not able
** to find out whether an encrypted message is also signed.
** (Crypto only)
*/

{ "crypt_encryption_info", DT_BOOL, true },
/*
** .pp
** If \fIset\fP, NeoMutt will include an informative block
** before an encrypted part,
** with details about the encryption.
** (Crypto only)
*/

{ "crypt_timestamp", DT_BOOL, true },
/*
** .pp
** If \fIset\fP, NeoMutt will include a time stamp in the lines surrounding
** PGP or S/MIME output, so spoofing such lines is more difficult.
** If you are using colors to mark these lines, and rely on these,
** you may \fIunset\fP this setting.
** (Crypto only)
*/

#ifdef CRYPT_BACKEND_GPGME
{ "crypt_use_gpgme", DT_BOOL, true },
/*
** .pp
** This variable controls the use of the GPGME-enabled crypto backends.
** If it is \fIset\fP and NeoMutt was built with GPGME support, the gpgme code for
** S/MIME and PGP will be used instead of the classic code.  Note that
** you need to set this option in .neomuttrc; it won't have any effect when
** used interactively.
** .pp
** Note that the GPGME backend does not support creating old-style inline
** (traditional) PGP encrypted or signed messages (see $$pgp_auto_inline).
*/

{ "crypt_use_pka", DT_BOOL, false },
/*
** .pp
** Controls whether NeoMutt uses PKA
** (see http://www.g10code.de/docs/pka-intro.de.pdf) during signature
** verification (only supported by the GPGME backend).
*/
#endif

{ "crypt_verify_sig", DT_QUAD, MUTT_YES },
/*
** .pp
** If \fI"yes"\fP, always attempt to verify PGP or S/MIME signatures.
** If \fI"ask-*"\fP, ask whether or not to verify the signature.
** If \fI"no"\fP, never attempt to verify cryptographic signatures.
** (Crypto only)
*/

{ "date_format", DT_STRING, "!%a, %b %d, %Y at %I:%M:%S%p %Z" },
/*
** .pp
** Instead of using $$date_format it is encouraged to use "%[fmt]"
** directly in the corresponding format strings, where "fmt" is the
** value of $$date_format.  This allows for a more fine grained control
** of the different menu needs.
** .pp
** This variable controls the format of the date printed by the "%d"
** sequence in $$index_format.  This is passed to the \fIstrftime(3)\fP
** function to process the date, see the man page for the proper syntax.
** .pp
** Unless the first character in the string is a bang ("!"), the month
** and week day names are expanded according to the locale.
** If the first character in the string is a
** bang, the bang is discarded, and the month and week day names in the
** rest of the string are expanded in the \fIC\fP locale (that is in US
** English).
** .pp
** Format strings using this variable are:
** .pp
** UI: $$folder_format, $$index_format, $$mailbox_folder_format,
** $$message_format
** .pp
** Composing: $$attribution_intro, $$forward_attribution_intro,
** $$forward_attribution_trailer, $$forward_format, $$indent_string.
** .pp
*/

{ "debug_file", DT_PATH, "~/.neomuttdebug" },
/*
** .pp
** Debug logging is controlled by the variables \fI$$debug_file\fP and \fI$$debug_level\fP.
** \fI$$debug_file\fP specifies the root of the filename.  NeoMutt will add "0" to the end.
** Each time NeoMutt is run with logging enabled, the log files are rotated.
** A maximum of five log files are kept, numbered 0 (most recent) to 4 (oldest).
** .pp
** This option can be enabled on the command line, "neomutt -l mylog"
** .pp
** See also: \fI$$debug_level\fP
*/

{ "debug_level", DT_NUMBER, 0 },
/*
** .pp
** Debug logging is controlled by the variables \fI$$debug_file\fP and \fI$$debug_level\fP.
** .pp
** The debug level controls how much information is saved to the log file.
** If you have a problem with NeoMutt, then enabling logging may help find the cause.
** Levels 1-3 will usually provide enough information for writing a bug report.
** Levels 4,5 will be extremely verbose.
** .pp
** Warning: Logging at high levels may save private information to the file.
** .pp
** This option can be enabled on the command line, "neomutt -d 2"
** .pp
** See also: \fI$$debug_file\fP
*/

{ "default_hook", DT_STRING, "~f %s !~P | (~P ~C %s)" },
/*
** .pp
** This variable controls how some hooks are interpreted if their pattern is a
** plain string or a regex. i.e. they don't contain a pattern, like \fI~f\fP
** .pp
** The hooks are: $fcc-hook, $fcc-save-hook, $index-format-hook, $message-hook,
** $reply-hook, $save-hook, $send-hook and $send2-hook.
** .pp
** The hooks are expanded when they are declared, so a hook will be interpreted
** according to the value of this variable at the time the hook is declared.
** .pp
** The default value matches if the message is either from a user matching the
** regular expression given, or if it is from you (if the from address matches
** "$alternates") and is to or cc'ed to a user matching the given regular
** expression.
*/

{ "delete", DT_QUAD, MUTT_ASKYES },
/*
** .pp
** Controls whether or not messages are really deleted when closing or
** synchronizing a mailbox.  If set to \fIyes\fP, messages marked for
** deleting will automatically be purged without prompting.  If set to
** \fIno\fP, messages marked for deletion will be kept in the mailbox.
*/

{ "delete_untag", DT_BOOL, true },
/*
** .pp
** If this option is \fIset\fP, NeoMutt will untag messages when marking them
** for deletion.  This applies when you either explicitly delete a message,
** or when you save it to another folder.
*/

{ "devel_security", DT_BOOL, false },
/*
** .pp
** If this option is \fIset\fP, NeoMutt will enable the \fBSecurity\fP development features.
** See: https://github.com/neomutt/neomutt/discussions/4251
*/

{ "digest_collapse", DT_BOOL, true },
/*
** .pp
** If this option is \fIset\fP, NeoMutt's received-attachments menu will not show the subparts of
** individual messages in a multipart/digest.  To see these subparts, press "v" on that menu.
*/

{ "display_filter", D_STRING_COMMAND, 0 },
/*
** .pp
** When set, specifies a command used to filter messages.  When a message
** is viewed it is passed as standard input to $$display_filter, and the
** filtered message is read from the standard output.
** .pp
** When preparing the message, NeoMutt inserts some escape sequences into the
** text.  They are of the form: \fI<esc>]9;XXX<bel>\fP where "XXX" is a random
** 64-bit number.
** .pp
** If these escape sequences interfere with your filter, they can be removed
** using a tool like \fIansifilter\fP or \fIsed 's/^\x1b]9;[0-9]\+\x7//'\fP
** .pp
** If they are removed, then PGP and MIME headers will no longer be coloured.
** This can be fixed by adding this to your config:
** \fIcolor body magenta default '^\[-- .* --\]$$$'\fP.
*/

{ "dsn_notify", DT_STRING, 0 },
/*
** .pp
** This variable sets the request for when notification is returned.  The
** string consists of a comma separated list (no spaces!) of one or more
** of the following: \fInever\fP, to never request notification,
** \fIfailure\fP, to request notification on transmission failure,
** \fIdelay\fP, to be notified of message delays, \fIsuccess\fP, to be
** notified of successful transmission.
** .pp
** Example:
** .ts
** set dsn_notify="failure,delay"
** .te
** .pp
** \fBNote:\fP when using $$sendmail for delivery, you should not enable
** this unless you are either using Sendmail 8.8.x or greater or a MTA
** providing a \fIsendmail(1)\fP-compatible interface supporting the \fI-N\fP option
** for DSN. For SMTP delivery, DSN support is auto-detected so that it
** depends on the server whether DSN will be used or not.
*/

{ "dsn_return", DT_STRING, 0 },
/*
** .pp
** This variable controls how much of your message is returned in DSN
** messages.  It may be set to either \fIhdrs\fP to return just the
** message header, or \fIfull\fP to return the full message.
** .pp
** Example:
** .ts
** set dsn_return=hdrs
** .te
** .pp
** \fBNote:\fP when using $$sendmail for delivery, you should not enable
** this unless you are either using Sendmail 8.8.x or greater or a MTA
** providing a \fIsendmail(1)\fP-compatible interface supporting the \fI-R\fP option
** for DSN. For SMTP delivery, DSN support is auto-detected so that it
** depends on the server whether DSN will be used or not.
*/

{ "duplicate_threads", DT_BOOL, true },
/*
** .pp
** This variable controls whether NeoMutt, when $$sort is set to \fIthreads\fP, threads
** messages with the same Message-Id together.  If it is \fIset\fP, it will indicate
** that it thinks they are duplicates of each other with an equals sign
** in the thread tree.
*/

{ "edit_headers", DT_BOOL, false },
/*
** .pp
** This option allows you to edit the header of your outgoing messages
** along with the body of your message.
** .pp
** Although the compose menu may have localized header labels, the
** labels passed to your editor will be standard RFC2822 headers,
** (e.g. To:, Cc:, Subject:).  Headers added in your editor must
** also be RFC2822 headers, or one of the pseudo headers listed in
** "$edit-header".  NeoMutt will not understand localized header
** labels, just as it would not when parsing an actual email.
** .pp
** \fBNote\fP that changes made to the References: and Date: headers are
** ignored for interoperability reasons.
*/

{ "editor", D_STRING_COMMAND, 0 },
/*
** .pp
** This variable specifies which editor is used by NeoMutt.
** It defaults to the value of the \fI$$$VISUAL\fP, or \fI$$$EDITOR\fP, environment
** It defaults to the value of the \fC$$$VISUAL\fP, or \fC$$$EDITOR\fP, environment
** variable, or to the string "vi" if neither of those are set.
** .pp
** The \fI$$editor\fP string may contain a \fI%s\fP escape, which will be replaced by the name
** of the file to be edited.  If the \fI%s\fP escape does not appear in \fI$$editor\fP, a
** space and the name to be edited are appended.
** .pp
** The resulting string is then executed by running
** .ts
** sh -c 'string'
** .te
** .pp
** where \fIstring\fP is the expansion of \fI$$editor\fP described above.
*/

{ "empty_subject", DT_STRING, "Re: your mail" },
/*
** .pp
** This variable specifies the subject to be used when replying to an email
** with an empty subject.  It defaults to "Re: your mail".
*/

{ "encode_from", DT_BOOL, false },
/*
** .pp
** When \fIset\fP, NeoMutt will quoted-printable encode messages when
** they contain the string "From " (note the trailing space) in the beginning of a line.
** This is useful to avoid the tampering certain mail delivery and transport
** agents tend to do with messages (in order to prevent tools from
** misinterpreting the line as a mbox message separator).
*/

#ifdef USE_SSL_OPENSSL
{ "entropy_file", DT_PATH, 0 },
/*
** .pp
** The file which includes random data that is used to initialize SSL
** library functions. (OpenSSL only)
*/
#endif

{ "envelope_from_address", DT_ADDRESS, 0 },
/*
** .pp
** Manually sets the \fIenvelope\fP sender for outgoing messages.
** This value is ignored if $$use_envelope_from is \fIunset\fP.
*/

{ "external_search_command", D_STRING_COMMAND, 0 },
/*
** .pp
** If set, contains the name of the external program used by "~I" patterns.
** This will usually be a wrapper script around mairix, mu, or similar
** indexers other than notmuch (for which there is optional special support).
** .pp
** Here is an example how it works.  Let's assume $$external_search_command
** is set to "mairix_filter", and mairix_filter is a script which
** runs the old but well loved mairix indexer with the arguments
** given to mairix_filter, in the "raw" mode of mairix, producing
** on the standard output a list of Message-IDs, one per line.
** .pp
** If possible, it also filters down the results coming from mairix
** such that only messages in the current folder remain.  It can do
** this because it gets a hidden first argument which is the path
** to the folder.
** (This can be the type of clean and simple script called a \fIone-liner\fP.)
** .pp
** Now if NeoMutt gets a limit or tag command followed by the pattern
** "~I '-t s:bleeping='", mairix_filter runs mairix with the
** arguments from inside the quotes (the quotes are needed because
** of the space after "-t"), mairix finds all messages with
** "bleeping" in the Subject plus all messages sharing threads
** with these and outputs their file names, and mairix_filter
** translates the file names into Message-IDs.  Finally, NeoMutt
** reads the Message-IDs and targets the matching messages with the
** command given to it.
** .pp
** You, the user, still have to rewrite the mairix_filter script to
** match the behavior of your indexer, but this should help users
** of indexers other than notmuch to integrate them cleanly with NeoMutt.
*/

{ "fast_reply", DT_BOOL, false },
/*
** .pp
** When \fIset\fP, the initial prompt for recipients (to, cc, bcc) and
** subject are skipped when the relevant information is already provided.
** These cases include replying to messages and passing the relevant
** command line arguments. The initial prompt for recipients
** is also skipped when composing a new message to the current message sender,
** while the initial prompt for subject is also skipped when forwarding messages.
** .pp
** \fBNote:\fP this variable has no effect when the $$auto_edit
** variable is \fIset\fP.
** .pp
** See also: $$auto_edit, $$edit_headers, $$ask_cc, $$ask_bcc
*/

{ "fcc_attach", DT_QUAD, MUTT_YES },
/*
** .pp
** This variable controls whether or not attachments on outgoing messages
** are saved along with the main body of your message.
** .pp
** Note: $$fcc_before_send forces the default (set) behavior of this option.
*/

{ "fcc_before_send", DT_BOOL, false },
/*
** .pp
** When this variable is \fIset\fP, FCCs will occur before sending
** the message.  Before sending, the message cannot be manipulated,
** so it will be stored the exact same as sent:
** $$fcc_attach and $$fcc_clear will be ignored (using their default
** values).
** .pp
** When \fIunset\fP, the default, FCCs will occur after sending.
** Variables $$fcc_attach and $$fcc_clear will be respected, allowing
** it to be stored without attachments or encryption/signing if
** desired.
*/

{ "fcc_clear", DT_BOOL, false },
/*
** .pp
** When this variable is \fIset\fP, FCCs will be stored unencrypted and
** unsigned, even when the actual message is encrypted and/or
** signed.
** .pp
** Note: $$fcc_before_send forces the default (unset) behavior of this option.
** (PGP only)
** .pp
** See also $$pgp_self_encrypt, $$smime_self_encrypt
*/

{ "flag_chars", DT_MBTABLE, "*!DdrONon- " },
/*
** .pp
** Controls the characters used in several flags.
** .dl
** .dt \fBCharacter\fP .dd \fBDefault\fP .dd \fBDescription\fP
** .dt 1 .dd * .dd The mail is tagged.
** .dt 2 .dd ! .dd The mail is flagged as important.
** .dt 3 .dd D .dd The mail is marked for deletion.
** .dt 4 .dd d .dd The mail has attachments marked for deletion.
** .dt 5 .dd r .dd The mail has been replied to.
** .dt 6 .dd O .dd The mail is Old (Unread but seen).
** .dt 7 .dd N .dd The mail is New (Unread but not seen).
** .dt 8 .dd o .dd The mail thread is Old (Unread but seen).
** .dt 9 .dd n .dd The mail thread is New (Unread but not seen).
** .dt 10 .dd - .dd The mail is read - %S expando.
** .dt 11 .dd <space> .dd The mail is read - %Z expando.
** .de
*/

{ "flag_safe", DT_BOOL, false },
/*
** .pp
** If set, flagged messages can't be deleted.
*/

{ "folder", D_STRING_MAILBOX, "~/Mail" },
/*
** .pp
** Specifies the default location of your mailboxes.  A "+" or "=" at the
** beginning of a pathname will be expanded to the value of this
** variable.  Note that if you change this variable (from the default)
** value you need to make sure that the assignment occurs \fIbefore\fP
** you use "+" or "=" for any other variables since expansion takes place
** when handling the "$mailboxes" command.
*/

{ "folder_format", DT_STRING, "%2C %t %N %F %2l %-8.8u %-8.8g %8s %d %i" },
/*
** .pp
** This variable allows you to customize the file browser display to your
** personal taste.  This string is similar to $$index_format, but has
** its own set of \fIprintf(3)\fP-like sequences:
** .dl
** .dt %a  .dd   .dd Alert: 1 if user is notified of new mail
** .dt %C  .dd   .dd Current file number
** .dt %d  .dd   .dd Date/time folder was last modified
** .dt %D  .dd   .dd Date/time folder was last modified using $$date_format.
**                   It is encouraged to use "%[fmt]" instead, where "fmt" is
**                   the value of $$date_format.
** .dt %f  .dd   .dd Filename ("/" is appended to directory names,
**                   "@" to symbolic links and "*" to executable files)
** .dt %F  .dd   .dd File permissions
** .dt %g  .dd   .dd Group name (or numeric gid, if missing)
** .dt %i  .dd   .dd Description of the folder
** .dt %l  .dd   .dd Number of hard links
** .dt %m  .dd * .dd Number of messages in the mailbox
** .dt %n  .dd * .dd Number of unread messages in the mailbox
** .dt %N  .dd   .dd "N" if mailbox has new mail, " " (space) otherwise
** .dt %p  .dd   .dd Poll: 1 if Mailbox is checked for new mail
** .dt %s  .dd   .dd Size in bytes (see $formatstrings-size)
** .dt %t  .dd   .dd "*" if the file is tagged, blank otherwise
** .dt %u  .dd   .dd Owner name (or numeric uid, if missing)
** .dt %[fmt] .dd   .dd Date/time folder was last modified using an \fIstrftime(3)\fP expression
** .dt %>X .dd   .dd Right justify the rest of the string and pad with character "X"
** .dt %|X .dd   .dd Pad to the end of the line with character "X"
** .dt %*X .dd   .dd Soft-fill with character "X" as pad
** .de
** .pp
** For an explanation of "soft-fill", see the $$index_format documentation.
** .pp
** * = can be optionally printed if nonzero
** .pp
** %m, %n, and %N only work for monitored mailboxes.
** %m requires $$mail_check_stats to be set.
** %n requires $$mail_check_stats to be set (except for IMAP mailboxes).
*/

{ "followup_to", DT_BOOL, true },
/*
** .pp
** Controls whether or not the "Mail-Followup-To:" header field is
** generated when sending mail.  When \fIset\fP, NeoMutt will generate this
** field when you are replying to a known mailing list, specified with
** the "$subscribe" or "$lists" commands.
** .pp
** This field has two purposes.  First, preventing you from
** receiving duplicate copies of replies to messages which you send
** to mailing lists, and second, ensuring that you do get a reply
** separately for any messages sent to known lists to which you are
** not subscribed.
** .pp
** The header will contain only the list's address
** for subscribed lists, and both the list address and your own
** email address for unsubscribed lists.  Without this header, a
** group reply to your message sent to a subscribed list will be
** sent to both the list and your address, resulting in two copies
** of the same email for you.
*/

{ "followup_to_poster", DT_QUAD, MUTT_ASKYES },
/*
** .pp
** If this variable is \fIset\fP and the keyword "poster" is present in
** \fIFollowup-To\fP header, follow-up to newsgroup function is not
** permitted.  The message will be mailed to the submitter of the
** message via mail.
*/

{ "force_name", DT_BOOL, false },
/*
** .pp
** This variable is similar to $$save_name, except that NeoMutt will
** store a copy of your outgoing message by the username of the address
** you are sending to even if that mailbox does not exist.
** .pp
** Also see the $$record variable.
*/

{ "forward_attachments", DT_QUAD, MUTT_ASKYES },
/*
** .pp
** When forwarding inline (i.e. $$mime_forward \fIunset\fP or
** answered with "no" and $$forward_decode \fIset\fP), attachments
** which cannot be decoded in a reasonable manner will be attached
** to the newly composed message if this quadoption is \fIset\fP or
** answered with "yes".
*/

{ "forward_attribution_intro", DT_STRING, "----- Forwarded message from %f -----" },
/*
** .pp
** This is the string that will precede a message which has been forwarded
** in the main body of a message (when $$mime_forward is unset).
** For a full listing of defined \fIprintf(3)\fP-like sequences see
** the section on $$index_format.  See also $$attribution_locale.
*/

{ "forward_attribution_trailer", DT_STRING, "----- End forwarded message -----" },
/*
** .pp
** This is the string that will follow a message which has been forwarded
** in the main body of a message (when $$mime_forward is unset).
** For a full listing of defined \fIprintf(3)\fP-like sequences see
** the section on $$index_format.  See also $$attribution_locale.
*/

{ "forward_decode", DT_BOOL, true },
/*
** .pp
** Controls the decoding of complex MIME messages into \fItext/plain\fP when
** forwarding a message.  The message header is also RFC2047 decoded.
** This variable is only used, if $$mime_forward is \fIunset\fP,
** otherwise $$mime_forward_decode is used instead.
*/

{ "forward_decrypt", DT_BOOL, true },
/*
** .pp
** Controls the handling of encrypted messages when forwarding a message.
** When \fIset\fP, the outer layer of encryption is stripped off.  This
** variable is only used if $$mime_forward is \fIset\fP and
** $$mime_forward_decode is \fIunset\fP.
*/

{ "forward_edit", DT_QUAD, MUTT_YES },
/*
** .pp
** This quadoption controls whether or not the user is automatically
** placed in the editor when forwarding messages.  For those who always want
** to forward with no modification, use a setting of "no".
*/

{ "forward_format", DT_STRING, "[%a: %s]" },
/*
** .pp
** This variable controls the default subject when forwarding a message.
** It uses the same format sequences as the $$index_format variable.
*/

{ "forward_quote", DT_BOOL, false },
/*
** .pp
** When \fIset\fP, forwarded messages included in the main body of the
** message (when $$mime_forward is \fIunset\fP) will be quoted using
** $$indent_string.
*/

{ "forward_references", DT_BOOL, false },
/*
** .pp
** When \fIset\fP, forwarded messages set the "In-Reply-To:" and
** "References:" headers in the same way as normal replies would. Hence the
** forwarded message becomes part of the original thread instead of starting
** a new one.
*/

{ "from", DT_ADDRESS, 0 },
/*
** .pp
** When \fIset\fP, this variable contains a default "from" address.  It
** can be overridden using "$my_hdr" (including from a "$send-hook") and
** $$reverse_name.  This variable is ignored if $$use_from is \fIunset\fP.
** .pp
** If not specified, then it may be read from the environment variable \fI$$$EMAIL\fP.
*/

{ "from_chars", DT_MBTABLE, 0 },
/*
** .pp
** Controls the character used to prefix the %F and %L fields in the
** index.
** .dl
** .dt \fBCharacter\fP .dd \fBDescription\fP
** .dt 1 .dd Mail is written by you and has a To address, or has a known mailing list in the To address.
** .dt 2 .dd Mail is written by you and has a Cc address, or has a known mailing list in the Cc address.
** .dt 3 .dd Mail is written by you and has a Bcc address.
** .dt 4 .dd All remaining cases.
** .de
** .pp
** If this is empty or unset (default), the traditional long "To ",
** "Cc " and "Bcc " prefixes are used.  If set but too short to
** include a character for a particular case, a single space will be
** prepended to the field.  To prevent any prefix at all from being
** added in a particular case, use the special value CR (aka ^M)
** for the corresponding character.
** .pp
** This slightly odd interface is necessitated by NeoMutt's handling of
** string variables; one can't tell a variable that is unset from one
** that is set to the empty string.
*/

{ "gecos_mask", DT_REGEX, "^[^,]*" },
/*
** .pp
** A regular expression used by NeoMutt to parse the GECOS field of a password
** entry when expanding the alias.  The default value
** will return the string up to the first "," encountered.
** If the GECOS field contains a string like "lastname, firstname" then you
** should set it to "\fI.*\fP".
** .pp
** This can be useful if you see the following behavior: you address an e-mail
** to user ID "stevef" whose full name is "Steve Franklin".  If NeoMutt expands
** "stevef" to '"Franklin" stevef@foo.bar' then you should set the $$gecos_mask to
** a regular expression that will match the whole name so NeoMutt will expand
** "Franklin" to "Franklin, Steve".
*/

{ "greeting", DT_STRING, 0 },
/*
** .pp
** When set, this is the string that will precede every message as a
** greeting phrase to the recipients.
** .pp
** "Format strings" are similar to the strings used in the "C"
** function printf to format output (see the man page for more detail).
** The following sequences are defined in NeoMutt:
** .pp
** .dl
** .dt %n .dd Recipient's real name
** .dt %u .dd User (login) name of recipient
** .dt %v .dd First name of recipient
** .de
*/

{ "group_index_format", DT_STRING, "%4C %M%N %5s  %-45.45f %d" },
/*
** .pp
** This variable allows you to customize the newsgroup browser display to
** your personal taste.  This string is similar to "$index_format", but
** has its own set of printf()-like sequences:
** .dl
** .dt %a  .dd Alert: 1 if user is notified of new mail
** .dt %C  .dd Current newsgroup number
** .dt %d  .dd Description of newsgroup (becomes from server)
** .dt %f  .dd Newsgroup name
** .dt %M  .dd - if newsgroup not allowed for direct post (moderated for example)
** .dt %N  .dd N if newsgroup is new, u if unsubscribed, blank otherwise
** .dt %n  .dd Number of new articles in newsgroup
** .dt %p  .dd Poll: 1 if Mailbox is checked for new mail
** .dt %s  .dd Number of unread articles in newsgroup
** .dt %>X .dd Right justify the rest of the string and pad with character "X"
** .dt %|X .dd Pad to the end of the line with character "X"
** .dt %*X .dd Soft-fill with character "X" as pad
** .de
*/

{ "hdrs", DT_BOOL, true },
/*
** .pp
** When \fIunset\fP, the header fields normally added by the "$my_hdr"
** command are not created.  This variable \fImust\fP be unset before
** composing a new message or replying in order to take effect.  If \fIset\fP,
** the user defined header fields are added to every new message.
*/

{ "header", DT_BOOL, false },
/*
** .pp
** When \fIset\fP, this variable causes NeoMutt to include the header
** of the message you are replying to into the edit buffer.
** The $$weed setting applies.
*/

#ifdef USE_HCACHE
{ "header_cache", DT_PATH, 0 },
/*
** .pp
** This variable points to the header cache database. If the path points to
** an existing directory, NeoMutt will create a dedicated header cache
** database per folder. Otherwise, the path points to a regular file, which
** will be created as needed and used as a shared global header cache for
** all folders.
** By default it is \fIunset\fP so no header caching will be used.
** .pp
** Header caching can greatly improve speed when opening POP, IMAP
** MH or Maildir folders, see "$caching" in the NeoMutt Guide for details.
*/

{ "header_cache_backend", DT_STRING, 0 },
/*
** .pp
** This variable specifies the header cache backend.  If no backend is
** specified, the first available backend will be used in the following order:
** tokyocabinet, kyotocabinet, qdbm, rocksdb, gdbm, bdb, tdb, lmdb.
*/

#ifdef USE_HCACHE_COMPRESSION
{ "header_cache_compress_level", DT_NUMBER, 1 },
/*
** .pp
** When NeoMutt is compiled with lz4, zstd or zlib, this option can be used
** to setup the compression level.
*/

{ "header_cache_compress_method", DT_STRING, 0 },
/*
** .pp
** When NeoMutt is compiled with lz4, zstd or zlib, the header cache backend
** can use these compression methods for compressing the cache files.
** This results in much smaller cache file sizes and may even improve speed.
*/
#endif
#endif

{ "header_color_partial", DT_BOOL, false },
/*
** .pp
** When \fIset\fP, color header regexes behave like color body regexes:
** color is applied to the exact text matched by the regex.  When
** \fIunset\fP, color is applied to the entire header.
** .pp
** One use of this option might be to apply color to just the header labels.
** .pp
** See "$color" for more details.
*/

{ "help", DT_BOOL, true },
/*
** .pp
** When \fIset\fP, help lines describing the bindings for the major functions
** provided by each menu are displayed on the first line of the screen.
** .pp
** \fBNote:\fP The binding will not be displayed correctly if the
** function is bound to a sequence rather than a single keystroke.  Also,
** the help line may not be updated if a binding is changed while NeoMutt is
** running.  Since this variable is primarily aimed at new users, neither
** of these should present a major problem.
*/

{ "hidden_host", DT_BOOL, false },
/*
** .pp
** When \fIset\fP, NeoMutt will skip the host name part of $$hostname variable
** when adding the domain part to addresses.
*/

{ "hidden_tags", DT_SLIST, "unread,draft,flagged,passed,replied,attachment,signed,encrypted" },
/*
** .pp
** This variable specifies a list of comma-separated private notmuch/imap tags
** which should not be printed on screen.
*/

{ "hide_limited", DT_BOOL, false },
/*
** .pp
** When \fIset\fP, NeoMutt will not show the presence of messages that are hidden
** by limiting, in the thread tree.
*/

{ "hide_missing", DT_BOOL, true },
/*
** .pp
** When \fIset\fP, NeoMutt will not show the presence of missing messages in the
** thread tree.
*/

{ "hide_thread_subject", DT_BOOL, true },
/*
** .pp
** When \fIset\fP, NeoMutt will not show the subject of messages in the thread
** tree that have the same subject as their parent or closest previously
** displayed sibling.
*/

{ "hide_top_limited", DT_BOOL, false },
/*
** .pp
** When \fIset\fP, NeoMutt will not show the presence of messages that are hidden
** by limiting, at the top of threads in the thread tree.  Note that when
** $$hide_limited is \fIset\fP, this option will have no effect.
*/

{ "hide_top_missing", DT_BOOL, true },
/*
** .pp
** When \fIset\fP, NeoMutt will not show the presence of missing messages at the
** top of threads in the thread tree.  Note that when $$hide_missing is
** \fIset\fP, this option will have no effect.
*/

{ "history", DT_NUMBER, 10 },
/*
** .pp
** This variable controls the size (in number of strings remembered) of
** the string history buffer per category. The buffer is cleared each time the
** variable is set.
** .pp
** Note that strings (e.g. commands) starting with a space are never recorded
** in the history.  This is for example useful to prevent leaking sensitive
** information into the history file or for one off tests.
** .pp
** Also note that a string is not added to the history if it exactly matches
** its immediate predecessor, e.g. executing the same command twice in a row
** results in only one copy being added to the history.  To prevent duplicates
** over all entries use $$history_remove_dups.
*/

{ "history_file", DT_PATH, "~/.mutthistory" },
/*
** .pp
** The file in which NeoMutt will save its history.
** .pp
** Also see $$save_history.
*/

{ "history_format", DT_STRING, "%s" },
/*
** .pp
** Controls the format of the entries of the history list.
** This string is similar to $$index_format, but has its own
** set of \fIprintf(3)\fP-like sequences:
** .dl
** .dt %C  .dd Line number
** .dt %s  .dd History match
** .dt %>X .dd right justify the rest of the string and pad with character "X"
** .dt %|X .dd pad to the end of the line with character "X"
** .dt %*X .dd soft-fill with character "X" as pad
** .de
*/

{ "history_remove_dups", DT_BOOL, false },
/*
** .pp
** When \fIset\fP, all of the string history will be scanned for duplicates
** when a new entry is added.  Duplicate entries in the $$history_file will
** also be removed when it is periodically compacted.
*/

{ "honor_disposition", DT_BOOL, false },
/*
** .pp
** When \fIset\fP, NeoMutt will not display attachments with a
** disposition of "attachment" inline even if it could
** render the part to plain text. These MIME parts can only
** be viewed from the attachment menu.
** .pp
** If \fIunset\fP, NeoMutt will render all MIME parts it can
** properly transform to plain text.
*/

{ "honor_followup_to", DT_QUAD, MUTT_YES },
/*
** .pp
** This variable controls whether or not a Mail-Followup-To header is
** honored when group-replying to a message.
*/

{ "hostname", DT_STRING, 0 },
/*
** .pp
** Specifies the fully-qualified hostname of the system NeoMutt is running on
** containing the host's name and the DNS domain it belongs to. It is used
** as the domain part (after "@") for local email addresses.
** .pp
** If not specified in a config file, then NeoMutt will try to determine the hostname itself.
** .pp
** Optionally, NeoMutt can be compiled with a fixed domain name.
** .pp
** Also see $$use_domain and $$hidden_host.
*/

#ifdef HAVE_LIBIDN
{ "idn_decode", DT_BOOL, true },
/*
** .pp
** When \fIset\fP, NeoMutt will show you international domain names decoded.
** Note: You can use IDNs for addresses even if this is \fIunset\fP.
** This variable only affects decoding. (IDN only)
*/

{ "idn_encode", DT_BOOL, true },
/*
** .pp
** When \fIset\fP, NeoMutt will encode international domain names using
** IDN.  Unset this if your SMTP server can handle newer (RFC6531)
** UTF-8 encoded domains. (IDN only)
*/
#endif

{ "ignore_list_reply_to", DT_BOOL, false },
/*
** .pp
** Affects the behavior of the \fI<reply>\fP function when replying to
** messages from mailing lists (as defined by the "$subscribe" or
** "$lists" commands).  When \fIset\fP, if the "Reply-To:" field is
** set to the same value as the "To:" field, NeoMutt assumes that the
** "Reply-To:" field was set by the mailing list to automate responses
** to the list, and will ignore this field.  To direct a response to the
** mailing list when this option is \fIset\fP, use the \fI$<list-reply>\fP
** function; \fI<group-reply>\fP will reply to both the sender and the
** list.
*/

{ "imap_authenticators", DT_SLIST, 0 },
/*
** .pp
** This is a colon-separated list of authentication methods NeoMutt may
** attempt to use to log in to an IMAP server, in the order NeoMutt should
** try them.  Authentication methods are either "login" or the right
** side of an IMAP "AUTH=xxx" capability string, e.g. "digest-md5", "gssapi"
** or "cram-md5". This option is case-insensitive. If it's
** \fIunset\fP (the default) NeoMutt will try all available methods,
** in order from most-secure to least-secure.
** .pp
** Example:
** .ts
** set imap_authenticators="gssapi:cram-md5:login"
** .te
** .pp
** \fBNote:\fP NeoMutt will only fall back to other authentication methods if
** the previous methods are unavailable. If a method is available but
** authentication fails, NeoMutt will not connect to the IMAP server.
*/

{ "imap_check_subscribed", DT_BOOL, false },
/*
** .pp
** When \fIset\fP, NeoMutt will fetch the set of subscribed folders from
** your server whenever a mailbox is \fBselected\fP, and add them to the set
** of mailboxes it polls for new mail just as if you had issued individual
** "$mailboxes" commands.
*/

{ "imap_condstore", DT_BOOL, false },
/*
** .pp
** When \fIset\fP, NeoMutt will use the CONDSTORE extension (RFC7162)
** if advertised by the server.  NeoMutt's current implementation is basic,
** used only for initial message fetching and flag updates.
** .pp
** For some IMAP servers, enabling this will slightly speed up
** downloading initial messages.  Unfortunately, Gmail is not one
** those, and displays worse performance when enabled.  Your
** mileage may vary.
*/

#ifdef USE_ZLIB
{ "imap_deflate", DT_BOOL, true },
/*
** .pp
** When \fIset\fP, NeoMutt will use the COMPRESS=DEFLATE extension (RFC4978)
** if advertised by the server.
** .pp
** In general a good compression efficiency can be achieved, which
** speeds up reading large mailboxes also on fairly good connections.
*/
#endif

{ "imap_delim_chars", DT_STRING, "/." },
/*
** .pp
** This contains the list of characters that NeoMutt will use as folder
** separators for IMAP paths, when no separator is provided on the IMAP
** connection.
*/

{ "imap_fetch_chunk_size", DT_LONG, 0 },
/*
** .pp
** When set to a value greater than 0, new headers will be
** downloaded in groups of this many headers per request.  If you
** have a very large mailbox, this might prevent a timeout and
** disconnect when opening the mailbox, by sending a FETCH per set
** of this many headers, instead of a single FETCH for all new
** headers.
*/

{ "imap_headers", DT_STRING, 0 },
/*
** .pp
** NeoMutt requests these header fields in addition to the default headers
** ("Date:", "From:", "Sender:", "Subject:", "To:", "Cc:", "Message-Id:",
** "References:", "Content-Type:", "Content-Description:", "In-Reply-To:",
** "Reply-To:", "Lines:", "List-Post:", "X-Label:") from IMAP
** servers before displaying the index menu. You may want to add more
** headers for spam detection.
** .pp
** \fBNote:\fP This is a space separated list, items should be uppercase
** and not contain the colon, e.g. "X-BOGOSITY X-SPAM-STATUS" for the
** "X-Bogosity:" and "X-Spam-Status:" header fields.
*/

{ "imap_idle", DT_BOOL, false },
/*
** .pp
** When \fIset\fP, NeoMutt will attempt to use the IMAP IDLE extension
** to check for new mail in the current mailbox. Some servers
** (dovecot was the inspiration for this option) react badly
** to NeoMutt's implementation. If your connection seems to freeze
** up periodically, try unsetting this.
*/

{ "imap_keep_alive", DT_NUMBER, 300 },
/*
** .pp
** This variable specifies the maximum amount of time in seconds that NeoMutt
** will wait before polling open IMAP connections, to prevent the server
** from closing them before NeoMutt has finished with them. The default is
** well within the RFC-specified minimum amount of time (30 minutes) before
** a server is allowed to do this, but in practice the RFC does get
** violated every now and then. Reduce this number if you find yourself
** getting disconnected from your IMAP server due to inactivity.
*/

{ "imap_list_subscribed", DT_BOOL, false },
/*
** .pp
** This variable configures whether IMAP folder browsing will look for
** only subscribed folders or all folders.  This can be toggled in the
** IMAP browser with the \fI<toggle-subscribed>\fP function.
*/

{ "imap_login", DT_STRING, 0 },
/*
** .pp
** Your login name on the IMAP server.
** .pp
** This variable defaults to the value of $$imap_user.
*/

{ "imap_oauth_refresh_command", D_STRING_COMMAND, 0 },
/*
** .pp
** The command to run to generate an OAUTH refresh token for
** authorizing your connection to your IMAP server.  This command will be
** run on every connection attempt that uses the OAUTHBEARER or XOAUTH2
** authentication mechanisms.  See "$oauth" for details.
*/

{ "imap_pass", DT_STRING, 0 },
/*
** .pp
** Specifies the password for your IMAP account.  If \fIunset\fP, NeoMutt will
** prompt you for your password when you invoke the \fI<imap-fetch-mail>\fP function
** or try to open an IMAP folder.
** .pp
** \fBWarning\fP: you should only use this option when you are on a
** fairly secure machine, because the superuser can read your neomuttrc even
** if you are the only one who can read the file.
*/

{ "imap_passive", DT_BOOL, true },
/*
** .pp
** When \fIset\fP, NeoMutt will not open new IMAP connections to check for new
** mail.  NeoMutt will only check for new mail over existing IMAP
** connections.  This is useful if you don't want to be prompted for
** user/password pairs on NeoMutt invocation, or if opening the connection
** is slow.
*/

{ "imap_peek", DT_BOOL, true },
/*
** .pp
** When \fIset\fP, NeoMutt will avoid implicitly marking your mail as read whenever
** you fetch a message from the server. This is generally a good thing,
** but can make closing an IMAP folder somewhat slower. This option
** exists to appease speed freaks.
*/

{ "imap_pipeline_depth", DT_NUMBER, 15 },
/*
** .pp
** Controls the number of IMAP commands that may be queued up before they
** are sent to the server. A deeper pipeline reduces the amount of time
** NeoMutt must wait for the server, and can make IMAP servers feel much
** more responsive. But not all servers correctly handle pipelined commands,
** so if you have problems you might want to try setting this variable to 0.
** .pp
** \fBNote:\fP Changes to this variable have no effect on open connections.
*/

{ "imap_poll_timeout", DT_NUMBER, 15 },
/*
** .pp
** This variable specifies the maximum amount of time in seconds
** that NeoMutt will wait for a response when polling IMAP connections
** for new mail, before timing out and closing the connection.  Set
** to 0 to disable timing out.
*/

{ "imap_qresync", DT_BOOL, false },
/*
** .pp
** When \fIset\fP, NeoMutt will use the QRESYNC extension (RFC7162)
** if advertised by the server.  NeoMutt's current implementation is basic,
** used only for initial message fetching and flag updates.
** .pp
** Note: this feature is currently experimental.  If you experience
** strange behavior, such as duplicate or missing messages please
** file a bug report to let us know.
*/

{ "imap_rfc5161", DT_BOOL, true },
/*
** .pp
** When \fIset\fP, NeoMutt will use the IMAP ENABLE extension (RFC5161) to
** select CAPABILITIES. Some servers (notably Coremail System IMap Server) do
** not properly respond to ENABLE commands, which might cause NeoMutt to hang.
** If your connection seems to freeze at login, try unsetting this. See also
** https://github.com/neomutt/neomutt/issues/1689
*/

{ "imap_send_id", DT_BOOL, false },
/*
** .pp
** When \fIset\fP, NeoMutt will send an IMAP ID command (RFC2971) to the
** server when logging in if advertised by the server. This command provides
** information about the IMAP client, such as "NeoMutt" and the current version.
*/

{ "imap_server_noise", DT_BOOL, true },
/*
** .pp
** When \fIset\fP, NeoMutt will display warning messages from the IMAP
** server as error messages. Since these messages are often
** harmless, or generated due to configuration problems on the
** server which are out of the users' hands, you may wish to suppress
** them at some point.
*/

{ "imap_user", DT_STRING, 0 },
/*
** .pp
** The name of the user whose mail you intend to access on the IMAP
** server.
** .pp
** This variable defaults to your user name on the local machine.
*/

{ "implicit_auto_view", DT_BOOL, false },
/*
** .pp
** If set to "yes", NeoMutt will look for a mailcap entry with the
** "\fIcopiousoutput\fP" flag set for \fIevery\fP MIME attachment it doesn't have
** an internal viewer defined for.  If such an entry is found, NeoMutt will
** use the viewer defined in that entry to convert the body part to text
** form.
*/

{ "include", DT_QUAD, MUTT_ASKYES },
/*
** .pp
** Controls whether or not a copy of the message(s) you are replying to
** is included in your reply.
*/

{ "include_encrypted", DT_BOOL, false },
/*
** .pp
** Controls whether or not NeoMutt includes separately encrypted attachment
** contents when replying.
** .pp
** This variable was added to prevent accidental exposure of encrypted
** contents when replying to an attacker.  If a previously encrypted message
** were attached by the attacker, they could trick an unwary recipient into
** decrypting and including the message in their reply.
*/

{ "include_only_first", DT_BOOL, false },
/*
** .pp
** Controls whether or not NeoMutt includes only the first attachment
** of the message you are replying.
*/

{ "indent_string", DT_STRING, "> " },
/*
** .pp
** Specifies the string to prepend to each line of text quoted in a
** message to which you are replying.  You are strongly encouraged not to
** change this value, as it tends to agitate the more fanatical netizens.
** .pp
** The value of this option is ignored if $$text_flowed is set, because
** the quoting mechanism is strictly defined for format=flowed.
** .pp
** This option is a format string, please see the description of
** $$index_format for supported \fIprintf(3)\fP-style sequences.
*/

{ "index_format", DT_STRING, "%4C %Z %{%b %d} %-15.15L (%<l?%4l&%4c>) %s" },
/*
** .pp
** This variable allows you to customize the message index display to
** your personal taste.
** .pp
** "Format strings" are similar to the strings used in the C
** function \fIprintf(3)\fP to format output (see the man page for more details).
** For an explanation of the %<...> construct, see the $status_format description.
** The following sequences are defined in NeoMutt:
** .dl
** .dt %a .dd Address of the author
** .dt %A .dd Reply-to address (if present; otherwise: address of author)
** .dt %b .dd Filename of the original message folder (think mailbox)
** .dt %B .dd Same as %K
** .dt %c .dd Number of characters (bytes) in the body of the message (see $formatstrings-size)
** .dt %C .dd Current message number
** .dt %cr .dd Number of characters (bytes) in the raw message, including the header (see $formatstrings-size)
** .dt %d .dd Date and time of message using $date_format and sender's timezone
**            It is encouraged to use "%{fmt}" instead, where "fmt" is the value of $$date_format.
** .dt %D .dd Date and time of message using $date_format and local timezone
**            It is encouraged to use "%[fmt]" instead, where "fmt" is the value of $$date_format.
** .dt %e .dd Current message number in thread
** .dt %E .dd Number of messages in current thread
** .dt %f .dd Sender (address + real name), either From: or Return-Path:
** .dt %F .dd Author name, or recipient name if the message is from you
** .dt %Fp .dd Like %F, but plain. No contextual formatting is applied to recipient name
** .dt %g .dd Message tags (e.g. notmuch tags/imap flags)
** .dt %Gx .dd Individual message tag (e.g. notmuch tags/imap flags)
** .dt %H .dd Spam attribute(s) of this message
** .dt %i .dd Message-id of the current message
** .dt %I .dd Initials of author
** .dt %J .dd Message tags (if present, tree unfolded, and != parent's tags)
** .dt %K .dd The list to which the letter was sent (if any; otherwise: empty)
** .dt %l .dd number of lines in the unprocessed message (may not work with
**            maildir, mh, and IMAP folders)
** .dt %L .dd If an address in the "To:" or "Cc:" header field matches an address
**            Defined by the user's "$subscribe" command, this displays
**            "To <list-name>", otherwise the same as %F
** .dt %m .dd Total number of message in the mailbox
** .dt %M .dd Number of hidden messages if the thread is collapsed
** .dt %n .dd Author's real name (or address if missing)
** .dt %N .dd Message score
** .dt %O .dd Original save folder where NeoMutt would formerly have
**            Stashed the message: list name or recipient name
**            If not sent to a list
** .dt %P .dd Progress indicator for the built-in pager (how much of the file has been displayed)
** .dt %q .dd Newsgroup name (if compiled with NNTP support)
** .dt %r .dd Comma separated list of "To:" recipients
** .dt %R .dd Comma separated list of "Cc:" recipients
** .dt %s .dd Subject of the message
** .dt %S .dd Single character status of the message ("N"/"O"/"D"/"d"/"!"/"r"/"\(as")
** .dt %t .dd "To:" field (recipients)
** .dt %T .dd The appropriate character from the $$to_chars string
** .dt %u .dd User (login) name of the author
** .dt %v .dd First name of the author, or the recipient if the message is from you
** .dt %W .dd Name of organization of author ("Organization:" field)
** .dt %x .dd "X-Comment-To:" field (if present and compiled with NNTP support)
** .dt %X .dd Number of MIME attachments
**            (please see the "$attachments" section for possible speed effects)
** .dt %y .dd "X-Label:" field, if present
** .dt %Y .dd "X-Label:" field, if present, and \fI(1)\fP not at part of a thread tree,
**            \fI(2)\fP at the top of a thread, or \fI(3)\fP "X-Label:" is different from
**            Preceding message's "X-Label:"
** .dt %Z .dd A three character set of message status flags.
**            The first character is new/read/replied flags ("n"/"o"/"r"/"O"/"N").
**            The second is deleted or encryption flags ("D"/"d"/"S"/"P"/"s"/"K").
**            The third is either tagged/flagged ("\(as"/"!"), or one of the characters
**            Listed in $$to_chars.
** .dt %zc .dd Message crypto flags
** .dt %zs .dd Message status flags
** .dt %zt .dd Message tag flags
** .dt %@name@ .dd insert and evaluate format-string from the matching
**                 "$index-format-hook" command
** .dt %{fmt} .dd the date and time of the message is converted to sender's
**                time zone, and "fmt" is expanded by the library function
**                \fIstrftime(3)\fP; if the first character inside the braces
**                is a bang ("!"), the date is formatted ignoring any locale
**                settings.  Note that the sender's time zone might only be
**                available as a numerical offset, so "%Z" behaves like "%z".
**                %{fmt} behaves like %[fmt] on systems where struct tm
**                doesn't have a tm_gmtoff member.
** .dt %[fmt] .dd the date and time of the message is converted to the local
**                time zone, and "fmt" is expanded by the library function
**                \fIstrftime(3)\fP; if the first character inside the brackets
**                is a bang ("!"), the date is formatted ignoring any locale settings.
** .dt %(fmt) .dd the local date and time when the message was received, and
**                "fmt" is expanded by the library function \fIstrftime(3)\fP;
**                if the first character inside the parentheses is a bang ("!"),
**                the date is formatted ignoring any locale settings.
** .dt %>X    .dd right justify the rest of the string and pad with character "X"
** .dt %|X    .dd pad to the end of the line with character "X"
** .dt %*X    .dd soft-fill with character "X" as pad
** .de
** .pp
** Date format expressions can be constructed based on relative dates. Using
** the date formatting operators along with nested conditionals, the date
** format can be modified based on how old a message is.  See the section on
** "Conditional Dates" for an explanation and examples
** .pp
** Note that for mbox/mmdf, "%l" applies to the unprocessed message, and
** for maildir/mh, the value comes from the "Lines:" header field when
** present (the meaning is normally the same). Thus the value depends on
** the encodings used in the different parts of the message and has little
** meaning in practice.
** .pp
** "Soft-fill" deserves some explanation: Normal right-justification
** will print everything to the left of the "%>", displaying padding and
** whatever lies to the right only if there's room. By contrast,
** soft-fill gives priority to the right-hand side, guaranteeing space
** to display it and showing padding only if there's still room. If
** necessary, soft-fill will eat text leftwards to make room for
** rightward text.
** .pp
** Note that these expandos are supported in
** "$save-hook", "$fcc-hook" and "$fcc-save-hook", too.
*/

{ "inews", D_STRING_COMMAND, 0 },
/*
** .pp
** If set, specifies the program and arguments used to deliver news posted
** by NeoMutt.  Otherwise, NeoMutt posts article using current connection to
** news server.  The following printf-style sequence is understood:
** .dl
** .dt %a .dd account url
** .dt %p .dd port
** .dt %P .dd port if specified
** .dt %s .dd news server name
** .dt %S .dd url schema
** .dt %u .dd username
** .de
** .pp
** Example:
** .ts
** set inews="/usr/local/bin/inews -hS"
** .te
*/

{ "ispell", D_STRING_COMMAND, ISPELL },
/*
** .pp
** How to invoke ispell (GNU's spell-checking software).
*/

{ "keep_flagged", DT_BOOL, false },
/*
** .pp
** If \fIset\fP, read messages marked as flagged will not be moved
** from your spool mailbox to your $$mbox mailbox or to the "mbox"
** specified by a $mbox-hook command.
** .pp
** Note that $$keep_flagged only has an effect if $$move is set.
*/

{ "local_date_header", DT_BOOL, true },
/*
** .pp
** If \fIset\fP, the date in the Date header of emails that you send will be in
** your local timezone. If unset a UTC date will be used instead to avoid
** leaking information about your current location.
*/

{ "mail_check", DT_NUMBER, 5 },
/*
** .pp
** This variable configures how often (in seconds) NeoMutt should look for
** new mail. Also see the $$timeout variable.
*/

{ "mail_check_recent", DT_BOOL, true },
/*
** .pp
** When \fIset\fP, NeoMutt will only notify you about new mail that has been received
** since the last time you opened the mailbox.  When \fIunset\fP, NeoMutt will notify you
** if any new mail exists in the mailbox, regardless of whether you have visited it
** recently.
*/

{ "mail_check_stats", DT_BOOL, false },
/*
** .pp
** When \fIset\fP, NeoMutt will periodically calculate message
** statistics of a mailbox while polling for new mail.  It will
** check for unread, flagged, and total message counts.
** (Note: IMAP mailboxes only support unread and total counts).
** .pp
** Because this operation is more performance intensive, it defaults
** to \fIunset\fP, and has a separate option,
** $$mail_check_stats_interval, to control how often to update these
** counts.
** .pp
** Message statistics can also be explicitly calculated by invoking the
** \fI<check-stats>\fP function.
*/

{ "mail_check_stats_interval", DT_NUMBER, 60 },
/*
** .pp
** When $$mail_check_stats is \fIset\fP, this variable configures
** how often (in seconds) NeoMutt will update message counts.
*/

{ "mailbox_folder_format", DT_STRING, "%2C %<n?%6n&      > %6m %i" },
/*
** .pp
** This variable allows you to customize the file browser display to your
** personal taste. It's only used to customize network mailboxes (e.g. imap).
** This string is identical in formatting to the one used by
** "$$folder_format".
*/

{ "mailcap_path", DT_SLIST, "~/.mailcap:" PKGDATADIR "/mailcap:" SYSCONFDIR "/mailcap:/etc/mailcap:/usr/etc/mailcap:/usr/local/etc/mailcap" },
/*
** .pp
** This variable specifies a list of colon-separated files to consult when
** attempting to display MIME bodies not directly supported by NeoMutt.  The
** default value is generated during startup: see the "$mailcap" section of the
** manual.
** .pp
** $$mailcap_path is overridden by the environment variable \fI$$$MAILCAPS\fP.
** .pp
** The default search path is from RFC1524.
*/

{ "mailcap_sanitize", DT_BOOL, true },
/*
** .pp
** If \fIset\fP, NeoMutt will restrict possible characters in mailcap % expandos
** to a well-defined set of safe characters.  This is the safe setting,
** but we are not sure it doesn't break some more advanced MIME stuff.
** .pp
** \fBDON'T CHANGE THIS SETTING UNLESS YOU ARE REALLY SURE WHAT YOU ARE
** DOING!\fP
*/

{ "maildir_check_cur", DT_BOOL, false },
/*
** .pp
** If \fIset\fP, NeoMutt will poll both the new and cur directories of
** a maildir folder for new messages.  This might be useful if other
** programs interacting with the folder (e.g. dovecot) are moving new
** messages to the cur directory.  Note that setting this option may
** slow down polling for new messages in large folders, since NeoMutt has
** to scan all cur messages.
*/

{ "maildir_field_delimiter", DT_STRING, ":" },
/*
** .pp
** Use the value as maildir field delimiter. This is a single-character used to
** accommodate maildir mailboxes on platforms where `:` is not allowed
** in a filename. The recommended alternative on such platforms is `;`.
** Neomutt supports all non-alphanumeric values except for `-`, `.`, `\`, `/`.
** \fBNote:\fP this only applies to maildir-style mailboxes. Setting
** it will have no effect on other mailbox types.
*/

#ifdef USE_HCACHE
{ "maildir_header_cache_verify", DT_BOOL, true },
/*
** .pp
** Check for Maildir unaware programs other than NeoMutt having modified maildir
** files when the header cache is in use.  This incurs one \fIstat(2)\fP per
** message every time the folder is opened (which can be very slow for NFS
** folders).
*/
#endif

{ "maildir_trash", DT_BOOL, false },
/*
** .pp
** If \fIset\fP, messages marked as deleted will be saved with the maildir
** trashed flag instead of unlinked.  \fBNote:\fP this only applies
** to maildir-style mailboxes.  Setting it will have no effect on other
** mailbox types.
*/

{ "mark_macro_prefix", DT_STRING, "'" },
/*
** .pp
** Prefix for macros created using mark-message.  A new macro
** automatically generated with \fI<mark-message>a\fP will be composed
** from this prefix and the letter \fIa\fP.
*/

{ "mark_old", DT_BOOL, true },
/*
** .pp
** Controls whether or not NeoMutt marks \fInew\fP \fBunread\fP
** messages as \fIold\fP if you exit a mailbox without reading them.
** With this option \fIset\fP, the next time you start NeoMutt, the messages
** will show up with an "O" next to them in the index menu,
** indicating that they are old.
*/

{ "markers", DT_BOOL, true },
/*
** .pp
** Controls the display of wrapped lines in the internal pager. If set, a
** "+" marker is displayed at the beginning of wrapped lines.
** .pp
** Also see the $$smart_wrap variable.
*/

{ "mask", DT_REGEX, "!^\\.[^.]" },
/*
** .pp
** A regular expression used in the file browser, optionally preceded by
** the \fInot\fP operator "!".  Only files whose names match this mask
** will be shown. The match is always case-sensitive.
*/

{ "mbox", D_STRING_MAILBOX, "~/mbox" },
/*
** .pp
** This specifies the folder into which read mail in your $$spool_file
** folder will be appended.
** .pp
** Also see the $$move variable.
*/

{ "mbox_type", DT_ENUM, MUTT_MBOX },
/*
** .pp
** The default mailbox type used when creating new folders. May be any of
** "mbox", "MMDF", "MH" or "Maildir".
** .pp
** This can also be set using the \fI-m\fP command-line option.
*/

{ "me_too", DT_BOOL, false },
/*
** .pp
** If \fIunset\fP, NeoMutt will remove your address (see the "$alternates"
** command) from the list of recipients when replying to a message.
*/

{ "menu_context", DT_NUMBER, 0 },
/*
** .pp
** This variable controls the number of lines of context that are given
** when scrolling through menus. (Similar to $$pager_context.)
*/

{ "menu_move_off", DT_BOOL, true },
/*
** .pp
** When \fIunset\fP, the bottom entry of menus will never scroll up past
** the bottom of the screen, unless there are less entries than lines.
** When \fIset\fP, the bottom entry may move off the bottom.
*/

{ "menu_scroll", DT_BOOL, false },
/*
** .pp
** When \fIset\fP, menus will be scrolled up or down one line when you
** attempt to move across a screen boundary.  If \fIunset\fP, the screen
** is cleared and the next or previous page of the menu is displayed
** (useful for slow links to avoid many redraws).
*/

{ "message_cache_clean", DT_BOOL, false },
/*
** .pp
** If \fIset\fP, NeoMutt will clean out obsolete entries from the message cache when
** the mailbox is synchronized. You probably only want to set it
** every once in a while, since it can be a little slow
** (especially for large folders).
*/

{ "message_cache_dir", DT_PATH, 0 },
/*
** .pp
** Set this to a directory and NeoMutt will cache copies of messages from
** your IMAP and POP servers here. You are free to remove entries at any
** time.
** .pp
** When setting this variable to a directory, NeoMutt needs to fetch every
** remote message only once and can perform regular expression searches
** as fast as for local folders.
** .pp
** Also see the $$message_cache_clean variable.
*/

{ "message_format", DT_STRING, "%s" },
/*
** .pp
** This is the string displayed in the "attachment" menu for
** attachments of type \fImessage/rfc822\fP.  For a full listing of defined
** \fIprintf(3)\fP-like sequences see the section on $$index_format.
*/

{ "meta_key", DT_BOOL, false },
/*
** .pp
** If \fIset\fP, forces NeoMutt to interpret keystrokes with the high bit (bit 8)
** set as if the user had pressed the Esc key and whatever key remains
** after having the high bit removed.  For example, if the key pressed
** has an ASCII value of \fI0xf8\fP, then this is treated as if the user had
** pressed Esc then "x".  This is because the result of removing the
** high bit from \fI0xf8\fP is \fI0x78\fP, which is the ASCII character
** "x".
*/

{ "mh_purge", DT_BOOL, false },
/*
** .pp
** When \fIunset\fP, NeoMutt will mimic mh's behavior and rename deleted messages
** to \fI,<old file name>\fP in mh folders instead of really deleting
** them. This leaves the message on disk but makes programs reading the folder
** ignore it. If the variable is \fIset\fP, the message files will simply be
** deleted.
** .pp
** This option is similar to $$maildir_trash for Maildir folders.
*/

{ "mh_seq_flagged", DT_STRING, "flagged" },
/*
** .pp
** The name of the MH sequence used for flagged messages.
*/

{ "mh_seq_replied", DT_STRING, "replied" },
/*
** .pp
** The name of the MH sequence used to tag replied messages.
*/

{ "mh_seq_unseen", DT_STRING, "unseen" },
/*
** .pp
** The name of the MH sequence used for unseen messages.
*/

{ "mime_forward", DT_QUAD, MUTT_NO },
/*
** .pp
** When \fIset\fP, the message you are forwarding will be attached as a
** separate \fImessage/rfc822\fP MIME part instead of included in the main body of the
** message.  This is useful for forwarding MIME messages so the receiver
** can properly view the message as it was delivered to you. If you like
** to switch between MIME and not MIME from mail to mail, set this
** variable to "ask-no" or "ask-yes".
** .pp
** Also see $$forward_decode and $$mime_forward_decode.
*/

{ "mime_forward_decode", DT_BOOL, false },
/*
** .pp
** Controls the decoding of complex MIME messages into \fItext/plain\fP when
** forwarding a message while $$mime_forward is \fIset\fP. Otherwise
** $$forward_decode is used instead.
*/

{ "mime_forward_rest", DT_QUAD, MUTT_YES },
/*
** .pp
** When forwarding multiple attachments of a MIME message from the attachment
** menu, attachments which can't be decoded in a reasonable manner will
** be attached to the newly composed message if this option is \fIset\fP.
*/

{ "mime_type_query_command", D_STRING_COMMAND, 0 },
/*
** .pp
** This specifies a command to run, to determine the mime type of a
** new attachment when composing a message.  Unless
** $$mime_type_query_first is set, this will only be run if the
** attachment's extension is not found in the mime.types file.
** .pp
** The string may contain a "%s", which will be substituted with the
** attachment filename.  NeoMutt will add quotes around the string substituted
** for "%s" automatically according to shell quoting rules, so you should
** avoid adding your own.  If no "%s" is found in the string, NeoMutt will
** append the attachment filename to the end of the string.
** .pp
** The command should output a single line containing the
** attachment's mime type.
** .pp
** Suggested values are "xdg-mime query filetype" or
** "file -bi".
*/

{ "mime_type_query_first", DT_BOOL, false },
/*
** .pp
** When \fIset\fP, the $$mime_type_query_command will be run before the
** mime.types lookup.
*/

{ "move", DT_QUAD, MUTT_NO },
/*
** .pp
** If this variable is \fIset\fP, then NeoMutt will move read messages
** from your spool mailbox to your $$mbox mailbox or to the "mbox"
** specified by a $mbox-hook command.
** .pp
** See also $$keep_flagged.
*/

{ "narrow_tree", DT_BOOL, false },
/*
** .pp
** This variable, when \fIset\fP, makes the thread tree narrower, allowing
** deeper threads to fit on the screen.
*/

{ "net_inc", DT_NUMBER, 10 },
/*
** .pp
** Operations that expect to transfer a large amount of data over the
** network will update their progress every $$net_inc kilobytes.
** If set to 0, no progress messages will be displayed.
** .pp
** See also $$read_inc, $$write_inc and $$net_inc.
*/

{ "new_mail_command", D_STRING_COMMAND, 0 },
/*
** .pp
** If \fIset\fP, NeoMutt will call this command after a new message is received.
** See the $$status_format documentation for the values that can be formatted
** into this command.
*/

{ "news_cache_dir", DT_PATH, "~/.neomutt" },
/*
** .pp
** This variable pointing to directory where NeoMutt will save cached news
** articles and headers in. If \fIunset\fP, articles and headers will not be
** saved at all and will be reloaded from the server each time.
*/

{ "news_server", DT_STRING, 0 },
/*
** .pp
** This variable specifies domain name or address of NNTP server.
** .pp
** You can also specify username and an alternative port for each news server,
** e.g. \fI[[s]news://][username[:password]@]server[:port]\fP
** .pp
** This option can also be set using the command line option "-g", the
** environment variable \fI$$$NNTPSERVER\fP, or putting the server name in the
** file "/etc/nntpserver".
*/

{ "newsgroups_charset", DT_STRING, "utf-8" },
/*
** .pp
** Character set of newsgroups descriptions.
*/

{ "newsrc", DT_PATH, "~/.newsrc" },
/*
** .pp
** The file, containing info about subscribed newsgroups - names and
** indexes of read articles.  The following printf-style sequence
** is understood:
** .dl
** .dt \fBExpando\fP .dd \fBDescription\fP .dd \fBExample\fP
** .dt %a .dd Account url       .dd \fInews:news.gmane.org\fP
** .dt %p .dd Port              .dd \fI119\fP
** .dt %P .dd Port if specified .dd \fI10119\fP
** .dt %s .dd News server name  .dd \fInews.gmane.org\fP
** .dt %S .dd Url schema        .dd \fInews\fP
** .dt %u .dd Username          .dd \fIusername\fP
** .de
*/

#ifdef USE_NOTMUCH
{ "nm_config_file", DT_PATH, "auto" },
/*
** .pp
** Configuration file for notmuch. Use 'auto' to detect configuration.
*/

{ "nm_config_profile", DT_STRING, 0 },
/*
** .pp
** Configuration profile for notmuch.
*/

{ "nm_db_limit", DT_NUMBER, 0 },
/*
** .pp
** This variable specifies the default limit used in notmuch queries.
*/

{ "nm_default_url", DT_STRING, 0 },
/*
** .pp
** This variable specifies the default Notmuch database in format
** notmuch://<absolute path>.
*/

{ "nm_exclude_tags", DT_STRING, 0 },
/*
** .pp
** The messages tagged with these tags are excluded and not loaded
** from notmuch DB to NeoMutt unless specified explicitly.
*/

{ "nm_flagged_tag", DT_STRING, "flagged" },
/*
** .pp
** This variable specifies notmuch tag which is used for flagged messages. The
** variable is used to count flagged messages in DB and set the flagged flag when
** modifying tags. All other NeoMutt commands use standard (e.g. maildir) flags.
*/

{ "nm_open_timeout", DT_NUMBER, 5 },
/*
** .pp
** This variable specifies the timeout for database open in seconds.
*/

{ "nm_query_type", DT_STRING, "messages" },
/*
** .pp
** This variable specifies the default query type (threads or messages) used in notmuch queries.
*/

{ "nm_query_window_current_position", DT_NUMBER, 0 },
/*
** .pp
** This variable contains the position of the current search for window based vfolder.
*/

{ "nm_query_window_current_search", DT_STRING, 0 },
/*
** .pp
** This variable contains the currently setup notmuch search for window based vfolder.
*/

{ "nm_query_window_duration", DT_NUMBER, 0 },
/*
** .pp
** This variable sets the time duration of a windowed notmuch query.
** Accepted values all non negative integers. A value of 0 disables the feature.
*/

{ "nm_query_window_enable", DT_BOOL, false },
/*
** .pp
** This variable enables windowed notmuch queries even if window duration is 0.
*/

{ "nm_query_window_or_terms", DT_STRING, 0 },
/*
** .pp
** This variable contains additional notmuch search terms for messages to be
** shown regardless of date.
** .pp
** Example:
** .pp
** Using "notmuch://?query=tag:inbox" as the mailbox and "tag:flagged and
** tag:unread" as the or terms, NeoMutt will produce a query window such as:
** .pp
** notmuch://?query=tag:inbox and (date:... or (tag:flagged and tag:unread))
*/

{ "nm_query_window_timebase", DT_STRING, "week" },
/*
** .pp
** This variable sets the time base of a windowed notmuch query.
** Accepted values are 'minute', 'hour', 'day', 'week', 'month', 'year'
*/

{ "nm_record", DT_BOOL, false },
/*
** .pp
** This variable specifies whether, when writing a just-sent message to the
** $$record, the message should also be added to the notmuch DB. Replies inherit
** the notmuch tags from the original message. See $$nm_record_tags for how to
** modify the set of notmuch tags assigned to sent messages written to the
** record.
*/

{ "nm_record_tags", DT_STRING, 0 },
/*
** .pp
** This variable specifies the notmuch tag modifications (addition, removal,
** toggling) applied to messages added to the Neomutt record when $$nm_record is
** true. See the description of the \fI<modify-labels>\fP function for the
** syntax.
*/

{ "nm_replied_tag", DT_STRING, "replied" },
/*
** .pp
** This variable specifies notmuch tag which is used for replied messages. The
** variable is used to set the replied flag when modifying tags. All other NeoMutt
** commands use standard (e.g. maildir) flags.
*/

{ "nm_unread_tag", DT_STRING, "unread" },
/*
** .pp
** This variable specifies notmuch tag which is used for unread messages. The
** variable is used to count unread messages in DB and set the unread flag when
** modifying tags. All other NeoMutt commands use standard (e.g. maildir) flags.
*/
#endif

{ "nntp_authenticators", DT_STRING, 0 },
/*
** .pp
** This is a colon-delimited list of authentication methods NeoMutt may
** attempt to use to log in to a news server, in the order NeoMutt should
** try them.  Authentication methods are either "user" or any
** SASL mechanism, e.g. "digest-md5", "gssapi" or "cram-md5".
** This option is case-insensitive.  If it's \fIunset\fP (the default)
** NeoMutt will try all available methods, in order from most-secure to
** least-secure.
** .pp
** Example:
** .ts
** set nntp_authenticators="digest-md5:user"
** .te
** .pp
** \fBNote:\fP NeoMutt will only fall back to other authentication methods if
** the previous methods are unavailable. If a method is available but
** authentication fails, NeoMutt will not connect to the IMAP server.
*/

{ "nntp_context", DT_LONG, 1000 },
/*
** .pp
** This variable defines number of articles which will be in index when
** newsgroup entered.  If active newsgroup have more articles than this
** number, oldest articles will be ignored.  Also controls how many
** articles headers will be saved in cache when you quit newsgroup.
*/

{ "nntp_listgroup", DT_BOOL, true },
/*
** .pp
** This variable controls whether or not existence of each article is
** checked when newsgroup is entered.
*/

{ "nntp_load_description", DT_BOOL, true },
/*
** .pp
** This variable controls whether or not descriptions for each newsgroup
** must be loaded when newsgroup is added to list (first time list
** loading or new newsgroup adding).
*/

{ "nntp_pass", DT_STRING, 0 },
/*
** .pp
** Your password for NNTP account.
*/

{ "nntp_poll", DT_NUMBER, 60 },
/*
** .pp
** The time in seconds until any operations on newsgroup except post new
** article will cause recheck for new news.  If set to 0, NeoMutt will
** recheck newsgroup on each operation in index (stepping, read article,
** etc.).
*/

{ "nntp_user", DT_STRING, 0 },
/*
** .pp
** Your login name on the NNTP server.  If \fIunset\fP and NNTP server requires
** authentication, NeoMutt will prompt you for your account name when you
** connect to news server.
*/

{ "pager", D_STRING_COMMAND, "" },
/*
** .pp
** This variable specifies which pager you would like to use to view
** messages. When empty, NeoMutt will use the built-in pager, otherwise this
** variable should specify the pathname of the external pager you would
** like to use.
** .pp
** Using an external pager may have some disadvantages: Additional
** keystrokes are necessary because you can't call NeoMutt functions
** directly from the pager, and screen resizes cause lines longer than
** the screen width to be badly formatted in the help menu.
*/

{ "pager_context", DT_NUMBER, 0 },
/*
** .pp
** This variable controls the number of lines of context that are given
** when displaying the next or previous page in the internal pager.  By
** default, NeoMutt will display the line after the last one on the screen
** at the top of the next page (0 lines of context).
** .pp
** This variable also specifies the amount of context given for search
** results. If positive, this many lines will be given before a match,
** if 0, the match will be top-aligned.
*/

{ "pager_format", DT_STRING, "-%Z- %C/%m: %-20.20n   %s%*  -- (%P)" },
/*
** .pp
** This variable controls the format of the one-line message "status"
** displayed before each message in either the internal or an external
** pager.  The valid sequences are listed in the $$index_format
** section.
*/

{ "pager_index_lines", DT_NUMBER, 0 },
/*
** .pp
** Determines the number of lines of a mini-index which is shown when in
** the pager.  The current message, unless near the top or bottom of the
** folder, will be roughly one third of the way down this mini-index,
** giving the reader the context of a few messages before and after the
** message.  This is useful, for example, to determine how many messages
** remain to be read in the current thread.  A value of 0 results in no index
** being shown.
*/

{ "pager_read_delay", DT_NUMBER, 0 },
/*
** .pp
** Determines the number of seconds that must elapse after first
** opening a new message in the pager before that message will be
** marked as read.  A value of 0 results in the message being marked
** read unconditionally; for other values, navigating to another
** message or exiting the pager before the timeout will leave the
** message marked unread.  This setting is ignored if $$pager is set.
*/

{ "pager_skip_quoted_context", DT_NUMBER, 0 },
/*
** .pp
** Determines the number of lines of context to show before the
** unquoted text when using the \fI<skip-quoted>\fP function. When set
** to a positive number at most that many lines of the previous quote
** are displayed. If the previous quote is shorter the whole quote is
** displayed.
** .pp
** The (now deprecated) \fIskip_quoted_offset\fP is an alias for this
** variable, and should no longer be used.
*/

{ "pager_stop", DT_BOOL, false },
/*
** .pp
** When \fIset\fP, the internal-pager will \fBnot\fP move to the next message
** when you are at the end of a message and invoke the \fI<next-page>\fP
** function.
*/

{ "pattern_format", DT_STRING, "%2n %-15e  %d" },
/*
** .pp
** This variable describes the format of the "pattern completion" menu. The
** following \fIprintf(3)\fP-style sequences are understood:
** .dl
** .dt %d  .dd pattern description
** .dt %e  .dd pattern expression
** .dt %n  .dd index number
** .dt %>X .dd right justify the rest of the string and pad with character "X"
** .dt %|X .dd pad to the end of the line with character "X"
** .dt %*X .dd soft-fill with character "X" as pad
** .de
** .pp
*/

{ "pgp_auto_decode", DT_BOOL, false },
/*
** .pp
** If \fIset\fP, NeoMutt will automatically attempt to decrypt traditional PGP
** messages whenever the user performs an operation which ordinarily would
** result in the contents of the message being operated on.  For example,
** if the user displays a pgp-traditional message which has not been manually
** checked with the \fI$<check-traditional-pgp>\fP function, NeoMutt will automatically
** check the message for traditional pgp.
*/

{ "pgp_auto_inline", DT_BOOL, false },
/*
** .pp
** This option controls whether NeoMutt generates old-style inline
** (traditional) PGP encrypted or signed messages under certain
** circumstances.  This can be overridden by use of the pgp menu,
** when inline is not required.  The GPGME backend does not support
** this option.
** .pp
** Note that NeoMutt might automatically use PGP/MIME for messages
** which consist of more than a single MIME part.  NeoMutt can be
** configured to ask before sending PGP/MIME messages when inline
** (traditional) would not work.
** .pp
** Also see the $$pgp_mime_auto variable.
** .pp
** Also note that using the old-style PGP message format is \fBstrongly\fP
** \fBdeprecated\fP.
** (PGP only)
*/

#ifdef CRYPT_BACKEND_CLASSIC_PGP
{ "pgp_check_exit", DT_BOOL, true },
/*
** .pp
** If \fIset\fP, NeoMutt will check the exit code of the PGP subprocess when
** signing or encrypting.  A non-zero exit code means that the
** subprocess failed.
** (PGP only)
*/

{ "pgp_check_gpg_decrypt_status_fd", DT_BOOL, true },
/*
** .pp
** If \fIset\fP, NeoMutt will check the status file descriptor output
** of $$pgp_decrypt_command and $$pgp_decode_command for GnuPG status codes
** indicating successful decryption.  This will check for the presence of
** DECRYPTION_OKAY, absence of DECRYPTION_FAILED, and that all
** PLAINTEXT occurs between the BEGIN_DECRYPTION and END_DECRYPTION
** status codes.
** .pp
** If \fIunset\fP, NeoMutt will instead match the status fd output
** against $$pgp_decryption_okay.
** (PGP only)
*/

{ "pgp_clear_sign_command", D_STRING_COMMAND, 0 },
/*
** .pp
** This format is used to create an old-style "clearsigned" PGP
** message.  Note that the use of this format is \fBstrongly\fP
** \fBdeprecated\fP.
** .pp
** This is a format string, see the $$pgp_decode_command command for
** possible \fIprintf(3)\fP-like sequences.
** Note that in this case, %r expands to the search string, which is a list of
** one or more quoted values such as email address, name, or keyid.
** (PGP only)
*/

{ "pgp_decode_command", D_STRING_COMMAND, 0 },
/*
** .pp
** This format strings specifies a command which is used to decode
** application/pgp attachments.
** .pp
** The PGP command formats have their own set of \fIprintf(3)\fP-like sequences:
** .dl
** .dt %a .dd The value of $$pgp_sign_as if set, otherwise the value
**            of $$pgp_default_key.
** .dt %f .dd Expands to the name of a file containing a message.
** .dt %p .dd Expands to PGPPASSFD=0 when a pass phrase is needed, to an empty
**            string otherwise. Note: This may be used with a %<...> construct.
** .dt %r .dd One or more key IDs (or fingerprints if available).
** .dt %s .dd Expands to the name of a file containing the signature part
**            of a \fImultipart/signed\fP attachment when verifying it.
** .de
** .pp
** (PGP only)
*/

{ "pgp_decrypt_command", D_STRING_COMMAND, 0 },
/*
** .pp
** This command is used to decrypt a PGP encrypted message.
** .pp
** This is a format string, see the $$pgp_decode_command command for
** possible \fIprintf(3)\fP-like sequences.
** (PGP only)
** .pp
** Note: When decrypting messages using \fIgpg\fP, a pinentry program needs to
** be invoked unless the password is cached within \fIgpg-agent\fP.
** Currently, the \fIpinentry-tty\fP program (usually distributed with
** \fIgpg\fP) isn't suitable for being invoked by NeoMutt.  You are encouraged
** to use a different pinentry-program when running NeoMutt in order to avoid
** problems.
** .pp
** See also: https://github.com/neomutt/neomutt/issues/1014
*/

{ "pgp_decryption_okay", DT_REGEX, 0 },
/*
** .pp
** If you assign text to this variable, then an encrypted PGP
** message is only considered successfully decrypted if the output
** from $$pgp_decrypt_command contains the text.  This is used to
** protect against a spoofed encrypted message, with multipart/encrypted
** headers but containing a block that is not actually encrypted.
** (e.g. simply signed and ascii armored text).
** .pp
** Note that if $$pgp_check_gpg_decrypt_status_fd is set, this variable
** is ignored.
** (PGP only)
*/
#endif

{ "pgp_default_key", DT_STRING, 0 },
/*
** .pp
** This is the default key-pair to use for PGP operations.  It will be
** used for encryption (see $$postpone_encrypt and $$pgp_self_encrypt).
** .pp
** It will also be used for signing unless $$pgp_sign_as is set.
** .pp
** The (now deprecated) \fIpgp_self_encrypt_as\fP is an alias for this
** variable, and should no longer be used.
** (PGP only)
*/

#ifdef CRYPT_BACKEND_CLASSIC_PGP
{ "pgp_encrypt_only_command", D_STRING_COMMAND, 0 },
/*
** .pp
** This command is used to encrypt a body part without signing it.
** .pp
** This is a format string, see the $$pgp_decode_command command for
** possible \fIprintf(3)\fP-like sequences.
** Note that in this case, %r expands to the search string, which is a list of
** one or more quoted values such as email address, name, or keyid.
** (PGP only)
*/

{ "pgp_encrypt_sign_command", D_STRING_COMMAND, 0 },
/*
** .pp
** This command is used to both sign and encrypt a body part.
** .pp
** This is a format string, see the $$pgp_decode_command command for
** possible \fIprintf(3)\fP-like sequences.
** (PGP only)
*/
#endif

{ "pgp_entry_format", DT_STRING, "%4n %t%f %4l/0x%k %-4a %2c %u" },
/*
** .pp
** This variable allows you to customize the PGP key selection menu to
** your personal taste. If $$crypt_use_gpgme is \fIset\fP, then it applies
** to S/MIME key selection menu also. This string is similar to $$index_format,
** but has its own set of \fIprintf(3)\fP-like sequences:
** .dl
** .dt %a     .dd Algorithm
** .dt %c     .dd Capabilities
** .dt %f     .dd Flags
** .dt %i     .dd Key fingerprint (or long key id if non-existent)
** .dt %k     .dd Key id
** .dt %l     .dd Key length
** .dt %n     .dd Number
** .dt %p     .dd Protocol
** .dt %t     .dd Trust/validity of the key-uid association
** .dt %u     .dd User id
** .dt %[<s>] .dd Date of the key where <s> is an \fIstrftime(3)\fP expression
** .dt %>X    .dd Right justify the rest of the string and pad with character "X"
** .dt %|X    .dd Pad to the end of the line with character "X"
** .dt %*X    .dd Soft-fill with character "X" as pad
** .de
** .pp
** See the section "Sending Cryptographically Signed/Encrypted Messages" of the
** user manual for the meaning of the letters some of these sequences expand
** to.
** .pp
** (Crypto only) or (PGP only when GPGME disabled)
*/

#ifdef CRYPT_BACKEND_CLASSIC_PGP
{ "pgp_export_command", D_STRING_COMMAND, 0 },
/*
** .pp
** This command is used to export a public key from the user's
** key ring.
** .pp
** This is a format string, see the $$pgp_decode_command command for
** possible \fIprintf(3)\fP-like sequences.
** (PGP only)
*/

{ "pgp_get_keys_command", D_STRING_COMMAND, 0 },
/*
** .pp
** This command is invoked whenever NeoMutt needs to fetch the public key associated with
** an email address.  Of the sequences supported by $$pgp_decode_command, %r is
** the only \fIprintf(3)\fP-like sequence used with this format.  Note that
** in this case, %r expands to the email address, not the public key ID (the key ID is
** unknown, which is why NeoMutt is invoking this command).
** (PGP only)
*/

{ "pgp_good_sign", DT_REGEX, 0 },
/*
** .pp
** If you assign a text to this variable, then a PGP signature is only
** considered verified if the output from $$pgp_verify_command contains
** the text. Use this variable if the exit code from the command is 0
** even for bad signatures.
** (PGP only)
*/
#endif

{ "pgp_ignore_subkeys", DT_BOOL, true },
/*
** .pp
** Setting this variable will cause NeoMutt to ignore OpenPGP subkeys. Instead,
** the principal key will inherit the subkeys' capabilities.  \fIUnset\fP this
** if you want to play interesting key selection games.
** (PGP only)
*/

#ifdef CRYPT_BACKEND_CLASSIC_PGP
{ "pgp_import_command", D_STRING_COMMAND, 0 },
/*
** .pp
** This command is used to import a key from a message into
** the user's public key ring.
** .pp
** This is a format string, see the $$pgp_decode_command command for
** possible \fIprintf(3)\fP-like sequences.
** (PGP only)
*/

{ "pgp_list_pubring_command", D_STRING_COMMAND, 0 },
/*
** .pp
** This command is used to list the public key ring's contents.  The
** output format must be analogous to the one used by
** .ts
** gpg --list-keys --with-colons --with-fingerprint
** .te
** .pp
** Note: gpg's \fIfixed-list-mode\fP option should not be used.  It
** produces a different date format which may result in NeoMutt showing
** incorrect key generation dates.
** .pp
** This is a format string, see the $$pgp_decode_command command for
** possible \fIprintf(3)\fP-like sequences.
** (PGP only)
*/

{ "pgp_list_secring_command", D_STRING_COMMAND, 0 },
/*
** .pp
** This command is used to list the secret key ring's contents.  The
** output format must be analogous to the one used by:
** .ts
** gpg --list-keys --with-colons --with-fingerprint
** .te
** .pp
** Note: gpg's \fIfixed-list-mode\fP option should not be used.  It
** produces a different date format which may result in NeoMutt showing
** incorrect key generation dates.
** .pp
** This is a format string, see the $$pgp_decode_command command for
** possible \fIprintf(3)\fP-like sequences.
** (PGP only)
*/
#endif

{ "pgp_key_sort", DT_SORT, KEY_SORT_ADDRESS },
/*
** .pp
** Specifies how the entries in the pgp menu are sorted. The
** following are legal values:
** .dl
** .dt address .dd sort alphabetically by user id
** .dt keyid   .dd sort alphabetically by key id
** .dt date    .dd sort by key creation date
** .dt trust   .dd sort by the trust of the key
** .de
** .pp
** If you prefer reverse order of the above values, prefix it with
** "reverse-".
** (PGP only)
*/

{ "pgp_long_ids", DT_BOOL, true },
/*
** .pp
** If \fIset\fP, use 64 bit PGP key IDs, if \fIunset\fP use the normal 32 bit key IDs.
** NOTE: Internally, NeoMutt has transitioned to using fingerprints (or long key IDs
** as a fallback).  This option now only controls the display of key IDs
** in the key selection menu and a few other places.
** (PGP only)
*/

{ "pgp_mime_auto", DT_QUAD, MUTT_ASKYES },
/*
** .pp
** This option controls whether NeoMutt will prompt you for
** automatically sending a (signed/encrypted) message using
** PGP/MIME when inline (traditional) fails (for any reason).
** .pp
** Also note that using the old-style PGP message format is \fBstrongly\fP
** \fBdeprecated\fP.
** (PGP only)
*/

{ "pgp_reply_inline", DT_BOOL, false },
/*
** .pp
** Setting this variable will cause NeoMutt to always attempt to
** create an inline (traditional) message when replying to a
** message which is PGP encrypted/signed inline.  This can be
** overridden by use of the pgp menu, when inline is not
** required.  This option does not automatically detect if the
** (replied-to) message is inline; instead it relies on NeoMutt
** internals for previously checked/flagged messages.
** .pp
** Note that NeoMutt might automatically use PGP/MIME for messages
** which consist of more than a single MIME part.  NeoMutt can be
** configured to ask before sending PGP/MIME messages when inline
** (traditional) would not work.
** .pp
** Also see the $$pgp_mime_auto variable.
** .pp
** Also note that using the old-style PGP message format is \fBstrongly\fP
** \fBdeprecated\fP.
** (PGP only)
*/

{ "pgp_retainable_sigs", DT_BOOL, false },
/*
** .pp
** If \fIset\fP, signed and encrypted messages will consist of nested
** \fImultipart/signed\fP and \fImultipart/encrypted\fP body parts.
** .pp
** This is useful for applications like encrypted and signed mailing
** lists, where the outer layer (\fImultipart/encrypted\fP) can be easily
** removed, while the inner \fImultipart/signed\fP part is retained.
** (PGP only)
*/

{ "pgp_self_encrypt", DT_BOOL, true },
/*
** .pp
** When \fIset\fP, PGP encrypted messages will also be encrypted
** using the key in $$pgp_default_key.
** (PGP only)
*/

{ "pgp_show_unusable", DT_BOOL, true },
/*
** .pp
** If \fIset\fP, NeoMutt will display non-usable keys on the PGP key selection
** menu.  This includes keys which have been revoked, have expired, or
** have been marked as "disabled" by the user.
** (PGP only)
*/

{ "pgp_sign_as", DT_STRING, 0 },
/*
** .pp
** If you have a different key pair to use for signing, you should
** set this to the signing key.  Most people will only need to set
** $$pgp_default_key.  It is recommended that you use the keyid form
** to specify your key (e.g. \fI0x00112233\fP).
** (PGP only)
*/

#ifdef CRYPT_BACKEND_CLASSIC_PGP
{ "pgp_sign_command", D_STRING_COMMAND, 0 },
/*
** .pp
** This command is used to create the detached PGP signature for a
** \fImultipart/signed\fP PGP/MIME body part.
** .pp
** This is a format string, see the $$pgp_decode_command command for
** possible \fIprintf(3)\fP-like sequences.
** (PGP only)
*/
#endif

{ "pgp_strict_enc", DT_BOOL, true },
/*
** .pp
** If \fIset\fP, NeoMutt will automatically encode PGP/MIME signed messages as
** quoted-printable.  Please note that unsetting this variable may
** lead to problems with non-verifyable PGP signatures, so only change
** this if you know what you are doing.
** (PGP only)
*/

#ifdef CRYPT_BACKEND_CLASSIC_PGP
{ "pgp_timeout", DT_LONG, 300 },
/*
** .pp
** The number of seconds after which a cached passphrase will expire if
** not used.
** (PGP only)
*/

{ "pgp_use_gpg_agent", DT_BOOL, true },
/*
** .pp
** If \fIset\fP, NeoMutt expects a \fIgpg-agent(1)\fP process will handle
** private key passphrase prompts.  If \fIunset\fP, NeoMutt will prompt
** for the passphrase and pass it via stdin to the pgp command.
** .pp
** Note that as of version 2.1, GnuPG automatically spawns an agent
** and requires the agent be used for passphrase management.  Since
** that version is increasingly prevalent, this variable now
** defaults \fIset\fP.
** .pp
** NeoMutt works with a GUI or curses pinentry program.  A TTY pinentry
** should not be used.
** .pp
** If you are using an older version of GnuPG without an agent running,
** or another encryption program without an agent, you will need to
** \fIunset\fP this variable.
** (PGP only)
*/

{ "pgp_verify_command", D_STRING_COMMAND, 0 },
/*
** .pp
** This command is used to verify PGP signatures.
** .pp
** This is a format string, see the $$pgp_decode_command command for
** possible \fIprintf(3)\fP-like sequences.
** (PGP only)
*/

{ "pgp_verify_key_command", D_STRING_COMMAND, 0 },
/*
** .pp
** This command is used to verify key information from the key selection
** menu.
** .pp
** This is a format string, see the $$pgp_decode_command command for
** possible \fIprintf(3)\fP-like sequences.
** (PGP only)
*/
#endif

{ "pipe_decode", DT_BOOL, false },
/*
** .pp
** Used in connection with the \fI<pipe-message>\fP function.  When \fIunset\fP,
** NeoMutt will pipe the messages without any preprocessing. When \fIset\fP, NeoMutt
** will attempt to decode the messages first.
** .pp
** Also see $$pipe_decode_weed, which controls whether headers will
** be weeded when this is \fIset\fP.
*/

{ "pipe_decode_weed", DT_BOOL, true },
/*
** .pp
** For \fI<pipe-message>\fP, when $$pipe_decode is set, this further
** controls whether NeoMutt will weed headers.
*/

{ "pipe_sep", DT_STRING, "\n" },
/*
** .pp
** The separator to add between messages when piping a list of tagged
** messages to an external Unix command.
*/

{ "pipe_split", DT_BOOL, false },
/*
** .pp
** Used in connection with the \fI<pipe-message>\fP function following
** \fI<tag-prefix>\fP.  If this variable is \fIunset\fP, when piping a list of
** tagged messages NeoMutt will concatenate the messages and will pipe them
** all concatenated.  When \fIset\fP, NeoMutt will pipe the messages one by one.
** In both cases the messages are piped in the current sorted order,
** and the $$pipe_sep separator is added after each message.
*/

{ "pop_auth_try_all", DT_BOOL, true },
/*
** .pp
** If \fIset\fP, NeoMutt will try all available authentication methods.
** When \fIunset\fP, NeoMutt will only fall back to other authentication
** methods if the previous methods are unavailable. If a method is
** available but authentication fails, NeoMutt will not connect to the POP server.
*/

{ "pop_authenticators", DT_SLIST, 0 },
/*
** .pp
** This is a colon-separated list of authentication methods NeoMutt may
** attempt to use to log in to an POP server, in the order NeoMutt should
** try them.  Authentication methods are either "user", "apop" or any
** SASL mechanism, e.g. "digest-md5", "gssapi" or "cram-md5".
** This option is case-insensitive. If this option is \fIunset\fP
** (the default) NeoMutt will try all available methods, in order from
** most-secure to least-secure.
** .pp
** Example:
** .ts
** set pop_authenticators="digest-md5:apop:user"
** .te
*/

{ "pop_check_interval", DT_NUMBER, 60 },
/*
** .pp
** This variable configures how often (in seconds) NeoMutt should look for
** new mail in the currently selected mailbox if it is a POP mailbox.
*/

{ "pop_delete", DT_QUAD, MUTT_ASKNO },
/*
** .pp
** If \fIset\fP, NeoMutt will delete successfully downloaded messages from the POP
** server when using the \fI$<fetch-mail>\fP function.  When \fIunset\fP, NeoMutt will
** download messages but also leave them on the POP server.
*/

{ "pop_host", DT_STRING, 0 },
/*
** .pp
** The name of your POP server for the \fI$<fetch-mail>\fP function.  You
** can also specify an alternative port, username and password, i.e.:
** .ts
** [pop[s]://][username[:password]@]popserver[:port]
** .te
** .pp
** where "[...]" denotes an optional part.
*/

{ "pop_last", DT_BOOL, false },
/*
** .pp
** If this variable is \fIset\fP, NeoMutt will try to use the "\fILAST\fP" POP command
** for retrieving only unread messages from the POP server when using
** the \fI$<fetch-mail>\fP function.
*/

{ "pop_oauth_refresh_command", D_STRING_COMMAND, 0 },
/*
** .pp
** The command to run to generate an OAUTH refresh token for
** authorizing your connection to your POP server.  This command will be
** run on every connection attempt that uses the OAUTHBEARER authentication
** mechanism.  See "$oauth" for details.
*/

{ "pop_pass", DT_STRING, 0 },
/*
** .pp
** Specifies the password for your POP account.  If \fIunset\fP, NeoMutt will
** prompt you for your password when you open a POP mailbox.
** .pp
** \fBWarning\fP: you should only use this option when you are on a
** fairly secure machine, because the superuser can read your neomuttrc
** even if you are the only one who can read the file.
*/

{ "pop_reconnect", DT_QUAD, MUTT_ASKYES },
/*
** .pp
** Controls whether or not NeoMutt will try to reconnect to the POP server if
** the connection is lost.
*/

{ "pop_user", DT_STRING, 0 },
/*
** .pp
** Your login name on the POP server.
** .pp
** This variable defaults to your user name on the local machine.
*/

{ "post_moderated", DT_QUAD, MUTT_ASKYES },
/*
** .pp
** If set to \fIyes\fP, NeoMutt will post article to newsgroup that have
** not permissions to posting (e.g. moderated).  \fBNote:\fP if news server
** does not support posting to that newsgroup or totally read-only, that
** posting will not have an effect.
*/

{ "postpone", DT_QUAD, MUTT_ASKYES },
/*
** .pp
** Controls whether or not messages are saved in the $$postponed
** mailbox when you elect not to send immediately. If set to
** \fIask-yes\fP or \fIask-no\fP, you will be prompted with "Save
** (postpone) draft message?" when quitting from the "compose"
** screen.
** .pp
** Also see the $$recall variable.
*/

{ "postpone_encrypt", DT_BOOL, false },
/*
** .pp
** When \fIset\fP, postponed messages that are marked for encryption will be
** self-encrypted.  NeoMutt will first try to encrypt using the value specified
** in $$pgp_default_key or $$smime_default_key.  If those are not
** set, it will try the deprecated $$postpone_encrypt_as.
** (Crypto only)
*/

{ "postpone_encrypt_as", DT_STRING, 0 },
/*
** .pp
** This is a deprecated fall-back variable for $$postpone_encrypt.
** Please use $$pgp_default_key or $$smime_default_key.
** (Crypto only)
*/

{ "postponed", D_STRING_MAILBOX, "~/postponed" },
/*
** .pp
** NeoMutt allows you to indefinitely "$postpone sending a message" which
** you are editing.  When you choose to postpone a message, NeoMutt saves it
** in the mailbox specified by this variable.
** .pp
** Also see the $$postpone variable.
*/

{ "preconnect", DT_STRING, 0 },
/*
** .pp
** If \fIset\fP, a shell command to be executed if NeoMutt fails to establish
** a connection to the server. This is useful for setting up secure
** connections, e.g. with \fIssh(1)\fP. If the command returns a  nonzero
** status, NeoMutt gives up opening the server. Example:
** .ts
** set preconnect="ssh -f -q -L 1234:mailhost.net:143 mailhost.net \(rs
** sleep 20 < /dev/null > /dev/null"
** .te
** .pp
** Mailbox "foo" on "mailhost.net" can now be reached
** as "{localhost:1234}foo".
** .pp
** Note: For this example to work, you must be able to log in to the
** remote machine without having to enter a password.
*/

{ "preferred_languages", DT_SLIST, 0 },
/*
** .pp
** This variable specifies a list of comma-separated languages.
** RFC8255 : user preferred languages to be searched in parts and display.
** Example:
** .ts
** set preferred_languages="en,fr,de"
** .te
*/

{ "print", DT_QUAD, MUTT_ASKNO },
/*
** .pp
** Controls whether or not NeoMutt really prints messages.
** This is set to "ask-no" by default, because some people
** accidentally hit "p" often.
*/

{ "print_command", D_STRING_COMMAND, "lpr" },
/*
** .pp
** This specifies the command pipe that should be used to print messages.
*/

{ "print_decode", DT_BOOL, true },
/*
** .pp
** Used in connection with the \fI<print-message>\fP function.  If this
** option is \fIset\fP, the message is decoded before it is passed to the
** external command specified by $$print_command.  If this option
** is \fIunset\fP, no processing will be applied to the message when
** printing it.  The latter setting may be useful if you are using
** some advanced printer filter which is able to properly format
** e-mail messages for printing.
** .pp
** Also see $$print_decode_weed, which controls whether headers will
** be weeded when this is \fIset\fP.
*/

{ "print_decode_weed", DT_BOOL, true },
/*
** .pp
** For \fI<print-message>\fP, when $$print_decode is set, this
** further controls whether NeoMutt will weed headers.
*/

{ "print_split", DT_BOOL, false },
/*
** .pp
** Used in connection with the \fI<print-message>\fP function.  If this option
** is \fIset\fP, the command specified by $$print_command is executed once for
** each message which is to be printed.  If this option is \fIunset\fP,
** the command specified by $$print_command is executed only once, and
** all the messages are concatenated, with a form feed as the message
** separator.
** .pp
** Those who use the \fIenscript\fP(1) program's mail-printing mode will
** most likely want to \fIset\fP this option.
*/

{ "prompt_after", DT_BOOL, true },
/*
** .pp
** If you use an \fIexternal\fP $$pager, setting this variable will
** cause NeoMutt to prompt you for a command when the pager exits rather
** than returning to the index menu.  If \fIunset\fP, NeoMutt will return to the
** index menu when the external pager exits.
*/

{ "query_command", D_STRING_COMMAND, 0 },
/*
** .pp
** This specifies the command NeoMutt will use to make external address
** queries.  The string may contain a "%s", which will be substituted
** with the query string the user types.  NeoMutt will add quotes around the
** string substituted for "%s" automatically according to shell quoting
** rules, so you should avoid adding your own.  If no "%s" is found in
** the string, NeoMutt will append the user's query to the end of the string.
** See "$query" (https://neomutt.org/guide/advancedusage.html#query) for more
** information.
*/

{ "query_format", DT_STRING, "%3i %t %-25N %-25E | %C%> %Y" },
/*
** .pp
** This variable describes the format of the "query" menu. The
** following \fIprintf(3)\fP-style sequences are understood:
** .dl
** .dt %A  .dd Full Address (Name and Email)
** .dt %C  .dd Comment
** .dt %E  .dd Email Address
** .dt %i  .dd Index number
** .dt %N  .dd Real name
** .dt %t  .dd Alias is tagged (selected)
** .dt %Y  .dd User-defined tags (labels)
** .dt %>X .dd Right justify the rest of the string and pad with "X"
** .dt %|X .dd Pad to the end of the line with "X"
** .dt %*X .dd Soft-fill with character "X" as pad
** .de
** .pp
** For an explanation of "soft-fill", see the $$index_format documentation.
** .pp
** The following sequences are deprecated; they will be removed in the future.
** .dl
** .dt %a  .dd Use %E instead
** .dt %c  .dd Use %i instead
** .dt %e  .dd Use %C instead
** .dt %n  .dd Use %N instead
** .de
*/

{ "quit", DT_QUAD, MUTT_YES },
/*
** .pp
** This variable controls whether "quit" and "exit" actually quit
** from NeoMutt.  If this option is \fIset\fP, they do quit, if it is \fIunset\fP, they
** have no effect, and if it is set to \fIask-yes\fP or \fIask-no\fP, you are
** prompted for confirmation when you try to quit.
** .pp
** In order to quit from NeoMutt if this variable is \fIunset\fP, you must send
** the signal SIGINT to NeoMutt.  This can usually be achieved by pressing
** CTRL-C in the terminal.
*/

{ "quote_regex", DT_REGEX, "^([ \t]*[|>:}#])+" },
/*
** .pp
** A regular expression used in the internal pager to determine quoted
** sections of text in the body of a message. Quoted text may be filtered
** out using the \fI<toggle-quoted>\fP command, or colored according to the
** "color quoted" family of directives.
** .pp
** Higher levels of quoting may be colored differently ("color quoted1",
** "color quoted2", etc.). The quoting level is determined by removing
** the last character from the matched text and recursively reapplying
** the regular expression until it fails to produce a match.
** .pp
** Match detection may be overridden by the $$smileys regular expression.
*/

{ "read_inc", DT_NUMBER, 10 },
/*
** .pp
** If set to a value greater than 0, NeoMutt will display which message it
** is currently on when reading a mailbox or when performing search actions
** such as search and limit. The message is printed after
** this many messages have been read or searched (e.g., if set to 25, NeoMutt will
** print a message when it is at message 25, and then again when it gets
** to message 50).  This variable is meant to indicate progress when
** reading or searching large mailboxes which may take some time.
** When set to 0, only a single message will appear before the reading
** the mailbox.
** .pp
** Also see the $$write_inc, $$net_inc and $$time_inc variables and the
** "$tuning" section of the manual for performance considerations.
*/

{ "read_only", DT_BOOL, false },
/*
** .pp
** If \fIset\fP, all folders are opened in read-only mode.
*/

{ "real_name", DT_STRING, 0 },
/*
** .pp
** This variable specifies what "real" or "personal" name should be used
** when sending messages.
** .pp
** If not specified, then the user's "real name" will be read from \fI/etc/passwd\fP.
** This option will not be used, if "$$from" is set.
*/

{ "recall", DT_QUAD, MUTT_ASKYES },
/*
** .pp
** Controls whether or not NeoMutt recalls postponed messages
** when composing a new message.
** .pp
** Setting this variable to \fIyes\fP is not generally useful, and thus not
** recommended.  Note that the \fI<recall-message>\fP function can be used
** to manually recall postponed messages.
** .pp
** Also see $$postponed variable.
*/

{ "record", D_STRING_MAILBOX, "~/sent" },
/*
** .pp
** This specifies the file into which your outgoing messages should be
** appended.  (This is meant as the primary method for saving a copy of
** your messages, but another way to do this is using the "$my_hdr"
** command to create a "Bcc:" field with your email address in it.)
** .pp
** The value of \fI$$record\fP is overridden by the $$force_name and
** $$save_name variables, and the "$fcc-hook" command.  Also see $$copy
** and $$write_bcc.
*/

{ "reflow_space_quotes", DT_BOOL, true },
/*
** .pp
** This option controls how quotes from format=flowed messages are displayed
** in the pager and when replying (with $$text_flowed \fIunset\fP).
** When set, this option adds spaces after each level of quote marks, turning
** ">>>foo" into "> > > foo".
** .pp
** \fBNote:\fP If $$reflow_text is \fIunset\fP, this option has no effect.
** Also, this option does not affect replies when $$text_flowed is \fIset\fP.
*/

{ "reflow_text", DT_BOOL, true },
/*
** .pp
** When \fIset\fP, NeoMutt will reformat paragraphs in text/plain
** parts marked format=flowed.  If \fIunset\fP, NeoMutt will display paragraphs
** unaltered from how they appear in the message body.  See RFC3676 for
** details on the \fIformat=flowed\fP format.
** .pp
** Also see $$reflow_wrap, and $$wrap.
*/

{ "reflow_wrap", DT_NUMBER, 78 },
/*
** .pp
** This variable controls the maximum paragraph width when reformatting text/plain
** parts when $$reflow_text is \fIset\fP.  When the value is 0, paragraphs will
** be wrapped at the terminal's right margin.  A positive value sets the
** paragraph width relative to the left margin.  A negative value set the
** paragraph width relative to the right margin.
** .pp
** Be aware that the reformatted lines of a paragraph are still subject to $$wrap.
** This means if $$reflow_wrap is 40 and $$wrap is 30, then the paragraph gets
** reformatted to 40 characters a line (due to $$reflow_wrap) and afterwards
** each 40-character-line is split at 30 characters (due to $$wrap), resulting in
** alternating line lengths of 30 and 10 characters.
** .pp
** Also see $$wrap.
*/

{ "reply_regex", DT_REGEX, "^((re|aw|sv)(\\[[0-9]+\\])*:[ \t]*)*" },
/*
** .pp
** A regular expression used to recognize reply messages when
** threading and replying. The default value corresponds to the
** standard Latin "Re:" prefix.
** .pp
** This value may have been localized by the translator for your
** locale, adding other prefixes that are common in the locale. You
** can add your own prefixes by appending inside \fI"^(re)"\fP.  For
** example: \fI"^(re|sv)"\fP or \fI"^(re|aw|sv)"\fP.
** .pp
** The second parenthesized expression matches zero or more
** bracketed numbers following the prefix, such as \fI"Re[1]: "\fP.
** The initial \fI"\\["\fP means a literal left-bracket character.
** Note the backslash must be doubled when used inside a double
** quoted string in the neomuttrc.  \fI"[0-9]+"\fP means one or more
** numbers.  \fI"\\]"\fP means a literal right-bracket.  Finally the
** whole parenthesized expression has a \fI"*"\fP suffix, meaning it
** can occur zero or more times.
** .pp
** The last part matches a colon followed by an optional space or
** tab.  Note \fI"\t"\fP is converted to a literal tab inside a
** double quoted string.  If you use a single quoted string, you
** would have to type an actual tab character, and would need to
** convert the double-backslashes to single backslashes.
** .pp
** Note: the result of this regex match against the subject is
** stored in the header cache.  Mutt isn't smart enough to
** invalidate a header cache entry based on changing $$reply_regex,
** so if you aren't seeing correct values in the index, try
** temporarily turning off the header cache.  If that fixes the
** problem, then once the variable is set to your liking, remove
** your stale header cache files and turn the header cache back on.
*/

{ "reply_self", DT_BOOL, false },
/*
** .pp
** If \fIunset\fP and you are replying to a message sent by you, NeoMutt will
** assume that you want to reply to the recipients of that message rather
** than to yourself.
** .pp
** Also see the "$alternates" command.
*/

{ "reply_to", DT_QUAD, MUTT_ASKYES },
/*
** .pp
** If \fIset\fP, when replying to a message, NeoMutt will use the address listed
** in the Reply-to: header as the recipient of the reply.  If \fIunset\fP,
** it will use the address in the From: header field instead.  This
** option is useful for reading a mailing list that sets the Reply-To:
** header field to the list address and you want to send a private
** message to the author of a message.
*/

{ "reply_with_xorig", DT_BOOL, false },
/*
** .pp
** This variable provides a toggle. When active, the From: header will be
** extracted from the current mail's 'X-Original-To:' header. This setting
** does not have precedence over "$reverse_real_name".
** .pp
** Assuming 'fast_reply' is disabled, this option will prompt the user with a
** prefilled From: header.
*/

{ "resolve", DT_BOOL, true },
/*
** .pp
** When \fIset\fP, the cursor in a list will be automatically advanced to the
** next (possibly undeleted) message/attachment/entry whenever a command that
** modifies the current message/attachment/entry is executed.
** .pp
** Examples of such commands are tagging a message, deleting an entry, or
** saving an attachment.
*/

{ "resume_draft_files", DT_BOOL, false },
/*
** .pp
** If \fIset\fP, draft files (specified by \fI-H\fP on the command
** line) are processed similarly to when resuming a postponed
** message.  Recipients are not prompted for; send-hooks are not
** evaluated; no alias expansion takes place; user-defined headers
** and signatures are not added to the message.
*/

{ "resume_edited_draft_files", DT_BOOL, true },
/*
** .pp
** If \fIset\fP, draft files previously edited (via \fI-E -H\fP on
** the command line) will have $$resume_draft_files automatically
** set when they are used as a draft file again.
** .pp
** The first time a draft file is saved, NeoMutt will add a header,
** X-Mutt-Resume-Draft to the saved file.  The next time the draft
** file is read in, if NeoMutt sees the header, it will set
** $$resume_draft_files.
** .pp
** This option is designed to prevent multiple signatures,
** user-defined headers, and other processing effects from being
** made multiple times to the draft file.
*/

{ "reverse_alias", DT_BOOL, false },
/*
** .pp
** This variable controls whether or not NeoMutt will display the "personal"
** name from your aliases in the index menu if it finds an alias that
** matches the message's sender.  For example, if you have the following
** alias:
** .ts
** alias juser abd30425@somewhere.net (Joe User)
** .te
** .pp
** and then you receive mail which contains the following header:
** .ts
** From: abd30425@somewhere.net
** .te
** .pp
** It would be displayed in the index menu as "Joe User" instead of
** "abd30425@somewhere.net."  This is useful when the person's e-mail
** address is not human friendly.
*/

{ "reverse_name", DT_BOOL, false },
/*
** .pp
** It may sometimes arrive that you receive mail to a certain machine,
** move the messages to another machine, and reply to some the messages
** from there.  If this variable is \fIset\fP, the default \fIFrom:\fP line of
** the reply messages is built using the address where you received the
** messages you are replying to \fBif\fP that address matches your
** "$alternates".  If the variable is \fIunset\fP, or the address that would be
** used doesn't match your "$alternates", the \fIFrom:\fP line will use
** your address on the current machine.
** .pp
** Also see the "$alternates" command and $$reverse_real_name.
*/

{ "reverse_real_name", DT_BOOL, true },
/*
** .pp
** This variable fine-tunes the behavior of the $$reverse_name feature.
** .pp
** When it is \fIunset\fP, NeoMutt will remove the real name part of a
** matching address.  This allows the use of the email address
** without having to also use what the sender put in the real name
** field.
** .pp
** When it is \fIset\fP, NeoMutt will use the matching address as-is.
** .pp
** In either case, a missing real name will be filled in afterwards
** using the value of $$real_name.
*/

{ "rfc2047_parameters", DT_BOOL, true },
/*
** .pp
** When this variable is \fIset\fP, NeoMutt will decode RFC2047-encoded MIME
** parameters. You want to set this variable when NeoMutt suggests you
** to save attachments to files named like:
** .ts
** =?iso-8859-1?Q?file=5F=E4=5F991116=2Ezip?=
** =?utf-8?Q?z=C4=99ta.png?=
** .te
** .pp
** When this variable is \fIset\fP interactively, the change won't be
** active until you change folders.
** .pp
** Note that this use of RFC2047's encoding is explicitly
** prohibited by the standard, but nevertheless encountered in the
** wild and produced by, e.g., Outlook.
** .pp
** Also note that setting this parameter will \fInot\fP have the effect
** that NeoMutt \fIgenerates\fP this kind of encoding.  Instead, NeoMutt will
** unconditionally use the encoding specified in RFC2231.
*/

{ "save_address", DT_BOOL, false },
/*
** .pp
** If \fIset\fP, NeoMutt will take the sender's full address when choosing a
** default folder for saving a mail. If $$save_name or $$force_name
** is \fIset\fP too, the selection of the Fcc folder will be changed as well.
*/

{ "save_empty", DT_BOOL, true },
/*
** .pp
** When \fIunset\fP, mailboxes which contain no saved messages will be removed
** when closed (the exception is $$spool_file which is never removed).
** If \fIset\fP, mailboxes are never removed.
** .pp
** \fBNote:\fP This only applies to mbox and MMDF folders, NeoMutt does not
** delete MH and Maildir directories.
*/

{ "save_history", DT_NUMBER, 0 },
/*
** .pp
** This variable controls the size of the history (per category) saved in the
** $$history_file file.
** .pp
** Setting this to a value greater than $$history is possible.  However, there
** will never be more than $$history entries to select from even if more are
** recorded in the history file.
*/

{ "save_name", DT_BOOL, false },
/*
** .pp
** This variable controls how copies of outgoing messages are saved.
** When \fIset\fP, a check is made to see if a mailbox specified by the
** recipient address exists (this is done by searching for a mailbox in
** the $$folder directory with the \fIusername\fP part of the
** recipient address).  If the mailbox exists, the outgoing message will
** be saved to that mailbox, otherwise the message is saved to the
** $$record mailbox.
** .pp
** Also see the $$force_name variable.
*/

{ "save_unsubscribed", DT_BOOL, false },
/*
** .pp
** When \fIset\fP, info about unsubscribed newsgroups will be saved into
** "newsrc" file and into cache.
*/

{ "score", DT_BOOL, true },
/*
** .pp
** When this variable is \fIunset\fP, scoring is turned off.  This can
** be useful to selectively disable scoring for certain folders when the
** $$score_threshold_delete variable and related are used.
*/

{ "score_threshold_delete", DT_NUMBER, -1 },
/*
** .pp
** Messages which have been assigned a score equal to or lower than the value
** of this variable are automatically marked for deletion by NeoMutt.  Since
** NeoMutt scores are always greater than or equal to zero, the default setting
** of this variable will never mark a message for deletion.
*/

{ "score_threshold_flag", DT_NUMBER, 9999 },
/*
** .pp
** Messages which have been assigned a score greater than or equal to this
** variable's value are automatically marked "flagged".
*/

{ "score_threshold_read", DT_NUMBER, -1 },
/*
** .pp
** Messages which have been assigned a score equal to or lower than the value
** of this variable are automatically marked as read by NeoMutt.  Since
** NeoMutt scores are always greater than or equal to zero, the default setting
** of this variable will never mark a message read.
*/

{ "search_context", DT_NUMBER, 0 },
/*
** .pp
** For the pager, this variable specifies the number of lines shown
** before search results. By default, search results will be top-aligned.
*/

{ "send_charset", DT_SLIST, "us-ascii:iso-8859-1:utf-8" },
/*
** .pp
** A colon-delimited list of character sets for outgoing messages. NeoMutt will use the
** first character set into which the text can be converted exactly.
** If your $$charset is not "iso-8859-1" and recipients may not
** understand "UTF-8", it is advisable to include in the list an
** appropriate widely used standard character set (such as
** "iso-8859-2", "koi8-r" or "iso-2022-jp") either instead of or after
** "iso-8859-1".
** .pp
** In case the text can't be converted into one of these exactly,
** NeoMutt uses $$charset as a fallback.
*/

{ "sendmail", D_STRING_COMMAND, SENDMAIL " -oem -oi" },
/*
** .pp
** Specifies the program and arguments used to deliver mail sent by NeoMutt.
** NeoMutt expects that the specified program interprets additional
** arguments as recipient addresses.  NeoMutt appends all recipients after
** adding a \fI--\fP delimiter (if not already present).  Additional
** flags, such as for $$use_8bit_mime, $$use_envelope_from,
** $$dsn_notify, or $$dsn_return will be added before the delimiter.
** .pp
** \fBNote:\fP This command is invoked differently from most other
** commands in NeoMutt.  It is tokenized by space, and invoked directly
** via \fIexecvp(3)\fP with an array of arguments - so commands or
** arguments with spaces in them are not supported.  The shell is
** not used to run the command, so shell quoting is also not
** supported.
** .pp
** \fBSee also:\fP $$write_bcc.
*/

{ "sendmail_wait", DT_NUMBER, 0 },
/*
** .pp
** Specifies the number of seconds to wait for the $$sendmail process
** to finish before giving up and putting delivery in the background.
** .pp
** NeoMutt interprets the value of this variable as follows:
** .dl
** .dt >0 .dd number of seconds to wait for sendmail to finish before continuing
** .dt 0  .dd wait forever for sendmail to finish
** .dt <0 .dd always put sendmail in the background without waiting
** .de
** .pp
** Note that if you specify a value other than 0, the output of the child
** process will be put in a temporary file.  If there is some error, you
** will be informed as to where to find the output.
*/

{ "shell", D_STRING_COMMAND, "/bin/sh" },
/*
** .pp
** Command to use when spawning a subshell.
** If not specified, then the user's login shell from \fI/etc/passwd\fP is used.
*/

{ "show_multipart_alternative", DT_STRING, 0 },
/*
** .pp
** When \fIset\fP to \fIinfo\fP, the multipart/alternative information is shown.
** When \fIset\fP to \fIinline\fP, all of the alternatives are displayed.
** When not set, the default behavior is to show only the chosen alternative.
*/

{ "show_new_news", DT_BOOL, true },
/*
** .pp
** If \fIset\fP, news server will be asked for new newsgroups on entering
** the browser.  Otherwise, it will be done only once for a news server.
** Also controls whether or not number of new articles of subscribed
** newsgroups will be then checked.
*/

{ "show_only_unread", DT_BOOL, false },
/*
** .pp
** If \fIset\fP, only subscribed newsgroups that contain unread articles
** will be displayed in browser.
*/

{ "sidebar_component_depth", DT_NUMBER, 0 },
/*
** .pp
** By default the sidebar will show the mailbox's path, relative to the
** $$folder variable. This specifies the number of parent directories to hide
** from display in the sidebar. For example: If a maildir is normally
** displayed in the sidebar as dir1/dir2/dir3/maildir, setting
** \fIsidebar_component_depth=2\fP will display it as dir3/maildir, having
** truncated the 2 highest directories.
** .pp
** \fBSee also:\fP $$sidebar_short_path
*/

{ "sidebar_delim_chars", DT_STRING, "/." },
/*
** .pp
** This contains the list of characters which you would like to treat
** as folder separators for displaying paths in the sidebar.
** .pp
** Local mail is often arranged in directories: 'dir1/dir2/mailbox'.
** .ts
** set sidebar_delim_chars='/'
** .te
** .pp
** IMAP mailboxes are often named: 'folder1.folder2.mailbox'.
** .ts
** set sidebar_delim_chars='.'
** .te
** .pp
** \fBSee also:\fP $$sidebar_short_path, $$sidebar_folder_indent, $$sidebar_indent_string.
*/

{ "sidebar_divider_char", DT_STRING, "|" },
/*
** .pp
** The default is a Unicode vertical line.
** .pp
** This specifies the characters to be drawn between the sidebar (when
** visible) and the other NeoMutt panels. ASCII and Unicode line-drawing
** characters are supported.
** .pp
** The divider char can be set to an empty string for some extra space.
** If empty, setting the sidebar_background color may help distinguish the
** sidebar from other panels.
*/

{ "sidebar_folder_indent", DT_BOOL, false },
/*
** .pp
** Set this to indent mailboxes in the sidebar.
** .pp
** \fBSee also:\fP $$sidebar_short_path, $$sidebar_indent_string, $$sidebar_delim_chars.
*/

{ "sidebar_format", DT_STRING, "%D%*  %n" },
/*
** .pp
** This variable allows you to customize the sidebar display. This string is
** similar to $$index_format, but has its own set of \fIprintf(3)\fP-like
** sequences:
** .dl
** .dt %a .dd     .dd Alert: 1 if user is notified of new mail
** .dt %B .dd     .dd Name of the mailbox
** .dt %d .dd * @ .dd Number of deleted messages in the mailbox
** .dt %D .dd     .dd Descriptive name of the mailbox
** .dt %F .dd *   .dd Number of flagged messages in the mailbox
** .dt %L .dd * @ .dd Number of messages after limiting
** .dt %n .dd     .dd "N" if mailbox has new mail, " " (space) otherwise
** .dt %N .dd *   .dd Number of unread messages in the mailbox (seen or unseen)
** .dt %o .dd *   .dd Number of old messages in the mailbox (unread, seen)
** .dt %p .dd     .dd Poll: 1 if Mailbox is checked for new mail
** .dt %r .dd *   .dd Number of read messages in the mailbox (read, seen)
** .dt %S .dd *   .dd Size of mailbox (total number of messages)
** .dt %t .dd * @ .dd Number of tagged messages in the mailbox
** .dt %Z .dd *   .dd Number of new messages in the mailbox (unread, unseen)
** .dt %! .dd     .dd "!" : one flagged message;
**                    "!!" : two flagged messages;
**                    "n!" : n flagged messages (for n > 2).
**                    Otherwise prints nothing.
** .dt %>X .dd .dd Right justify the rest of the string and pad with "X"
** .dt %|X .dd .dd Pad to the end of the line with "X"
** .dt %*X .dd .dd Soft-fill with character "X" as pad
** .de
** .pp
** * = Can be optionally printed if nonzero
** .pp
** @ = Only applicable to the current folder
** .pp
** In order to use %S, %N, %F, and %!, $$mail_check_stats must
** be \fIset\fP.  When thus set, a suggested value for this option is
** "%B%<F? [%F]>%* %<N?%N/>%S".
*/

{ "sidebar_indent_string", DT_STRING, "  " },
/*
** .pp
** This specifies the string that is used to indent mailboxes in the sidebar.
** It defaults to two spaces.
** .pp
** \fBSee also:\fP $$sidebar_short_path, $$sidebar_folder_indent, $$sidebar_delim_chars.
*/

{ "sidebar_new_mail_only", DT_BOOL, false },
/*
** .pp
** When set, the sidebar will only display mailboxes containing new, or
** flagged, mail.
** .pp
** \fBSee also:\fP $sidebar_pin, $$sidebar_non_empty_mailbox_only.
*/

{ "sidebar_next_new_wrap", DT_BOOL, false },
/*
** .pp
** When set, the \fI<sidebar-next-new>\fP command will not stop at the end of
** the list of mailboxes, but wrap around to the beginning. The
** \fI<sidebar-prev-new>\fP command is similarly affected, wrapping around to
** the end of the list.
*/

{ "sidebar_non_empty_mailbox_only", DT_BOOL, false },
/*
** .pp
** When set, the sidebar will only display mailboxes that contain one or more mails.
** .pp
** \fBSee also:\fP $$sidebar_new_mail_only, $sidebar_pin.
*/

{ "sidebar_on_right", DT_BOOL, false },
/*
** .pp
** When set, the sidebar will appear on the right-hand side of the screen.
*/

{ "sidebar_short_path", DT_BOOL, false },
/*
** .pp
** By default the sidebar will show the mailbox's path, relative to the
** $$folder variable. Setting \fIsidebar_shortpath=yes\fP will shorten the
** names relative to the previous name. Here's an example:
** .dl
** .dt \fBshortpath=no\fP .dd \fBshortpath=yes\fP .dd \fBshortpath=yes, folderindent=yes, indentstr=".."\fP
** .dt \fIfruit\fP        .dd \fIfruit\fP         .dd \fIfruit\fP
** .dt \fIfruit.apple\fP  .dd \fIapple\fP         .dd \fI..apple\fP
** .dt \fIfruit.banana\fP .dd \fIbanana\fP        .dd \fI..banana\fP
** .dt \fIfruit.cherry\fP .dd \fIcherry\fP        .dd \fI..cherry\fP
** .de
** .pp
** \fBSee also:\fP $$sidebar_delim_chars, $$sidebar_folder_indent,
** $$sidebar_indent_string, $$sidebar_component_depth.
*/

{ "sidebar_sort", DT_SORT, SB_SORT_UNSORTED },
/*
** .pp
** Specifies how to sort mailbox entries in the sidebar.  By default, the
** entries are \fBunsorted\fP.  Valid values:
** .il
** .dd \fBcount\fP (all message count)
** .dd \fBdesc\fP (mailbox description)
** .dd \fBflagged\fP (flagged message count)
** .dd \fBpath\fP (alphabetically)
** .dd \fBunread\fP (unread message count)
** .dd \fBunsorted\fP
** .ie
** .pp
** You may optionally use the "reverse-" prefix to specify reverse sorting
** order (example: "\fIset sidebar_sort=reverse-path\fP").
** .pp
** The \fBalpha\fP and \fBname\fP values are synonyms for \fBpath\fP. The
** \fBnew\fP value is a synonym for \fBunread\fP.
*/

{ "sidebar_visible", DT_BOOL, false },
/*
** .pp
** This specifies whether or not to show sidebar. The sidebar shows a list of
** all your mailboxes.
** .pp
** \fBSee also:\fP $$sidebar_format, $$sidebar_width
*/

{ "sidebar_width", DT_NUMBER, 30 },
/*
** .pp
** This controls the width of the sidebar.  It is measured in screen columns.
** For example: sidebar_width=20 could display 20 ASCII characters, or 10
** Chinese characters.
*/

{ "sig_dashes", DT_BOOL, true },
/*
** .pp
** If \fIset\fP, a line containing "-- " (note the trailing space) will be inserted before your
** $$signature.  It is \fBstrongly\fP recommended that you not \fIunset\fP
** this variable unless your signature contains just your name.  The
** reason for this is because many software packages use "-- \n" to
** detect your signature.  For example, NeoMutt has the ability to highlight
** the signature in a different color in the built-in pager.
*/

{ "sig_on_top", DT_BOOL, false },
/*
** .pp
** If \fIset\fP, the signature will be included before any quoted or forwarded
** text.  It is \fBstrongly\fP recommended that you do not set this variable
** unless you really know what you are doing, and are prepared to take
** some heat from netiquette guardians.
*/

{ "signature", DT_PATH, "~/.signature" },
/*
** .pp
** Specifies the filename of your signature, which is appended to all
** outgoing messages.   If the filename ends with a pipe ("|"), it is
** assumed that filename is a shell command and input should be read from
** its standard output.
*/

{ "simple_search", DT_STRING, "~f %s | ~s %s" },
/*
** .pp
** Specifies how NeoMutt should expand a simple search into a real search
** pattern.  A simple search is one that does not contain any of the "~" pattern
** operators.  See "$patterns" for more information on search patterns.
** .pp
** simple_search applies to several functions, e.g. \fI<delete-pattern>\fP,
** \fI<limit>\fP, searching in the index, and all of the index colors.
** .pp
** For example, if you simply type "joe" at a search or limit prompt, NeoMutt
** will automatically expand it to the value specified by this variable by
** replacing "%s" with the supplied string.
** For the default value, "joe" would be expanded to: "~f joe | ~s joe".
*/

{ "size_show_bytes", DT_BOOL, false },
/*
** .pp
** If \fIset\fP, message sizes will display bytes for values less than
** 1 kilobyte.  See $formatstrings-size.
*/

{ "size_show_fractions", DT_BOOL, true },
/*
** .pp
** If \fIset\fP, message sizes will be displayed with a single decimal value
** for sizes from 0 to 10 kilobytes and 1 to 10 megabytes.
** See $formatstrings-size.
*/

{ "size_show_mb", DT_BOOL, true },
/*
** .pp
** If \fIset\fP, message sizes will display megabytes for values greater than
** or equal to 1 megabyte.  See $formatstrings-size.
*/

{ "size_units_on_left", DT_BOOL, false },
/*
** .pp
** If \fIset\fP, message sizes units will be displayed to the left of the number.
** See $formatstrings-size.
*/

{ "sleep_time", DT_NUMBER, 1 },
/*
** .pp
** Specifies time, in seconds, to pause while displaying certain informational
** messages, while moving from folder to folder and after expunging
** messages from the current folder.  The default is to pause one second, so
** a value of zero for this option suppresses the pause.
*/

{ "smart_wrap", DT_BOOL, true },
/*
** .pp
** Controls the display of lines longer than the screen width in the
** internal pager. If \fIset\fP, long lines are wrapped at a word boundary.  If
** \fIunset\fP, lines are simply wrapped at the screen edge. Also see the
** $$markers variable.
*/

{ "smileys", DT_REGEX, "(>From )|(:[-^]?[][)(><}{|/DP])" },
/*
** .pp
** The \fIpager\fP uses this variable to catch some common false
** positives of $$quote_regex, most notably smileys and not consider
** a line quoted text if it also matches $$smileys. This mostly
** happens at the beginning of a line.
*/

#ifdef CRYPT_BACKEND_CLASSIC_SMIME
{ "smime_ask_cert_label", DT_BOOL, true },
/*
** .pp
** This flag controls whether you want to be asked to enter a label
** for a certificate about to be added to the database or not. It is
** \fIset\fP by default.
** (S/MIME only)
*/

{ "smime_ca_location", DT_PATH, 0 },
/*
** .pp
** This variable contains the name of either a directory, or a file which
** contains trusted certificates for use with OpenSSL.
** (S/MIME only)
*/

{ "smime_certificates", DT_PATH, 0 },
/*
** .pp
** Since for S/MIME there is no pubring/secring as with PGP, NeoMutt has to handle
** storage and retrieval of keys by itself. This is very basic right
** now, and keys and certificates are stored in two different
** directories, both named as the hash-value retrieved from
** OpenSSL. There is an index file which contains mailbox-address
** keyid pairs, and which can be manually edited. This option points to
** the location of the certificates.
** (S/MIME only)
*/

{ "smime_decrypt_command", D_STRING_COMMAND, 0 },
/*
** .pp
** This format string specifies a command which is used to decrypt
** \fIapplication/pkcs7-mime\fP attachments.
** .pp
** The OpenSSL command formats have their own set of \fIprintf(3)\fP-like sequences
** similar to PGP's:
** .dl
** .dt %a .dd The algorithm used for encryption.
** .dt %c .dd One or more certificate IDs.
** .dt %C .dd CA location:  Depending on whether $$smime_ca_location
**            points to a directory or file, this expands to
**            "-CApath $$smime_ca_location" or "-CAfile $$smime_ca_location".
** .dt %d .dd The message digest algorithm specified with $$smime_sign_digest_alg.
** .dt %f .dd Expands to the name of a file containing a message.
** .dt %i .dd Intermediate certificates
** .dt %k .dd The key-pair specified with $$smime_default_key
** .dt %s .dd Expands to the name of a file containing the signature part
**            of a \fImultipart/signed\fP attachment when verifying it.
** .de
** .pp
** For examples on how to configure these formats, see the \fIsmime.rc\fP in
** the \fIsamples/\fP subdirectory which has been installed on your system
** alongside the documentation.
** (S/MIME only)
*/

{ "smime_decrypt_use_default_key", DT_BOOL, true },
/*
** .pp
** If \fIset\fP (default) this tells NeoMutt to use the default key for decryption. Otherwise,
** if managing multiple certificate-key-pairs, NeoMutt will try to use the mailbox-address
** to determine the key to use. It will ask you to supply a key, if it can't find one.
** (S/MIME only)
*/
#endif

{ "smime_default_key", DT_STRING, 0 },
/*
** .pp
** This is the default key-pair to use for S/MIME operations, and must be
** set to the keyid (the hash-value that OpenSSL generates) to work properly.
** .pp
** It will be used for encryption (see $$postpone_encrypt and
** $$smime_self_encrypt). If GPGME is enabled, this is the key id displayed
** by gpgsm.
** .pp
** It will be used for decryption unless $$smime_decrypt_use_default_key
** is \fIunset\fP.
** .pp
** It will also be used for signing unless $$smime_sign_as is set.
** .pp
** The (now deprecated) \fIsmime_self_encrypt_as\fP is an alias for this
** variable, and should no longer be used.
** (S/MIME only)
*/

#ifdef CRYPT_BACKEND_CLASSIC_SMIME
{ "smime_encrypt_command", D_STRING_COMMAND, 0 },
/*
** .pp
** This command is used to create encrypted S/MIME messages.
** .pp
** This is a format string, see the $$smime_decrypt_command command for
** possible \fIprintf(3)\fP-like sequences.
** (S/MIME only)
** .pp
** Encrypt the message to $$smime_default_key too.
** (S/MIME only)
*/
#endif

{ "smime_encrypt_with", DT_STRING, "aes256" },
/*
** .pp
** This sets the algorithm that should be used for encryption.
** Valid choices are "aes128", "aes192", "aes256", "des", "des3", "rc2-40", "rc2-64", "rc2-128".
** (S/MIME only)
*/

#ifdef CRYPT_BACKEND_CLASSIC_SMIME
{ "smime_get_cert_command", D_STRING_COMMAND, 0 },
/*
** .pp
** This command is used to extract X509 certificates from a PKCS7 structure.
** .pp
** This is a format string, see the $$smime_decrypt_command command for
** possible \fIprintf(3)\fP-like sequences.
** (S/MIME only)
*/

{ "smime_get_cert_email_command", D_STRING_COMMAND, 0 },
/*
** .pp
** This command is used to extract the mail address(es) used for storing
** X509 certificates, and for verification purposes (to check whether the
** certificate was issued for the sender's mailbox).
** .pp
** This is a format string, see the $$smime_decrypt_command command for
** possible \fIprintf(3)\fP-like sequences.
** (S/MIME only)
*/

{ "smime_get_signer_cert_command", D_STRING_COMMAND, 0 },
/*
** .pp
** This command is used to extract only the signers X509 certificate from a S/MIME
** signature, so that the certificate's owner may get compared to the
** email's "From:" field.
** .pp
** This is a format string, see the $$smime_decrypt_command command for
** possible \fIprintf(3)\fP-like sequences.
** (S/MIME only)
*/

{ "smime_import_cert_command", D_STRING_COMMAND, 0 },
/*
** .pp
** This command is used to import a certificate via smime_keys.
** .pp
** This is a format string, see the $$smime_decrypt_command command for
** possible \fIprintf(3)\fP-like sequences.  NOTE: %c and %k will default
** to $$smime_sign_as if set, otherwise $$smime_default_key.
** (S/MIME only)
*/
#endif

{ "smime_is_default", DT_BOOL, false },
/*
** .pp
** The default behavior of NeoMutt is to use PGP on all auto-sign/encryption
** operations. To override and to use OpenSSL instead this must be \fIset\fP.
** However, this has no effect while replying, since NeoMutt will automatically
** select the same application that was used to sign/encrypt the original
** message.  (Note that this variable can be overridden by unsetting $$crypt_auto_smime.)
** (S/MIME only)
*/

#ifdef CRYPT_BACKEND_CLASSIC_SMIME
{ "smime_keys", DT_PATH, 0 },
/*
** .pp
** Since for S/MIME there is no pubring/secring as with PGP, NeoMutt has to handle
** storage and retrieval of keys/certs by itself. This is very basic right now,
** and stores keys and certificates in two different directories, both
** named as the hash-value retrieved from OpenSSL. There is an index file
** which contains mailbox-address keyid pair, and which can be manually
** edited. This option points to the location of the private keys.
** (S/MIME only)
*/

{ "smime_pk7out_command", D_STRING_COMMAND, 0 },
/*
** .pp
** This command is used to extract PKCS7 structures of S/MIME signatures,
** in order to extract the public X509 certificate(s).
** .pp
** This is a format string, see the $$smime_decrypt_command command for
** possible \fIprintf(3)\fP-like sequences.
** (S/MIME only)
*/
#endif

{ "smime_self_encrypt", DT_BOOL, true },
/*
** .pp
** When \fIset\fP, S/MIME encrypted messages will also be encrypted
** using the certificate in $$smime_default_key.
** (S/MIME only)
*/

{ "smime_sign_as", DT_STRING, 0 },
/*
** .pp
** If you have a separate key to use for signing, you should set this
** to the signing key. Most people will only need to set $$smime_default_key.
** (S/MIME only)
*/

#ifdef CRYPT_BACKEND_CLASSIC_SMIME
{ "smime_sign_command", D_STRING_COMMAND, 0 },
/*
** .pp
** This command is used to created S/MIME signatures of type
** \fImultipart/signed\fP, which can be read by all mail clients.
** .pp
** This is a format string, see the $$smime_decrypt_command command for
** possible \fIprintf(3)\fP-like sequences.
** (S/MIME only)
*/

{ "smime_sign_digest_alg", DT_STRING, "sha256" },
/*
** .pp
** This sets the algorithm that should be used for the signature message digest.
** Valid choices are "md5", "sha1", "sha224", "sha256", "sha384", "sha512".
** (S/MIME only)
*/

{ "smime_timeout", DT_NUMBER, 300 },
/*
** .pp
** The number of seconds after which a cached passphrase will expire if
** not used.
** (S/MIME only)
*/

{ "smime_verify_command", D_STRING_COMMAND, 0 },
/*
** .pp
** This command is used to verify S/MIME signatures of type \fImultipart/signed\fP.
** .pp
** This is a format string, see the $$smime_decrypt_command command for
** possible \fIprintf(3)\fP-like sequences.
** (S/MIME only)
*/

{ "smime_verify_opaque_command", D_STRING_COMMAND, 0 },
/*
** .pp
** This command is used to verify S/MIME signatures of type
** \fIapplication/pkcs7-mime\fP.
** .pp
** This is a format string, see the $$smime_decrypt_command command for
** possible \fIprintf(3)\fP-like sequences.
** (S/MIME only)
*/
#endif

{ "smtp_authenticators", DT_SLIST, 0 },
/*
** .pp
** This is a colon-separated list of authentication methods NeoMutt may
** attempt to use to log in to an SMTP server, in the order NeoMutt should
** try them.  Authentication methods are any SASL mechanism, e.g. "plain",
** "digest-md5", "gssapi" or "cram-md5".
** This option is case-insensitive. If it is "unset"
** (the default) NeoMutt will try all available methods, in order from
** most-secure to least-secure. Support for the "plain" mechanism is
** bundled; other mechanisms are provided by an external SASL library (look
** for '+sasl' in the output of neomutt -v).
** .pp
** Example:
** .ts
** set smtp_authenticators="digest-md5:cram-md5"
** .te
*/

{ "smtp_oauth_refresh_command", D_STRING_COMMAND, 0 },
/*
** .pp
** The command to run to generate an OAUTH refresh token for
** authorizing your connection to your SMTP server.  This command will be
** run on every connection attempt that uses the OAUTHBEARER or XOAUTH2
** authentication mechanisms.  See "$oauth" for details.
*/

{ "smtp_pass", DT_STRING, 0 },
/*
** .pp
** Specifies the password for your SMTP account.  If \fIunset\fP, NeoMutt will
** prompt you for your password when you first send mail via SMTP.
** See $$smtp_url to configure NeoMutt to send mail via SMTP.
** .pp
** \fBWarning\fP: you should only use this option when you are on a
** fairly secure machine, because the superuser can read your neomuttrc even
** if you are the only one who can read the file.
*/

{ "smtp_url", DT_STRING, 0 },
/*
** .pp
** Defines the SMTP smarthost where sent messages should relayed for
** delivery. This should take the form of an SMTP URL, e.g.:
** .ts
** smtp[s]://[user[:pass]@]host[:port]
** .te
** .pp
** where "[...]" denotes an optional part.
** Setting this variable overrides the value of the $$sendmail
** variable.
** .pp
** Also see $$write_bcc.
*/

{ "smtp_user", DT_STRING, 0 },
/*
** .pp
** The username for the SMTP server.
** .pp
** This variable defaults to your user name on the local machine.
*/

{ "socket_timeout", DT_NUMBER, 30 },
/*
** .pp
** Causes NeoMutt to timeout any socket connect/read/write operation (for IMAP,
** POP or SMTP) after this many seconds.  A negative value causes NeoMutt to
** wait indefinitely.
*/

{ "sort", DT_SORT, EMAIL_SORT_DATE },
/*
** .pp
** Specifies how to sort messages in the "index" menu.  Valid values
** are:
** .il
** .dd date
** .dd date-received
** .dd from
** .dd label
** .dd score
** .dd size
** .dd spam
** .dd subject
** .dd threads
** .dd to
** .dd unsorted
** .ie
** .pp
** You may optionally use the "reverse-" prefix to specify reverse
** sorting order, or the "last-" prefix to sort threads based on the
** corresponding attribute of the last descendant rather than the
** thread root.  If both prefixes are in use, "reverse-" must come
** before "last-".  The "last-" prefix has no effect on a flat view.
** .pp
** Any ties in the primary sort are broken by $$sort_aux.  When
** $$use_threads is "threads" or "reverse", $$sort controls the
** sorting between threads, and $$sort_aux controls the sorting within
** a thread.
** .pp
** The "date-sent" value is a synonym for "date". The "mailbox-order" value is
** a synonym for "unsorted".
** .pp
** The values of "threads" and "reverse-threads" are legacy options,
** which cause the value of \fI$$sort_aux\fP to also control sorting
** between threads, and they may not be used with the "last-" prefix.
** The preferred way to enable a threaded view is via
** \fI$$use_threads\fP.  This variable can also be set via the
** \fI<sort-mailbox>\fP and \fI<sort-reverse>\fP functions.
** .pp
** Note: When $$use_threads is "threads", the last thread sorts to the
** bottom; when it is "reversed", the last thread sorts to the top.
** The use of "reverse-" in $$sort swaps which end the last thread
** will sort to.
** .pp
** See the "Use Threads Feature" section for further explanation and
** examples, https://neomutt.org/feature/use-threads
*/

{ "sort_aux", DT_SORT, EMAIL_SORT_DATE },
/*
** .pp
** This provides a secondary sort for messages in the "index" menu, used
** when the $$sort value is equal for two messages.
** .pp
** When sorting by threads, this variable controls how subthreads are
** sorted within a single thread (for the order between threads, see
** $$sort).  This can be set to any value that $$sort can, including
** with the use of "reverse-" and "last-" prefixes, except for
** variations using "threads" (in that case, NeoMutt will just use
** "date").  For instance,
** .ts
** set sort_aux=last-date-received
** .te
** .pp
** would mean that if a new message is received in a thread, that
** subthread becomes the last one displayed (or the first, if you have
** "\fIset use_threads=reverse\fP".)  When using $$use_threads, it is
** more common to use "last-" with $$sort and not with $$sort_aux.
** .pp
** See the "Use Threads Feature" section for further explanation and
** examples, https://neomutt.org/feature/use-threads
*/

{ "sort_re", DT_BOOL, true },
/*
** .pp
** This variable is only useful when sorting by threads with $$strict_threads
** \fIunset\fP.  In that case, it changes the heuristic neomutt uses to thread
** messages by subject.  With $$sort_re \fIset\fP, neomutt will only attach a
** message as the child of another message by subject if the subject of the
** child message starts with a substring matching the setting of
** $$reply_regex.  With $$sort_re \fIunset\fP, neomutt will attach the message
** whether or not this is the case, as long as the non-$$reply_regex parts of
** both messages are identical.
*/

{ "spam_separator", DT_STRING, "," },
/*
** .pp
** This variable controls what happens when multiple spam headers
** are matched: if \fIunset\fP, each successive header will overwrite any
** previous matches value for the spam label. If \fIset\fP, each successive
** match will append to the previous, using this variable's value as a
** separator.
*/

{ "spool_file", D_STRING_MAILBOX, 0 },
/*
** .pp
** If your spool mailbox is in a non-default place where NeoMutt can't find
** it, you can specify its location with this variable. The description from
** "named-mailboxes" or "virtual-mailboxes" may be used for the spool_file.
** .pp
** If not specified, then the environment variables \fI$$$MAIL\fP and
** \fI$$$MAILDIR\fP will be checked.
*/

#ifdef USE_SSL_GNUTLS
{ "ssl_ca_certificates_file", DT_PATH, 0 },
/*
** .pp
** This variable specifies a file containing trusted CA certificates.
** Any server certificate that is signed with one of these CA
** certificates is also automatically accepted. (GnuTLS only)
** .pp
** Example:
** .ts
** set ssl_ca_certificates_file=/etc/ssl/certs/ca-certificates.crt
** .te
*/
#endif

#ifdef USE_SSL
{ "ssl_ciphers", DT_STRING, 0 },
/*
** .pp
** Contains a colon-separated list of ciphers to use when using SSL.
** For OpenSSL, see ciphers(1) for the syntax of the string.
** .pp
** For GnuTLS, this option will be used in place of "NORMAL" at the
** start of the priority string.  See gnutls_priority_init(3) for the
** syntax and more details. (Note: GnuTLS version 2.1.7 or higher is
** required.)
*/

{ "ssl_client_cert", DT_PATH, 0 },
/*
** .pp
** The file containing a client certificate and its associated private
** key.
*/

{ "ssl_force_tls", DT_BOOL, true },
/*
** .pp
** If this variable is \fIset\fP, NeoMutt will require that all connections
** to remote servers be encrypted. Furthermore it will attempt to
** negotiate TLS even if the server does not advertise the capability,
** since it would otherwise have to abort the connection anyway. This
** option supersedes $$ssl_starttls.
*/
#endif

#ifdef USE_SSL_GNUTLS
{ "ssl_min_dh_prime_bits", DT_NUMBER, 0 },
/*
** .pp
** This variable specifies the minimum acceptable prime size (in bits)
** for use in any Diffie-Hellman key exchange. A value of 0 will use
** the default from the GNUTLS library. (GnuTLS only)
*/
#endif

#ifdef USE_SSL
{ "ssl_starttls", DT_QUAD, MUTT_YES },
/*
** .pp
** If \fIset\fP (the default), NeoMutt will attempt to use \fISTARTTLS\fP on servers
** advertising the capability. When \fIunset\fP, NeoMutt will not attempt to
** use \fISTARTTLS\fP regardless of the server's capabilities.
** .pp
** \fBNote\fP that \fISTARTTLS\fP is subject to many kinds of
** attacks, including the ability of a machine-in-the-middle to
** suppress the advertising of support.  Setting $$ssl_force_tls is
** recommended if you rely on \fISTARTTLS\fP.
*/
#endif

#ifdef USE_SSL_OPENSSL
{ "ssl_use_sslv2", DT_BOOL, false },
/*
** .pp
** If \fIset\fP , NeoMutt will use SSLv2 when communicating with servers that
** request it. \fBN.B. As of 2011, SSLv2 is considered insecure, and using
** is inadvisable\fP. See https://tools.ietf.org/html/rfc6176
** (OpenSSL only)
*/
#endif

#ifdef USE_SSL
{ "ssl_use_sslv3", DT_BOOL, false },
/*
** .pp
** If \fIset\fP , NeoMutt will use SSLv3 when communicating with servers that
** request it. \fBN.B. As of 2015, SSLv3 is considered insecure, and using
** it is inadvisable\fP. See https://tools.ietf.org/html/rfc7525
*/
#endif

#ifdef USE_SSL_OPENSSL
{ "ssl_use_system_certs", DT_BOOL, true },
/*
** .pp
** If set to \fIyes\fP, NeoMutt will use CA certificates in the
** system-wide certificate store when checking if a server certificate
** is signed by a trusted CA. (OpenSSL only)
*/
#endif

#ifdef USE_SSL
{ "ssl_use_tlsv1", DT_BOOL, false },
/*
** .pp
** If \fIset\fP , NeoMutt will use TLSv1.0 when communicating with servers that
** request it. \fBN.B. As of 2015, TLSv1.0 is considered insecure, and using
** it is inadvisable\fP. See https://tools.ietf.org/html/rfc7525
*/

{ "ssl_use_tlsv1_1", DT_BOOL, false },
/*
** .pp
** If \fIset\fP , NeoMutt will use TLSv1.1 when communicating with servers that
** request it. \fBN.B. As of 2015, TLSv1.1 is considered insecure, and using
** it is inadvisable\fP. See https://tools.ietf.org/html/rfc7525
*/

{ "ssl_use_tlsv1_2", DT_BOOL, true },
/*
** .pp
** If \fIset\fP , NeoMutt will use TLSv1.2 when communicating with servers that
** request it.
*/

{ "ssl_use_tlsv1_3", DT_BOOL, true },
/*
** .pp
** If \fIset\fP , NeoMutt will use TLSv1.3 when communicating with servers that
** request it.
*/

{ "ssl_verify_dates", DT_BOOL, true },
/*
** .pp
** If \fIset\fP (the default), NeoMutt will not automatically accept a server
** certificate that is either not yet valid or already expired. You should
** only unset this for particular known hosts, using the
** \fI$<account-hook>\fP function.
*/

{ "ssl_verify_host", DT_BOOL, true },
/*
** .pp
** If \fIset\fP (the default), NeoMutt will not automatically accept a server
** certificate whose host name does not match the host used in your folder
** URL. You should only unset this for particular known hosts, using
** the \fI$<account-hook>\fP function.
*/
#endif

#ifdef HAVE_SSL_PARTIAL_CHAIN
{ "ssl_verify_partial_chains", DT_BOOL, false },
/*
** .pp
** This option should not be changed from the default unless you understand
** what you are doing.
** .pp
** Setting this variable to \fIyes\fP will permit verifying partial
** certification chains, i. e. a certificate chain where not the root,
** but an intermediate certificate CA, or the host certificate, are
** marked trusted (in $$certificate_file), without marking the root
** signing CA as trusted.
** .pp
** (OpenSSL 1.0.2b and newer only).
*/
#endif

{ "status_chars", DT_MBTABLE, "-*%A" },
/*
** .pp
** Controls the characters used by the "%r" indicator in $$status_format.
** .dl
** .dt \fBCharacter\fP .dd \fBDefault\fP .dd \fBDescription\fP
** .dt 1 .dd - .dd Mailbox is unchanged
** .dt 2 .dd * .dd Mailbox has been changed and needs to be resynchronized
** .dt 3 .dd % .dd Mailbox is read-only, or will not be written when exiting.
**                 (You can toggle whether to write changes to a mailbox
**                 with the \fI<toggle-write>\fP operation, bound by default
**                 to "%")
** .dt 4 .dd A .dd Folder opened in attach-message mode.
**                 (Certain operations like composing a new mail, replying,
**                 forwarding, etc. are not permitted in this mode)
** .de
*/

{ "status_format", DT_STRING, "-%r-NeoMutt: %D [Msgs:%<M?%M/>%m%<n? New:%n>%<o? Old:%o>%<d? Del:%d>%<F? Flag:%F>%<t? Tag:%t>%<p? Post:%p>%<b? Inc:%b>%<l? %l>]---(%<T?%T/>%s/%S)-%>-(%P)---" },
/*
** .pp
** Controls the format of the status line displayed in the "index"
** menu.  This string is similar to $$index_format, but has its own
** set of \fIprintf(3)\fP-like sequences:
** .dl
** .dt %b  .dd * .dd Number of mailboxes with new mail
** .dt %d  .dd * .dd Number of deleted messages
** .dt %D  .dd   .dd Description of the mailbox
** .dt %f  .dd   .dd The full pathname of the current mailbox
** .dt %F  .dd * .dd Number of flagged messages
** .dt %h  .dd   .dd Local hostname
** .dt %l  .dd * .dd Size (in bytes) of the current mailbox (see $formatstrings-size)
** .dt %L  .dd * .dd Size (in bytes) of the messages shown
**                   (i.e., which match the current limit) (see $formatstrings-size)
** .dt %m  .dd * .dd The number of messages in the mailbox
** .dt %M  .dd * .dd The number of messages shown (i.e., which match the current limit)
** .dt %n  .dd * .dd Number of new messages in the mailbox (unread, unseen)
** .dt %o  .dd * .dd Number of old messages in the mailbox (unread, seen)
** .dt %p  .dd * .dd Number of postponed messages
** .dt %P  .dd   .dd Percentage of the way through the index
** .dt %r  .dd   .dd Modified/read-only/won't-write/attach-message indicator,
**                   According to $$status_chars
** .dt %R  .dd * .dd Number of read messages in the mailbox (read, seen)
** .dt %s  .dd   .dd Current sorting mode ($$sort)
** .dt %S  .dd   .dd Current aux sorting method ($$sort_aux)
** .dt %t  .dd * .dd Number of tagged messages in the mailbox
** .dt %T  .dd * .dd Current threading mode ($$use_threads)
** .dt %u  .dd * .dd Number of unread messages in the mailbox (seen or unseen)
** .dt %v  .dd   .dd NeoMutt version string
** .dt %V  .dd * .dd Currently active limit pattern, if any
** .dt %>X .dd   .dd Right justify the rest of the string and pad with "X"
** .dt %|X .dd   .dd Pad to the end of the line with "X"
** .dt %*X .dd   .dd Soft-fill with character "X" as pad
** .de
** .pp
** For an explanation of "soft-fill", see the $$index_format documentation.
** .pp
** * = can be optionally printed if nonzero
** .pp
** Some of the above sequences can be used to optionally print a string
** if their value is nonzero.  For example, you may only want to see the
** number of flagged messages if such messages exist, since zero is not
** particularly meaningful.  To optionally print a string based upon one
** of the above sequences, the following construct is used:
** .pp
**  \fI%<sequence_char?optional_string>\fP
** .pp
** where \fIsequence_char\fP is a character from the table above, and
** \fIoptional_string\fP is the string you would like printed if
** \fIsequence_char\fP is nonzero.  \fIoptional_string\fP \fBmay\fP contain
** other sequences as well as normal text.
** .pp
** Here is an example illustrating how to optionally print the number of
** new messages in a mailbox:
** .pp
** \fI%<n?%n new messages>\fP
** .pp
** You can also switch between two strings using the following construct:
** .pp
** \fI%<sequence_char?if_string&else_string>\fP
** .pp
** If the value of \fIsequence_char\fP is non-zero, \fIif_string\fP will
** be expanded, otherwise \fIelse_string\fP will be expanded.
** .pp
** As another example, here is how to show either $$sort and
** $$sort_aux or $$use_threads and $$sort, based on whether threads
** are enabled with $$use_threads:
** .pp
** \fI%<T?%s/%S&%T/%s>\fP
** .pp
** You can force the result of any \fIprintf(3)\fP-like sequence to be lowercase
** by prefixing the sequence character with an underscore ("_") sign.
** For example, if you want to display the local hostname in lowercase,
** you would use: "\fI%_h\fP".
** .pp
** If you prefix the sequence character with a colon (":") character, NeoMutt
** will replace any dots in the expansion by underscores. This might be helpful
** with IMAP folders that don't like dots in folder names.
*/

{ "status_on_top", DT_BOOL, false },
/*
** .pp
** Setting this variable causes the "status bar" to be displayed on
** the first line of the screen rather than near the bottom. If $$help
** is \fIset\fP too, it'll be placed at the bottom.
*/

{ "strict_threads", DT_BOOL, false },
/*
** .pp
** If \fIset\fP, threading will only make use of the "In-Reply-To" and
** "References:" fields when you $$sort by message threads.  By
** default, messages with the same subject are grouped together in
** "pseudo threads.". This may not always be desirable, such as in a
** personal mailbox where you might have several unrelated messages with
** the subjects like "hi" which will get grouped together. See also
** $$sort_re for a less drastic way of controlling this
** behavior.
*/

{ "suspend", DT_BOOL, true },
/*
** .pp
** When \fIunset\fP, NeoMutt won't stop when the user presses the terminal's
** \fIsusp\fP key, usually "^Z". This is useful if you run NeoMutt
** inside an xterm using a command like "\fIxterm -e neomutt\fP".
** .pp
** On startup NeoMutt tries to detect if it is the process session leader.
** If so, the default of $suspend is "no" otherwise "yes".  This default covers
** the above mentioned use case of "\fIxterm -e neomutt\fP".
*/

{ "text_flowed", DT_BOOL, false },
/*
** .pp
** When \fIset\fP, NeoMutt will generate "format=flowed" bodies with a content type
** of "\fItext/plain; format=flowed\fP".
** This format is easier to handle for some mailing software, and generally
** just looks like ordinary text.  To actually make use of this format's
** features, you'll need support in your editor.
** .pp
** The option only controls newly composed messages.  Postponed messages,
** resent messages, and draft messages (via -H on the command line) will
** use the content-type of the source message.
** .pp
** Note that $$indent_string is ignored when this option is \fIset\fP.
*/

{ "thorough_search", DT_BOOL, true },
/*
** .pp
** Affects the \fI~b\fP, \fI~B\fP, and \fI~h\fP search operations described in
** section "$patterns".  If \fIset\fP, the headers and body/attachments of
** messages to be searched are decoded before searching. If \fIunset\fP,
** messages are searched as they appear in the folder.
** .pp
** Users searching attachments or for non-ASCII characters should \fIset\fP
** this value because decoding also includes MIME parsing/decoding and possible
** character set conversions. Otherwise NeoMutt will attempt to match against the
** raw message received (for example quoted-printable encoded or with encoded
** headers) which may lead to incorrect search results.
*/

{ "thread_received", DT_BOOL, false },
/*
** .pp
** If $$strict_threads is \fIunset\fP, then messages may also be grouped by
** subject.  Unlike threading by "In-Reply-To:" and "References:" header,
** grouping by subject does not imply a parent-child relation between two
** messages.
** .pp
** To determine the ancestry between messages grouped by subject, Neomutt uses
** their date: only newer messages can be descendants of older ones.
** .pp
** When $$thread_received is \fIset\fP, NeoMutt uses the date received rather
** than the date sent when comparing messages for the date.
** .pp
** See also $$strict_threads, and $$sort_re.
*/

{ "tilde", DT_BOOL, false },
/*
** .pp
** When \fIset\fP, the internal-pager will pad blank lines to the bottom of the
** screen with a tilde ("~").
*/

{ "time_inc", DT_NUMBER, 0 },
/*
** .pp
** Along with $$read_inc, $$write_inc, and $$net_inc, this
** variable controls the frequency with which progress updates are
** displayed. It suppresses updates less than $$time_inc milliseconds
** apart. This can improve throughput on systems with slow terminals,
** or when running NeoMutt on a remote system.
** .pp
** Also see the "$tuning" section of the manual for performance considerations.
*/

{ "timeout", DT_NUMBER, 600 },
/*
** .pp
** When NeoMutt is waiting for user input either idling in menus or
** in an interactive prompt, NeoMutt would block until input is
** present. Depending on the context, this would prevent certain
** operations from working, like checking for new mail or keeping
** an IMAP connection alive.
** .pp
** This variable controls how many seconds NeoMutt will at most wait
** until it aborts waiting for input, performs these operations and
** continues to wait for input.
** .pp
** A value of zero or less will cause NeoMutt to never time out.
*/

{ "tmp_dir", DT_PATH, TMPDIR },
/*
** .pp
** This variable allows you to specify where NeoMutt will place its
** temporary files needed for displaying and composing messages.
** .pp
** If this variable is not set, the environment variable \fI$$$TMPDIR\fP is
** used.  Failing that, then "\fI/tmp\fP" is used.
*/

{ "to_chars", DT_MBTABLE, " +TCFLR" },
/*
** .pp
** Controls the character used to indicate mail addressed to you.
** .dl
** .dt \fBCharacter\fP .dd \fBDefault\fP .dd \fBDescription\fP
** .dt 1 .dd <space> .dd The mail is \fInot\fP addressed to your address.
** .dt 2 .dd + .dd You are the only recipient of the message.
** .dt 3 .dd T .dd Your address appears in the "To:" header field, but you are not the only recipient of the message.
** .dt 4 .dd C .dd Your address is specified in the "Cc:" header field, but you are not the only recipient.
** .dt 5 .dd F .dd Indicates the mail that was sent by \fIyou\fP.
** .dt 6 .dd L .dd Indicates the mail was sent to a mailing-list you subscribe to.
** .dt 7 .dd R .dd Your address appears in the "Reply-To:" header field but none of the above applies.
** .de
*/

{ "toggle_quoted_show_levels", DT_NUMBER, 0 },
/*
** .pp
** Quoted text may be filtered out using the \fI<toggle-quoted>\fP command.
** If set to a number greater than 0, then the \fI<toggle-quoted>\fP
** command will only filter out quote levels above this number.
*/

{ "trash", D_STRING_MAILBOX, 0 },
/*
** .pp
** If set, this variable specifies the path of the trash folder where the
** mails marked for deletion will be moved, instead of being irremediably
** purged.
** .pp
** NOTE: When you delete a message in the trash folder, it is really
** deleted, so that you have a way to clean the trash.
*/

{ "ts_enabled", DT_BOOL, false },
/*
** .pp
** Controls whether NeoMutt tries to set the terminal status line and icon name.
** Most terminal emulators emulate the status line in the window title.
*/

{ "ts_icon_format", DT_STRING, "M%<n?AIL&ail>" },
/*
** .pp
** Controls the format of the icon title, as long as "$$ts_enabled" is set.
** This string is identical in formatting to the one used by
** "$$status_format".
*/

{ "ts_status_format", DT_STRING, "NeoMutt with %<m?%m messages&no messages>%<n? [%n NEW]>" },
/*
** .pp
** Controls the format of the terminal status line (or window title),
** provided that "$$ts_enabled" has been set. This string is identical in
** formatting to the one used by "$$status_format".
*/

{ "tunnel", D_STRING_COMMAND, 0 },
/*
** .pp
** Setting this variable will cause NeoMutt to open a pipe to a command
** instead of a raw socket. You may be able to use this to set up
** preauthenticated connections to your IMAP/POP3/SMTP server. Example:
** .ts
** set tunnel="ssh -q mailhost.net /usr/local/libexec/imapd"
** .te
** .pp
** Note: For this example to work you must be able to log in to the remote
** machine without having to enter a password.
** .pp
** When set, NeoMutt uses the tunnel for all remote connections.
** Please see "$account-hook" in the manual for how to use different
** tunnel commands per connection.
*/

{ "tunnel_is_secure", DT_BOOL, true },
/*
** .pp
** When \fIset\fP, NeoMutt will assume the $$tunnel connection does not need
** STARTTLS to be enabled.  It will also allow IMAP PREAUTH server
** responses inside a $tunnel to proceed.  This is appropriate if $$tunnel
** uses ssh or directly invokes the server locally.
** .pp
** When \fIunset\fP, NeoMutt will negotiate STARTTLS according to the
** $ssl_starttls and $ssl_force_tls variables.  If $ssl_force_tls is
** set, NeoMutt will abort connecting if an IMAP server responds with PREAUTH.
** This setting is appropriate if $$tunnel does not provide security and
** could be tampered with by attackers.
*/

{ "uncollapse_jump", DT_BOOL, false },
/*
** .pp
** When \fIset\fP, NeoMutt will jump to the next unread message, if any,
** when the current thread is \fIun\fPcollapsed.
*/

{ "uncollapse_new", DT_BOOL, true },
/*
** .pp
** When \fIset\fP, NeoMutt will automatically uncollapse any collapsed
** thread that receives a newly delivered message.  When
** \fIunset\fP, collapsed threads will remain collapsed. The
** presence of the newly delivered message will still affect index
** sorting, though.
*/

{ "use_8bit_mime", DT_BOOL, false },
/*
** .pp
** \fBWarning:\fP do not set this variable unless you are using a version
** of sendmail which supports the \fI-B8BITMIME\fP flag (such as sendmail
** 8.8.x) or you may not be able to send mail.
** .pp
** When \fIset\fP, NeoMutt will invoke $$sendmail with the \fI-B8BITMIME\fP
** flag when sending 8-bit messages to enable ESMTP negotiation.
*/

{ "use_domain", DT_BOOL, true },
/*
** .pp
** When \fIset\fP, NeoMutt will qualify all local addresses (ones without the
** "@host" portion) with the value of $$hostname.  If \fIunset\fP, no
** addresses will be qualified.
*/

{ "use_envelope_from", DT_BOOL, false },
/*
** .pp
** When \fIset\fP, NeoMutt will set the \fIenvelope\fP sender of the message.
** If $$envelope_from_address is \fIset\fP, it will be used as the sender
** address. If \fIunset\fP, NeoMutt will attempt to derive the sender from the
** "From:" header.
** .pp
** Note that this information is passed to sendmail command using the
** \fI-f\fP command line switch. Therefore setting this option is not useful
** if the $$sendmail variable already contains \fI-f\fP or if the
** executable pointed to by $$sendmail doesn't support the \fI-f\fP switch.
*/

{ "use_from", DT_BOOL, true },
/*
** .pp
** When \fIset\fP, NeoMutt will generate the "From:" header field when
** sending messages.  If \fIunset\fP, no "From:" header field will be
** generated unless the user explicitly sets one using the "$my_hdr"
** command.
*/

#ifdef HAVE_GETADDRINFO
{ "use_ipv6", DT_BOOL, true },
/*
** .pp
** When \fIset\fP, NeoMutt will look for IPv6 addresses of hosts it tries to
** contact.  If this option is \fIunset\fP, NeoMutt will restrict itself to IPv4 addresses.
** Normally, the default should work.
*/
#endif

{ "use_threads", DT_ENUM, UT_UNSET },
/*
** .pp
** The style of threading used in the index. May be one of "flat" (no
** threading), "threads" (threaded, with subthreads below root
** message) or "reverse" (threaded, with subthreads above root
** message). For convenience, the value "yes" is a synonym for
** "threads", and "no" is a synonym for "flat".
** .pp
** If this variable is never set, then \fI$$sort\fP controls whether
** threading is used, \fI$$sort_aux\fP controls both the sorting of
** threads and subthreads, and using \fI<sort-mailbox>\fP to select
** threads affects only \fI$$sort\fP.  Once this variable is set,
** attempting to set \fI$$sort\fP to a value using "threads" will
** warn, the value of \fI$$sort\fP controls the sorting between
** threads while \fI$$sort_aux\fP controls sorting within a thread,
** and \fI<sort-mailbox>\fP toggles \fI$$use_threads\fP.
** .pp
** Example:
** .ts
** set use_threads=yes
** .te
** .pp
** See the "Use Threads Feature" section for further explanation and
** examples.
*/

{ "user_agent", DT_BOOL, false },
/*
** .pp
** When \fIset\fP, NeoMutt will add a "User-Agent:" header to outgoing
** messages, indicating which version of NeoMutt was used for composing
** them.
*/

#ifdef USE_NOTMUCH
{ "virtual_spool_file", DT_BOOL, false },
/*
** .pp
** This command is now unnecessary. $$spool_file has been extended to support
** mailbox descriptions as a value.
** .pp
** When \fIset\fP, NeoMutt will use the first defined virtual mailbox (see
** virtual-mailboxes) as a spool file.
*/
#endif

{ "wait_key", DT_BOOL, true },
/*
** .pp
** Controls whether NeoMutt will ask you to press a key after an external command
** has been invoked by these functions: \fI<shell-escape>\fP,
** \fI<pipe-message>\fP, \fI<pipe-entry>\fP, \fI<print-message>\fP,
** and \fI<print-entry>\fP commands.
** .pp
** It is also used when viewing attachments with "$auto_view", provided
** that the corresponding mailcap entry has a \fIneedsterminal\fP flag,
** and the external program is interactive.
** .pp
** When \fIset\fP, NeoMutt will always ask for a key. When \fIunset\fP, NeoMutt will wait
** for a key only if the external command returned a non-zero status.
*/

{ "weed", DT_BOOL, true },
/*
** .pp
** When \fIset\fP, NeoMutt will weed headers when displaying, forwarding,
** or replying to messages.
** .pp
** Also see $$copy_decode_weed, $$pipe_decode_weed, $$print_decode_weed.
*/

{ "wrap", DT_NUMBER, 0 },
/*
** .pp
** When set to a positive value, NeoMutt will wrap text at $$wrap characters.
** When set to a negative value, NeoMutt will wrap text so that there are $$wrap
** characters of empty space on the right side of the terminal. Setting it
** to zero makes NeoMutt wrap at the terminal width.
** .pp
** Also see $$reflow_wrap.
*/

{ "wrap_headers", DT_NUMBER, 78 },
/*
** .pp
** This option specifies the number of characters to use for wrapping
** an outgoing message's headers. Allowed values are between 78 and 998
** inclusive.
** .pp
** \fBNote:\fP This option usually shouldn't be changed. RFC5233
** recommends a line length of 78 (the default), so \fBplease only change
** this setting when you know what you're doing\fP.
*/

{ "wrap_search", DT_BOOL, true },
/*
** .pp
** Controls whether searches wrap around the end.
** .pp
** When \fIset\fP, searches will wrap around the first (or last) item. When
** \fIunset\fP, incremental searches will not wrap.
*/

{ "write_bcc", DT_BOOL, false },
/*
** .pp
** Controls whether NeoMutt writes out the "Bcc:" header when
** preparing messages to be sent.  Some MTAs, such as Exim and
** Courier, do not strip the "Bcc:" header; so it is advisable to
** leave this unset unless you have a particular need for the header
** to be in the sent message.
** .pp
** If NeoMutt is set to deliver directly via SMTP(see $$smtp_url),
** this option does nothing: NeoMutt will never write out the "Bcc:"
** header in this case.
** .pp
** Note this option only affects the sending of messages.  Fcc'ed
** copies of a message will always contain the "Bcc:" header if
** one exists.
*/

{ "write_inc", DT_NUMBER, 10 },
/*
** .pp
** When writing a mailbox, a message will be printed every
** $$write_inc messages to indicate progress.  If set to 0, only a
** single message will be displayed before writing a mailbox.
** .pp
** Also see the $$read_inc, $$net_inc and $$time_inc variables and the
** "$tuning" section of the manual for performance considerations.
*/

{ "x_comment_to", DT_BOOL, false },
/*
** .pp
** If \fIset\fP, NeoMutt will add "X-Comment-To:" field (that contains full
** name of original article author) to article that followuped to newsgroup.
*/
// clang-format on
/*--*/
