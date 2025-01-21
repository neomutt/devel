void gui(void)
{
  int rc = 0;
  SendFlags sendflags = SEND_NO_FLAGS;
  bool repeat_error = false;
  char *subject = NULL;
  struct Email *e = NULL;
  char *draft_file = NULL;
  char *include_file = NULL;
  struct ListHead attach = STAILQ_HEAD_INITIALIZER(attach);
  int argc = 0;
  int i = 0;
  char **argv = NULL;
  bool edit_infile = false;
  struct Buffer *expanded_infile = buf_pool_get();
  struct Buffer *tempfile = buf_pool_get();
  struct ConfigSet *cs = NULL;
  CliFlags flags = MUTT_CLI_NO_FLAGS;
  const char *const c_folder = cs_subset_string(NeoMutt->sub, "folder");
  bool explicit_folder = false;
  struct Buffer *folder = buf_pool_get();

  // --------------------------------------------------------------------------------
  // Postponed -> mutt_send_message() -> GUI
  //   none
  //   one
  //   many
  // REQUIREMENTS: ConfigSubset
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

  // --------------------------------------------------------------------------------
  // Send email
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

    if (rv != 0)
      goto main_curses; // TEST36: neomutt -H existing -s test john@example.com -E (cancel sending)
  }

  // --------------------------------------------------------------------------------
  // Failed send batch?
  else if (sendflags & SEND_BATCH)
  {
    /* This guards against invoking `neomutt < /dev/null` and accidentally
     * sending an email due to a my_hdr or other setting.  */
    mutt_error(_("No recipients specified"));
    goto main_curses;
  }

  // --------------------------------------------------------------------------------

  else
  {
    // --------------------------------------------------------------------------------
    // Open first mailbox
    //   new mail
    //   no mail
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

    // --------------------------------------------------------------------------------
    // Open list of all mailboxes
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

    // --------------------------------------------------------------------------------
    // Select initial folder
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

    // --------------------------------------------------------------------------------
    // NNTP override default mailbox
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

    // --------------------------------------------------------------------------------
    // Open first mailbox with mail
    //   or do nothing
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

    // Open Index - GUI
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

    // --------------------------------------------------------------------------------
    // Gui Cleanup
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

  // --------------------------------------------------------------------------------
main_ok:
main_curses:
}
