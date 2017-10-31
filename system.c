/**
 * @file
 * Execute external programs
 *
 * @authors
 * Copyright (C) 1996-2000,2013 Michael R. Elkins <me@mutt.org>
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

#include "config.h"
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include "mutt.h"
#include "protos.h"
#ifdef USE_IMAP
#include "imap/imap.h"
#endif
#include <sys/types.h>
#include <sys/wait.h>

int mutt_system(const char *cmd)
{
  int rc = -1;
  struct sigaction act;
  struct sigaction oldtstp;
  struct sigaction oldcont;
  pid_t thepid;

  if (!cmd || !*cmd)
    return 0;

  /* must ignore SIGINT and SIGQUIT */

  mutt_block_signals_system();

  act.sa_handler = SIG_DFL;
/* we want to restart the waitpid() below */
#ifdef SA_RESTART
  act.sa_flags = SA_RESTART;
#endif
  sigemptyset(&act.sa_mask);
  sigaction(SIGTSTP, &act, &oldtstp);
  sigaction(SIGCONT, &act, &oldcont);

  thepid = fork();
  if (thepid == 0)
  {
    act.sa_flags = 0;

    /* reset signals for the child; not really needed, but... */
    mutt_unblock_signals_system(0);
    act.sa_handler = SIG_DFL;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGTSTP, &act, NULL);
    sigaction(SIGCONT, &act, NULL);

    execle(EXECSHELL, "sh", "-c", cmd, NULL, mutt_envlist());
    _exit(127); /* execl error */
  }
  else if (thepid != -1)
  {
#ifdef USE_IMAP
    rc = imap_wait_keepalive(thepid);
#endif
  }

  sigaction(SIGCONT, &oldcont, NULL);
  sigaction(SIGTSTP, &oldtstp, NULL);

  /* reset SIGINT, SIGQUIT and SIGCHLD */
  mutt_unblock_signals_system(1);

  rc = (thepid != -1) ? (WIFEXITED(rc) ? WEXITSTATUS(rc) : -1) : -1;

  return rc;
}
