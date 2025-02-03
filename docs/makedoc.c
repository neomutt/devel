/**
 * @file
 * Read nroff-like comments in the code and convert them into documentation
 *
 * @authors
 * Copyright (C) 1999-2000 Thomas Roessler <roessler@does-not-exist.org>
 * Copyright (C) 2016-2023 Richard Russon <rich@flatcap.org>
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

/*
 * This program parses neomutt's config.c and generates documentation in
 * three different formats:
 *
 * -> a commented neomuttrc configuration file
 * -> nroff, suitable for inclusion in a manual page
 * -> docbook-xml, suitable for inclusion in the SGML-based manual
 */

/*
 * Documentation line parser
 *
 * The following code parses specially formatted documentation
 * comments in config.c
 *
 * The format is very remotely inspired by nroff. Most important, it's
 * easy to parse and convert, and it was easy to generate from the SGML
 * source of neomutt's original manual.
 *
 * - \fI switches to italics
 * - \fB switches to boldface
 * - \fP switches to normal display
 * - .dl on a line starts a definition list (name taken taken from HTML).
 * - .dt starts a term in a definition list.
 * - .dd starts a definition in a definition list.
 * - .de on a line finishes a definition list.
 * - .il on a line starts an itemized list
 * - .dd starts an item in an itemized list
 * - .ie on a line finishes an itemized list
 * - .ts on a line starts a "tscreen" environment (name taken from SGML).
 * - .te on a line finishes this environment.
 * - .pp on a line starts a paragraph.
 * - \$word will be converted to a reference to word, where appropriate.
 *   Note that \$$word is possible as well.
 * - '. ' in the beginning of a line expands to two space characters.
 *   This is used to protect indentations in tables.
 */

#include "config.h"
#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include "makedoc_defs.h"

char *Progname = NULL;
short Debug = 0;
int fd_recurse = 0;

#define BUFSIZE 2048

// clang-format off
#define D_NL    (1 <<  0)
#define D_EM    (1 <<  1)
#define D_BF    (1 <<  2)
#define D_TAB   (1 <<  3)
#define D_NP    (1 <<  4)
#define D_INIT  (1 <<  5)
#define D_DL    (1 <<  6)
#define D_DT    (1 <<  7)
#define D_DD    (1 <<  8)
#define D_PA    (1 <<  9)
#define D_IL    (1 << 10)
#define D_TT    (1 << 11)
// clang-format on

/**
 * enum OutputFormats - Documentation output formats
 */
enum OutputFormats
{
  F_NONE, ///< Error, none selected
  F_CONF, ///< NeoMutt config file
  F_MAN,  ///< Manual page
  F_SGML, ///< DocBook XML
};

/**
 * enum SpecialChars - All specially-treated characters
 */
enum SpecialChars
{
  SP_START_EM,
  SP_START_BF,
  SP_END_FT,
  SP_NEWLINE,
  SP_NEWPAR,
  SP_END_PAR,
  SP_STR,
  SP_START_TAB,
  SP_END_TAB,
  SP_START_DL,
  SP_DT,
  SP_DD,
  SP_END_DD,
  SP_END_DL,
  SP_START_IL,
  SP_END_IL,
  SP_END_SECT,
  SP_REFER
};

/**
 * enum DataType - User-variable types
 */
enum DataType
{
  DT_NONE = 0,
  DT_ADDRESS,
  DT_BOOL,
  D_STRING_COMMAND,
  DT_ENUM,
  DT_LONG,
  D_STRING_MAILBOX,
  DT_MBTABLE,
  DT_NUMBER,
  DT_PATH,
  DT_QUAD,
  DT_REGEX,
  DT_SLIST,
  DT_SORT,
  DT_STRING,
  DT_SYNONYM,
};

struct VariableTypes
{
  char *machine;
  char *human;
};

struct VariableTypes types[] = {
  // clang-format off
  { "DT_NONE",    "-none-"             },
  { "DT_ADDRESS", "e-mail address"     },
  { "DT_BOOL",    "boolean"            },
  { "D_STRING_COMMAND", "command"            },
  { "DT_ENUM",    "enumeration"        },
  { "DT_LONG",    "number (long)"      },
  { "D_STRING_MAILBOX", "mailbox"            },
  { "DT_MBTABLE", "character string"   },
  { "DT_NUMBER",  "number"             },
  { "DT_PATH",    "path"               },
  { "DT_QUAD",    "quadoption"         },
  { "DT_REGEX",   "regular expression" },
  { "DT_SLIST",   "string list"        },
  { "DT_SORT",    "sort order"         },
  { "DT_STRING",  "string"             },
  { "DT_SYNONYM", NULL                 },
  { NULL,         NULL                 },
  // clang-format on
};

/* skip whitespace */

static char *skip_ws(char *s)
{
  while (*s && isspace((unsigned char) *s))
    s++;

  return s;
}

/* isolate a token */
static char *get_token(char *d, size_t l, char *s)
{
  static char single_char_tokens[] = "[]{},;|";
  char *t = NULL;
  bool is_quoted = false;
  char *dd = d;

  if (Debug)
    fprintf(stderr, "%s: get_token called for `%s'.\n", Progname, s);

  s = skip_ws(s);

  if (Debug > 1)
    fprintf(stderr, "%s: argument after skip_ws():  `%s'.\n", Progname, s);

  if (!*s)
  {
    if (Debug)
      fprintf(stderr, "%s: no more tokens on this line.\n", Progname);
    return NULL;
  }

  if (strchr(single_char_tokens, *s))
  {
    if (Debug)
      fprintf(stderr, "%s: found single character token `%c'.\n", Progname, *s);

    d[0] = *s++;
    d[1] = '\0';
    return s;
  }

  if (*s == '"')
  {
    if (Debug)
      fprintf(stderr, "%s: found quote character.\n", Progname);

    s++;
    is_quoted = true;
  }

  for (t = s; *t && --l > 0; t++)
  {
    if (*t == '\\' && !t[1])
      break;

    if (is_quoted && *t == '\\')
    {
      switch ((*d = *++t))
      {
        case 'n':
          *d = '\n';
          break;
        case 't':
          *d = '\t';
          break;
        case 'r':
          *d = '\r';
          break;
        case 'a':
          *d = '\a';
          break;
      }

      d++;
      continue;
    }

    if (is_quoted && (*t == '"'))
    {
      t++;
      break;
    }
    else if (!is_quoted && strchr(single_char_tokens, *t))
    {
      break;
    }
    else if (!is_quoted && isspace((unsigned char) *t))
    {
      break;
    }
    else
    {
      *d++ = *t;
    }
  }

  *d = '\0';

  if (Debug)
  {
    fprintf(stderr, "%s: Got %stoken: `%s'.\n", Progname, is_quoted ? "quoted " : "", dd);
    fprintf(stderr, "%s: Remainder: `%s'.\n", Progname, t);
  }

  return t;
}

static int sgml_fputc(int c, FILE *fp_out)
{
  switch (c)
  {
    /* the bare minimum for escaping */
    case '<':
      return fputs("&lt;", fp_out);
    case '>':
      return fputs("&gt;", fp_out);
    case '&':
      return fputs("&amp;", fp_out);
    default:
      return fputc(c, fp_out);
  }
}

static int sgml_fputs(const char *s, FILE *fp_out)
{
  for (; *s; s++)
    if (sgml_fputc((unsigned int) *s, fp_out) == EOF)
      return EOF;

  return 0;
}

/* print something. */

static int print_it(enum OutputFormats format, int special, char *str, FILE *fp_out, int docstat)
{
  int onl = docstat & (D_NL | D_NP);

  docstat &= ~(D_NL | D_NP | D_INIT);

  switch (format)
  {
    /* configuration file */
    case F_CONF:
    {
      switch (special)
      {
        static int Continuation = 0;

        case SP_END_FT:
          docstat &= ~(D_EM | D_BF | D_TT);
          break;
        case SP_START_BF:
          docstat |= D_BF;
          break;
        case SP_START_EM:
          docstat |= D_EM;
          break;
        case SP_NEWLINE:
        {
          if (onl)
          {
            docstat |= onl;
          }
          else
          {
            fputs("\n# ", fp_out);
            docstat |= D_NL;
          }
          if (docstat & D_DL)
            Continuation++;
          break;
        }
        case SP_NEWPAR:
        {
          if (onl & D_NP)
          {
            docstat |= onl;
            break;
          }

          if (!(onl & D_NL))
            fputs("\n# ", fp_out);
          fputs("\n# ", fp_out);
          docstat |= D_NP;
          break;
        }
        case SP_START_TAB:
        {
          if (!onl)
            fputs("\n# ", fp_out);
          docstat |= D_TAB;
          break;
        }
        case SP_END_TAB:
        {
          docstat &= ~D_TAB;
          docstat |= D_NL;
          break;
        }
        case SP_START_DL:
        {
          docstat |= D_DL;
          break;
        }
        case SP_DT:
        {
          Continuation = 0;
          docstat |= D_DT;
          break;
        }
        case SP_DD:
        {
          if (docstat & D_IL)
            fputs("- ", fp_out);
          Continuation = 0;
          break;
        }
        case SP_END_DL:
        {
          Continuation = 0;
          docstat &= ~D_DL;
          break;
        }
        case SP_START_IL:
        {
          docstat |= D_IL;
          break;
        }
        case SP_END_IL:
        {
          Continuation = 0;
          docstat &= ~D_IL;
          break;
        }
        case SP_STR:
        {
          if (Continuation)
          {
            Continuation = 0;
            fputs("        ", fp_out);
          }
          fputs(str, fp_out);
          if (docstat & D_DT)
          {
            for (int i = strlen(str); i < 8; i++)
              putc(' ', fp_out);
            docstat &= ~D_DT;
            docstat |= D_NL;
          }
          break;
        }
      }
      break;
    }

    /* manual page */
    case F_MAN:
    {
      switch (special)
      {
        case SP_END_FT:
        {
          fputs("\\fP", fp_out);
          docstat &= ~(D_EM | D_BF | D_TT);
          break;
        }
        case SP_START_BF:
        {
          fputs("\\fB", fp_out);
          docstat |= D_BF;
          docstat &= ~(D_EM | D_TT);
          break;
        }
        case SP_START_EM:
        {
          fputs("\\fI", fp_out);
          docstat |= D_EM;
          docstat &= ~(D_BF | D_TT);
          break;
        }
        case SP_NEWLINE:
        {
          if (onl)
            docstat |= onl;
          else
          {
            fputc('\n', fp_out);
            docstat |= D_NL;
          }
          break;
        }
        case SP_NEWPAR:
        {
          if (onl & D_NP)
          {
            docstat |= onl;
            break;
          }

          if (!(onl & D_NL))
            fputc('\n', fp_out);
          fputs(".IP\n", fp_out);

          docstat |= D_NP;
          break;
        }
        case SP_START_TAB:
        {
          fputs("\n.IP\n.EX\n", fp_out);
          docstat |= D_TAB | D_NL;
          break;
        }
        case SP_END_TAB:
        {
          fputs("\n.EE\n", fp_out);
          docstat &= ~D_TAB;
          docstat |= D_NL;
          break;
        }
        case SP_START_DL:
        {
          fputs(".RS\n.PD 0\n", fp_out);
          docstat |= D_DL;
          break;
        }
        case SP_DT:
        {
          fputs(".TP\n", fp_out);
          break;
        }
        case SP_DD:
        {
          if (docstat & D_IL)
            fputs(".TP\n\\(hy ", fp_out);
          else
            fputs("\n", fp_out);
          break;
        }
        case SP_END_DL:
        {
          fputs(".RE\n.PD 1", fp_out);
          docstat &= ~D_DL;
          break;
        }
        case SP_START_IL:
        {
          fputs(".RS\n.PD 0\n", fp_out);
          docstat |= D_IL;
          break;
        }
        case SP_END_IL:
        {
          fputs(".RE\n.PD 1", fp_out);
          docstat &= ~D_DL;
          break;
        }
        case SP_STR:
        {
          while (*str)
          {
            for (; *str; str++)
            {
              if (*str == '"')
              {
                fputs("\"", fp_out);
              }
              else if (*str == '\\')
              {
                fputs("\\\\", fp_out);
              }
              else if (*str == '-')
              {
                fputs("\\-", fp_out);
              }
              else if (strncmp(str, "``", 2) == 0)
              {
                fputs("\\(lq", fp_out);
                str++;
              }
              else if (strncmp(str, "''", 2) == 0)
              {
                fputs("\\(rq", fp_out);
                str++;
              }
              else
              {
                fputc(*str, fp_out);
              }
            }
          }
          break;
        }
      }
      break;
    }

    /* SGML based manual */
    case F_SGML:
    {
      switch (special)
      {
        case SP_END_FT:
        {
          if (docstat & D_EM)
            fputs("</emphasis>", fp_out);
          if (docstat & D_BF)
            fputs("</emphasis>", fp_out);
          if (docstat & D_TT)
            fputs("</literal>", fp_out);
          docstat &= ~(D_EM | D_BF | D_TT);
          break;
        }
        case SP_START_BF:
        {
          fputs("<emphasis role=\"bold\">", fp_out);
          docstat |= D_BF;
          docstat &= ~(D_EM | D_TT);
          break;
        }
        case SP_START_EM:
        {
          fputs("<emphasis>", fp_out);
          docstat |= D_EM;
          docstat &= ~(D_BF | D_TT);
          break;
        }
        case SP_NEWLINE:
        {
          if (onl)
          {
            docstat |= onl;
          }
          else
          {
            fputc('\n', fp_out);
            docstat |= D_NL;
          }
          break;
        }
        case SP_NEWPAR:
        {
          if (onl & D_NP)
          {
            docstat |= onl;
            break;
          }

          if (!(onl & D_NL))
            fputc('\n', fp_out);
          if (docstat & D_PA)
            fputs("</para>\n", fp_out);
          fputs("<para>\n", fp_out);

          docstat |= D_NP;
          docstat |= D_PA;

          break;
        }
        case SP_END_PAR:
        {
          fputs("</para>\n", fp_out);
          docstat &= ~D_PA;
          break;
        }
        case SP_START_TAB:
        {
          if (docstat & D_PA)
          {
            fputs("\n</para>\n", fp_out);
            docstat &= ~D_PA;
          }
          fputs("\n<screen>\n", fp_out);
          docstat |= D_TAB | D_NL;
          break;
        }
        case SP_END_TAB:
        {
          fputs("</screen>", fp_out);
          docstat &= ~D_TAB;
          docstat |= D_NL;
          break;
        }
        case SP_START_DL:
        {
          if (docstat & D_PA)
          {
            fputs("\n</para>\n", fp_out);
            docstat &= ~D_PA;
          }
          fputs("\n<informaltable>\n<tgroup cols=\"2\">\n<tbody>\n", fp_out);
          docstat |= D_DL;
          break;
        }
        case SP_DT:
        {
          fputs("<row><entry>", fp_out);
          break;
        }
        case SP_DD:
        {
          docstat |= D_DD;
          if (docstat & D_DL)
            fputs("</entry><entry>", fp_out);
          else
            fputs("<listitem><para>", fp_out);
          break;
        }
        case SP_END_DD:
        {
          if (docstat & D_DL)
            fputs("</entry></row>\n", fp_out);
          else
            fputs("</para></listitem>", fp_out);
          docstat &= ~D_DD;
          break;
        }
        case SP_END_DL:
        {
          fputs("</entry></row></tbody></tgroup></informaltable>\n", fp_out);
          docstat &= ~(D_DD | D_DL);
          break;
        }
        case SP_START_IL:
        {
          if (docstat & D_PA)
          {
            fputs("\n</para>\n", fp_out);
            docstat &= ~D_PA;
          }
          fputs("\n<itemizedlist>\n", fp_out);
          docstat |= D_IL;
          break;
        }
        case SP_END_IL:
        {
          fputs("</para></listitem></itemizedlist>\n", fp_out);
          docstat &= ~(D_DD | D_DL);
          break;
        }
        case SP_END_SECT:
        {
          fputs("</sect2>", fp_out);
          break;
        }
        case SP_STR:
        {
          if (docstat & D_TAB)
          {
            sgml_fputs(str, fp_out);
          }
          else
          {
            while (*str)
            {
              for (; *str; str++)
              {
                if (strncmp(str, "``", 2) == 0)
                {
                  fputs("<quote>", fp_out);
                  str++;
                }
                else if (strncmp(str, "''", 2) == 0)
                {
                  fputs("</quote>", fp_out);
                  str++;
                }
                else
                {
                  sgml_fputc(*str, fp_out);
                }
              }
            }
          }
          break;
        }
      }
      break;
    }

    default:
      break;
  }

  return docstat;
}

/* close eventually-open environments. */

static int flush_doc(enum OutputFormats format, int docstat, FILE *fp_out)
{
  if (docstat & D_INIT)
    return D_INIT;

  if (fd_recurse++)
  {
    fprintf(stderr, "%s: Internal error, recursion in flush_doc()!\n", Progname);
    exit(1);
  }

  if (docstat & D_PA)
    docstat = print_it(format, SP_END_PAR, NULL, fp_out, docstat);

  if (docstat & D_TAB)
    docstat = print_it(format, SP_END_TAB, NULL, fp_out, docstat);

  if (docstat & D_DL)
    docstat = print_it(format, SP_END_DL, NULL, fp_out, docstat);

  if (docstat & (D_EM | D_BF | D_TT))
    docstat = print_it(format, SP_END_FT, NULL, fp_out, docstat);

  print_it(format, SP_END_SECT, NULL, fp_out, docstat);
  print_it(format, SP_NEWLINE, NULL, fp_out, 0);

  fd_recurse--;
  return D_INIT;
}

static int commit_buf(enum OutputFormats format, char *buf, char **d, FILE *fp_out, int docstat)
{
  if (*d > buf)
  {
    **d = '\0';
    docstat = print_it(format, SP_STR, buf, fp_out, docstat);
    *d = buf;
  }

  return docstat;
}

/**
 * sgml_id_fputs - reduce CDATA to ID
 */
static int sgml_id_fputs(const char *s, FILE *fp_out)
{
  char id;

  if (*s == '<')
    s++;

  for (; *s; s++)
  {
    if (*s == '_')
      id = '-';
    else
      id = *s;

    if ((s[0] == '>') && (s[1] == '\0'))
      break;

    if (fputc((unsigned int) id, fp_out) == EOF)
      return EOF;
  }

  return 0;
}

static void print_ref(enum OutputFormats format, FILE *fp_out,
                      bool output_dollar, const char *ref)
{
  switch (format)
  {
    case F_CONF:
    case F_MAN:
      if (output_dollar)
        putc('$', fp_out);
      fputs(ref, fp_out);
      break;

    case F_SGML:
      fputs("<link linkend=\"", fp_out);
      sgml_id_fputs(ref, fp_out);
      fputs("\">", fp_out);
      if (output_dollar)
        fputc('$', fp_out);
      sgml_fputs(ref, fp_out);
      fputs("</link>", fp_out);
      break;

    default:
      break;
  }
}

static int handle_docline(enum OutputFormats format, char *l, FILE *fp_out, int docstat)
{
  char buf[BUFSIZE];
  char *s = NULL, *d = NULL;
  l = skip_ws(l);

  if (Debug)
    fprintf(stderr, "%s: handle_docline `%s'\n", Progname, l);

  if (strncmp(l, ".pp", 3) == 0)
    return print_it(format, SP_NEWPAR, NULL, fp_out, docstat);
  if (strncmp(l, ".ts", 3) == 0)
    return print_it(format, SP_START_TAB, NULL, fp_out, docstat);
  if (strncmp(l, ".te", 3) == 0)
    return print_it(format, SP_END_TAB, NULL, fp_out, docstat);
  if (strncmp(l, ".dl", 3) == 0)
    return print_it(format, SP_START_DL, NULL, fp_out, docstat);
  if (strncmp(l, ".de", 3) == 0)
    return print_it(format, SP_END_DL, NULL, fp_out, docstat);
  if (strncmp(l, ".il", 3) == 0)
    return print_it(format, SP_START_IL, NULL, fp_out, docstat);
  if (strncmp(l, ".ie", 3) == 0)
    return print_it(format, SP_END_IL, NULL, fp_out, docstat);
  if (strncmp(l, ". ", 2) == 0)
    *l = ' ';

  for (s = l, d = buf; *s; s++)
  {
    if (strncmp(s, "\\(as", 4) == 0)
    {
      *d++ = '*';
      s += 3;
    }
    else if (strncmp(s, "\\(rs", 4) == 0)
    {
      *d++ = '\\';
      s += 3;
    }
    else if (strncmp(s, "\\fI", 3) == 0)
    {
      docstat = commit_buf(format, buf, &d, fp_out, docstat);
      docstat = print_it(format, SP_START_EM, NULL, fp_out, docstat);
      s += 2;
    }
    else if (strncmp(s, "\\fB", 3) == 0)
    {
      docstat = commit_buf(format, buf, &d, fp_out, docstat);
      docstat = print_it(format, SP_START_BF, NULL, fp_out, docstat);
      s += 2;
    }
    else if (strncmp(s, "\\fP", 3) == 0)
    {
      docstat = commit_buf(format, buf, &d, fp_out, docstat);
      docstat = print_it(format, SP_END_FT, NULL, fp_out, docstat);
      s += 2;
    }
    else if (strncmp(s, ".dt", 3) == 0)
    {
      if (docstat & D_DD)
      {
        docstat = commit_buf(format, buf, &d, fp_out, docstat);
        docstat = print_it(format, SP_END_DD, NULL, fp_out, docstat);
      }
      docstat = commit_buf(format, buf, &d, fp_out, docstat);
      docstat = print_it(format, SP_DT, NULL, fp_out, docstat);
      s += 3;
    }
    else if (strncmp(s, ".dd", 3) == 0)
    {
      if ((docstat & D_IL) && (docstat & D_DD))
      {
        docstat = commit_buf(format, buf, &d, fp_out, docstat);
        docstat = print_it(format, SP_END_DD, NULL, fp_out, docstat);
      }
      docstat = commit_buf(format, buf, &d, fp_out, docstat);
      docstat = print_it(format, SP_DD, NULL, fp_out, docstat);
      s += 3;
    }
    else if (*s == '$')
    {
      bool output_dollar = false;
      char *ref = NULL;

      s++;
      if (*s == '$')
      {
        output_dollar = true;
        s++;
      }
      if (*s == '$')
      {
        *d++ = '$';
      }
      else
      {
        ref = s;
        while (isalnum((unsigned char) *s) || (*s && strchr("-_<>", *s)))
          s++;

        docstat = commit_buf(format, buf, &d, fp_out, docstat);
        const char save = *s;
        *s = '\0';
        print_ref(format, fp_out, output_dollar, ref);
        *s = save;
        s--;
      }
    }
    else
    {
      *d++ = *s;
    }
  }

  docstat = commit_buf(format, buf, &d, fp_out, docstat);
  return print_it(format, SP_NEWLINE, NULL, fp_out, docstat);
}

static int buf_to_type(const char *s)
{
  for (int type = DT_NONE; types[type].machine; type++)
    if (strcmp(types[type].machine, s) == 0)
      return type;

  return DT_NONE;
}

static void pretty_default(char *t, size_t l, const char *s, int type)
{
  memset(t, 0, l);
  l--;

  switch (type)
  {
    case DT_QUAD:
    {
      if (strcasecmp(s, "MUTT_YES") == 0)
        strncpy(t, "yes", l);
      else if (strcasecmp(s, "MUTT_NO") == 0)
        strncpy(t, "no", l);
      else if (strcasecmp(s, "MUTT_ASKYES") == 0)
        strncpy(t, "ask-yes", l);
      else if (strcasecmp(s, "MUTT_ASKNO") == 0)
        strncpy(t, "ask-no", l);
      break;
    }
    case DT_BOOL:
    {
      if (strcasecmp(s, "true") == 0)
        strncpy(t, "yes", l);
      else if (strcasecmp(s, "false") == 0)
        strncpy(t, "no", l);
      else if (atoi(s))
        strncpy(t, "yes", l);
      else
        strncpy(t, "no", l);
      break;
    }
    case DT_ENUM:
    {
      if (strcasecmp(s, "MUTT_MBOX") == 0)
        strncpy(t, "mbox", l);
      else if (strcasecmp(s, "MUTT_MMDF") == 0)
        strncpy(t, "mmdf", l);
      else if (strcasecmp(s, "MUTT_MH") == 0)
        strncpy(t, "mh", l);
      else if (strcasecmp(s, "MUTT_MAILDIR") == 0)
        strncpy(t, "maildir", l);
      else if (strcasecmp(s, "UT_UNSET") == 0)
        strncpy(t, "unset", l);
      break;
    }
    case DT_SORT:
    {
      const char *name = s;
      // heuristic! A constant of SORT_XYZ means "xyz"
      if (strncmp(s, "SORT_", 5) == 0)
      {
        name = s + 5;
      }
      else
      {
        // Or ABC_SORT_XYZ means "xyz"
        const char *underscore = strchr(s, '_');
        if ((underscore) && (strncmp(underscore + 1, "SORT_", 5) == 0))
        {
          name = underscore + 6;
        }
      }

      if (name == s)
        fprintf(stderr, "WARNING: expected prefix of SORT_ for type DT_SORT instead of %s\n", s);
      strncpy(t, name, l);
      for (; *t; t++)
        *t = tolower((unsigned char) *t);
      break;
    }
    case DT_ADDRESS:
    case D_STRING_COMMAND:
    case D_STRING_MAILBOX:
    case DT_MBTABLE:
    case DT_PATH:
    case DT_REGEX:
    case DT_SLIST:
    case DT_STRING:
    {
      if (strcmp(s, "0") == 0)
        break;
    }
      __attribute__((fallthrough));
    default:
    {
      strncpy(t, s, l);
      break;
    }
  }
}

static void char_to_escape(char *dest, unsigned int c)
{
  switch (c)
  {
    case '\r':
      strcpy(dest, "\\r");
      break;
    case '\n':
      strcpy(dest, "\\n");
      break;
    case '\t':
      strcpy(dest, "\\t");
      break;
    case '\f':
      strcpy(dest, "\\f");
      break;
    default:
      sprintf(dest, "\\%03o", c);
      break;
  }
}

static void conf_char_to_escape(unsigned int c, FILE *fp_out)
{
  char buf[16];
  char_to_escape(buf, c);
  fputs(buf, fp_out);
}

static void conf_print_strval(const char *v, FILE *fp_out)
{
  for (; *v; v++)
  {
    if ((*v < ' ') || (*v & 0x80))
    {
      conf_char_to_escape((unsigned int) *v, fp_out);
      continue;
    }

    if ((*v == '"') || (*v == '\\'))
      fputc('\\', fp_out);
    fputc(*v, fp_out);
  }
}

static const char *type2human(int type)
{
  return types[type].human;
}

/*
 * Configuration line parser
 *
 * The following code parses a line from config.c which declares
 * a configuration variable.
 */

static void man_print_strval(const char *v, FILE *fp_out)
{
  for (; *v; v++)
  {
    if ((*v < ' ') || (*v & 0x80))
    {
      fputc('\\', fp_out);
      conf_char_to_escape((unsigned int) *v, fp_out);
      continue;
    }

    if (*v == '"')
      fputs("\"", fp_out);
    else if (*v == '\\')
      fputs("\\\\", fp_out);
    else if (*v == '-')
      fputs("\\-", fp_out);
    else
      fputc(*v, fp_out);
  }
}

static void sgml_print_strval(const char *v, FILE *fp_out)
{
  char buf[16];
  for (; *v; v++)
  {
    if ((*v < ' ') || (*v & 0x80))
    {
      char_to_escape(buf, (unsigned int) *v);
      sgml_fputs(buf, fp_out);
      continue;
    }
    sgml_fputc((unsigned int) *v, fp_out);
  }
}

static void print_confline(enum OutputFormats format, const char *varname,
                           int type, const char *val, FILE *fp_out)
{
  if (type == DT_SYNONYM)
    return;

  switch (format)
  {
    /* configuration file */
    case F_CONF:
    {
      if ((type == DT_STRING) || (type == DT_REGEX) || (type == DT_ADDRESS) ||
          (type == D_STRING_MAILBOX) || (type == DT_MBTABLE) || (type == DT_SLIST) ||
          (type == DT_PATH) || (type == D_STRING_COMMAND))
      {
        fprintf(fp_out, "\n# set %s=\"", varname);
        conf_print_strval(val, fp_out);
        fputs("\"", fp_out);
      }
      else
      {
        fprintf(fp_out, "\n# set %s=%s", varname, val);
      }

      fprintf(fp_out, "\n#\n# Name: %s", varname);
      fprintf(fp_out, "\n# Type: %s", type2human(type));
      if ((type == DT_STRING) || (type == DT_REGEX) || (type == DT_ADDRESS) ||
          (type == D_STRING_MAILBOX) || (type == DT_MBTABLE) || (type == DT_SLIST) ||
          (type == DT_PATH) || (type == D_STRING_COMMAND))
      {
        fputs("\n# Default: \"", fp_out);
        conf_print_strval(val, fp_out);
        fputs("\"", fp_out);
      }
      else
      {
        fprintf(fp_out, "\n# Default: %s", val);
      }

      fputs("\n# ", fp_out);
      break;
    }

    /* manual page */
    case F_MAN:
    {
      fprintf(fp_out, "\n.TP\n.B %s\n", varname);
      fputs(".nf\n", fp_out);
      fprintf(fp_out, "Type: %s\n", type2human(type));
      if ((type == DT_STRING) || (type == DT_REGEX) || (type == DT_ADDRESS) ||
          (type == D_STRING_MAILBOX) || (type == DT_MBTABLE) || (type == DT_SLIST) ||
          (type == DT_PATH) || (type == D_STRING_COMMAND))
      {
        fputs("Default: \"", fp_out);
        man_print_strval(val, fp_out);
        fputs("\"\n", fp_out);
      }
      else
      {
        fputs("Default: ", fp_out);
        man_print_strval(val, fp_out);
        fputs("\n", fp_out);
      }

      fputs(".fi", fp_out);

      break;
    }

    /* SGML based manual */
    case F_SGML:
    {
      fputs("\n<sect2 id=\"", fp_out);
      sgml_id_fputs(varname, fp_out);
      fputs("\">\n<title>", fp_out);
      sgml_fputs(varname, fp_out);
      fprintf(fp_out, "</title>\n<literallayout>Type: %s", type2human(type));

      if ((type == DT_STRING) || (type == DT_REGEX) || (type == DT_ADDRESS) ||
          (type == D_STRING_MAILBOX) || (type == DT_MBTABLE) || (type == DT_SLIST) ||
          (type == DT_PATH) || (type == D_STRING_COMMAND))
      {
        if (val && (*val != '\0'))
        {
          fputs("\nDefault: <quote><literal>", fp_out);
          sgml_print_strval(val, fp_out);
          fputs("</literal></quote>", fp_out);
        }
        else
        {
          fputs("\nDefault: (empty)", fp_out);
        }
        fputs("</literallayout>\n", fp_out);
      }
      else
      {
        fprintf(fp_out, "\nDefault: %s</literallayout>\n", val);
      }
      break;
    }
    /* make gcc happy */
    default:
      break;
  }
}

static void handle_confline(enum OutputFormats format, char *s, FILE *fp_out)
{
  char varname[BUFSIZE];
  char buf[BUFSIZE];
  char tmp[BUFSIZE];
  char val[BUFSIZE];
  int type;

  /* xxx - put this into an actual state machine? */

  /* variable name */
  s = get_token(varname, sizeof(varname), s);
  if (!s)
    return;

  /* comma */
  s = get_token(buf, sizeof(buf), s);
  if (!s)
    return;

  /* type */
  s = get_token(buf, sizeof(buf), s);
  if (!s)
    return;

  type = buf_to_type(buf);

  /* comma */
  s = get_token(buf, sizeof(buf), s);
  if (!s)
    return;

  /* <default value> */
  s = get_token(tmp, sizeof(tmp), s);
  if (!s)
    return;

  // Look for unjoined strings (pre-processor artifacts)
  while ((s[0] == ' ') && (s[1] == '"'))
  {
    s = get_token(buf, sizeof(buf), s);
    strncpy(tmp + strlen(tmp), buf, sizeof(tmp) - strlen(tmp));
  }

  pretty_default(val, sizeof(val), tmp, type);
  print_confline(format, varname, type, val, fp_out);
}

static void makedoc(enum OutputFormats format, FILE *fp_in, FILE *fp_out)
{
  char buffer[BUFSIZE];
  char token[BUFSIZE];
  char *p = NULL;
  bool active = false;
  int line = 0;
  int docstat = D_INIT;

  while ((fgets(buffer, sizeof(buffer), fp_in)))
  {
    line++;
    p = strchr(buffer, '\n');
    if (!p)
    {
      fprintf(stderr, "%s: Line %d too long\n", Progname, line);
      exit(1);
    }
    else
    {
      *p = '\0';
    }

    p = get_token(token, sizeof(token), buffer);
    if (!p)
      continue;

    if (Debug)
      fprintf(stderr, "%s: line %d.  first token: \"%s\".\n", Progname, line, token);

    if (strcmp(token, "/*++*/") == 0)
    {
      active = true;
    }
    else if (strcmp(token, "/*--*/") == 0)
    {
      docstat = flush_doc(format, docstat, fp_out);
      active = false;
    }
    else if (active && ((strcmp(token, "/**") == 0) || (strcmp(token, "**") == 0)))
    {
      docstat = handle_docline(format, p, fp_out, docstat);
    }
    else if (active && (strcmp(token, "{") == 0))
    {
      docstat = flush_doc(format, docstat, fp_out);
      handle_confline(format, p, fp_out);
    }
  }
  flush_doc(format, docstat, fp_out);
  fputs("\n", fp_out);
}

int main(int argc, char *argv[])
{
  int c;
  FILE *fp = NULL;
  enum OutputFormats format = F_NONE;

  Progname = strrchr(argv[0], '/');
  if (Progname)
    Progname++;
  else
    Progname = argv[0];

  while ((c = getopt(argc, argv, "cmsd")) != EOF)
  {
    switch (c)
    {
      case 'c':
        format = F_CONF;
        break;
      case 'm':
        format = F_MAN;
        break;
      case 's':
        format = F_SGML;
        break;
      case 'd':
        Debug++;
        break;
      default:
      {
        fprintf(stderr, "%s: bad command line parameter.\n", Progname);
        exit(1);
      }
    }
  }

  if (optind != argc)
  {
    fp = fopen(argv[optind], "r");
    if (!fp)
    {
      fprintf(stderr, "%s: Can't open %s (%s).\n", Progname, argv[optind], strerror(errno));
      exit(1);
    }
  }
  else
  {
    fp = stdin;
  }

  if (format == F_NONE)
  {
    fprintf(stderr, "%s: No output format specified.\n", Progname);
    exit(1);
  }

  makedoc(format, fp, stdout);

  if (fp != stdin)
    fclose(fp);

  return 0;
}
