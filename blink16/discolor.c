/*-*- mode:c;indent-tabs-mode:nil;c-basic-offset:2;tab-width:8;coding:utf-8 -*-│
│vi: set net ft=c ts=2 sts=2 sw=2 fenc=utf-8                                :vi│
╞══════════════════════════════════════════════════════════════════════════════╡
│ Copyright 2022 Justine Alexandra Roberts Tunney                              │
│                                                                              │
│ Permission to use, copy, modify, and/or distribute this software for         │
│ any purpose with or without fee is hereby granted, provided that the         │
│ above copyright notice and this permission notice appear in all copies.      │
│                                                                              │
│ THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL                │
│ WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED                │
│ WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE             │
│ AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL         │
│ DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR        │
│ PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER               │
│ TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR             │
│ PERFORMANCE OF THIS SOFTWARE.                                                │
╚─────────────────────────────────────────────────────────────────────────────*/
#include <stdio.h>
#include <string.h>

#include "discolor.h"

#if BLINK16
struct highlight g_high = {
    .enabled = 1,
    .active = 0,
    //.keyword = 155,
    .keyword = 40,
    .reg = 215,
    .literal = 182,
    //.label = 221,
    .label = 1,
    .comment = 112,
    .quote = 215,
    .grey = 241,
    .symbol = 1
};

#else
struct highlight g_high = {
    .enabled = 1,
    .active = 0,
    //.keyword = 40,          // instruction
    //.reg = 215,             // register
    //.literal = 182,         // literal
    //.label = 221
    .label = 1,             // label:
    .comment = 112,
    .quote = 215,
    .grey = 241,            // op bytes
    .symbol = 1,            // symbol
};
#endif

char *highStart(char *p, int h) {
  if (g_high.enabled) {
    if (h == 1) {           /* special case for bold */
      p = stpcpy(p, "\033[1m");
      g_high.active = 2;
    } else if (h) {
      p = stpcpy(p, "\033[38;5;");
      p += snprintf(p, 12, "%u", h);
      p = stpcpy(p, "m");
      g_high.active = 1;
    }
  }
  return p;
}

char *highEnd(char *p) {
  if (g_high.enabled) {
    if (g_high.active == 2) {
      p = stpcpy(p, "\033[m");
    } else if (g_high.active) {
      p = stpcpy(p, "\033[39m");
    }
    g_high.active = 0;
  }
  return p;
}

char *colorInst(struct dis *d, char *str)
{
    static char buf[256];
    int i, startbytes = 0, startinst = 0;
    char *p = buf;

    if (d->flags & fDisAddr)
        startbytes += 6;
    if (d->flags & fDisCS)
        startbytes += 5;
    if (d->flags & fDisIP)
        startbytes += 5;
    startinst = startbytes;
    if (d->flags & fDisBytes)
        startinst += 6 * ((d->flags & fDisOctal)? 4: 3) - 1;

    for (i=0; i<startbytes; i++)
        *p++ = *str++;
    if (d->flags & fDisBytes) {
        p = highStart(p, g_high.grey);
        do {
            *p++ = *str++;
        }  while (i++ < startinst);
        p = highEnd(p);
    }
    p = highStart(p, g_high.keyword);
    do {
        *p++ = *str++;
    } while (*str && *str != ' ');
    p = highEnd(p);
    
    while (*str) {
        switch (*str) {
        case '%':
            p = highStart(p, g_high.reg);
            *p++ = *str++;
            *p++ = *str++;
            *p++ = *str++;
            p = highEnd(p);
            break;
        case '$':
            *p++ = *str++;
            p = highStart(p, g_high.literal);
            do {
                *p++ = *str++;
            } while (*str && *str != ',');
            p = highEnd(p);
            break;
        default:
            *p++ = *str++;
            break;
        }
    }
    *p = '\0';
    return buf;
}
