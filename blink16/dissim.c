/* symbol string functions for disasm */

#include <stdio.h>
#include <string.h>
#include "disasm.h"
#include "discolor.h"
#include "syms.h"
#include "exe.h"

char * getsymbol(struct dis *d, int seg, int offset)
{
    char *p;
    struct exe *e = d->e;
    static char buf[64];

    if (e && e->syms) {
        if (seg != 0 && seg == e->dataseg) {
            p = highStart(buf, g_high.symbol);
            p = stpcpy(p, sym_data_symbol(e, offset, 1));
            p = highEnd(p);
            *p = '\0';
            return buf;
        }
        if (seg != 0 && seg == e->ftextseg) {
            p = highStart(buf, g_high.symbol);
            p = stpcpy(p, sym_ftext_symbol(e, offset, 1));
            p = highEnd(p);
            *p = '\0';
            return buf;
        }
        if (seg == e->textseg) {
            p = highStart(buf, g_high.symbol);
            p = stpcpy(p, sym_text_symbol(e, offset, 1));
            p = highEnd(p);
            *p = '\0';
            return buf;
        }
    }

    sprintf(buf, "0x%04x", offset);
    return buf;
}

char * getsegsymbol(struct dis *d, int seg)
{
    struct exe *e = d->e;
    static char buf[8];

    if (e && e->syms) {
        if (seg == e->textseg)
            return ".text";
        if (seg != 0 && seg == e->ftextseg)
            return ".fartext";
        if (seg != 0 && seg == e->dataseg)
            return ".data";
    }

    sprintf(buf, "0x%04x", seg);
    return buf;
}
