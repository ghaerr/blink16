#ifndef SYMS_H_
#define SYMS_H_
/* ELKS symbol table support */

#include "exe.h"

/* symbol table format
 *  | byte type | word address | byte symbol length | symbol |
 *  type: (lower case means static)
 *      T, t    .text
 *      F, f    .fartext
 *      D, d    .data
 *      B, b    .bss
 *      0       end of symbol table
 */

#define TYPE        0
#define ADDR        1
#define SYMLEN      3
#define SYMBOL      4

/* raw access functions */
#define symNext(p)  (((unsigned char *)p) + 1 + 2 + symLen(p) + 1)
#define symType(p)  (((unsigned char *)p)[TYPE])
#define symAddr(p)  ((unsigned short)(((unsigned char *)p)[ADDR] | (((unsigned char *)p)[ADDR+1] << 8)))
#define symLen(p)   (((unsigned char *)p)[SYMLEN])
#define symName(p)  (((char *)p) + SYMBOL)

#ifndef noinstrument
#define noinstrument    __attribute__((no_instrument_function))
#endif

typedef unsigned int addr_t;    /* ELKS a.out address size (short) or larger */

unsigned char * noinstrument sym_read_exe_symbols(struct exe *e, char *path);
unsigned char * noinstrument sym_read_symbols(struct exe *e, char *path);
void noinstrument sym_free(struct exe *e);
char * noinstrument sym_text_symbol(struct exe *e, addr_t addr, int exact);
char * noinstrument sym_ftext_symbol(struct exe *e, addr_t addr, int exact);
char * noinstrument sym_data_symbol(struct exe *e, addr_t addr, int exact);
char * noinstrument sym_symbol(struct exe *e, addr_t addr, int exact);
addr_t  noinstrument sym_fn_start_address(struct exe *e, addr_t addr);
unsigned char * noinstrument sym_next_text_entry(struct exe *e, unsigned char *entry);

#endif /* SYMS_H_ */
