#ifndef DISASM_H_
#define DISASM_H_
/* ELKS disassembler header file */

#ifndef noinstrument
#define noinstrument    __attribute__((no_instrument_function))
#endif

struct dis {
    unsigned int cs;
    unsigned int ip;
    unsigned int ds;
    unsigned int flags;
    unsigned int oplen;
    unsigned int col;
    int (*getbyte)(int, int);
    char *s;
    struct exe *e;
    char buf[128];
};

/* disassembler flags */
#define fDisCS          0x0001  /* show CS: value */
#define fDisIP          0x0002  /* show IP address */
#define fDisAddr        0x0004  /* show linear address */
#define fDisBytes       0x0008  /* show byte codes */
#define fDisOctal       0x0010  /* use octal for byte codes */
#define fDisInst        0x0020  /* show instruction */
#define fDisAsmSource   0x0040  /* output gnu compatible 'as' input */

/* disasm.c */
// use unsigned!
int disasm(struct dis *d, int cs, int ip, int (*nextbyte)(int, int), int ds, int flags);

/* to be defined by caller of disasm() */
char * noinstrument getsymbol(struct dis *d, int seg, int offset);
char * noinstrument getsegsymbol(struct dis *d, int seg);

#endif /* DISASM_H */
