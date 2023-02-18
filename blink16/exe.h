#ifndef EXE_H_
#define EXE_H_
/* ELKS a.out and DOS MZ headers */

#include <stdint.h>

/* minimal ELKS header */
struct minix_exec_hdr {
    uint32_t  type;
    uint8_t   hlen;       // 0x04
    uint8_t   reserved1;
    uint16_t  version;
    uint32_t  tseg;       // 0x08
    uint32_t  dseg;       // 0x0c
    uint32_t  bseg;       // 0x10
    uint32_t  entry;
    uint16_t  chmem;
    uint16_t  minstack;
    uint32_t  syms;
};

/* ELKS optional fields */
struct elks_supl_hdr {
    uint32_t  msh_trsize;       /* text relocation size */      // 0x20
    uint32_t  msh_drsize;       /* data relocation size */      // 0x24
    uint32_t  msh_tbase;        /* text relocation base */
    uint32_t  msh_dbase;        /* data relocation base */
    uint32_t  esh_ftseg;        /* far text size */             // 0x30
    uint32_t  esh_ftrsize;      /* far text relocation size */  // 0x34
    uint16_t  esh_compr_tseg;   /* compressed tseg size */
    uint16_t  esh_compr_dseg;   /* compressed dseg size* */
    uint16_t  esh_compr_ftseg;  /* compressed ftseg size*/
    uint16_t  esh_reserved;
};

struct minix_reloc {
    uint32_t  r_vaddr;          /* address of place within section */
    uint16_t  r_symndx;         /* index into symbol table */   // 0x04
    uint16_t  r_type;           /* relocation type */           // 0x06
};

struct image_dos_header {       // DOS .EXE header
    uint16_t e_magic;           // Magic number                  // 0x00
    uint16_t e_cblp;            // Bytes on last page of file    // 0x02
    uint16_t e_cp;              // Pages in file                 // 0x04
    uint16_t e_crlc;            // Relocations                   // 0x06
    uint16_t e_cparhdr;         // Size of header in paragraphs  // 0x08
    uint16_t e_minalloc;        // Minimum extra paragraphs needed
    uint16_t e_maxalloc;        // Maximum extra paragraphs needed
    uint16_t e_ss;              // Initial (relative) SS value   // 0x0e
    uint16_t e_sp;              // Initial SP value              // 0x10
    uint16_t e_csum;            // Checksum
    uint16_t e_ip;              // Initial IP value              // 0x14
    uint16_t e_cs;              // Initial (relative) CS value   // 0x16
    uint16_t e_lfarlc;          // File address of relocation table // 0x18
    uint16_t e_ovno;            // Overlay number
    uint16_t e_res[4];          // Reserved words
    uint16_t e_oemid;           // OEM identifier (for e_oeminfo)
    uint16_t e_oeminfo;         // OEM information; e_oemid specific
    uint16_t e_res2[10];        // Reserved words
    uint32_t e_lfanew;          // File address of new exe header
};

struct dos_reloc {              // DOS relocation table entry
    uint16_t r_offset;          // Offset of segment to reloc from r_seg
    uint16_t r_seg;             // Segment relative to load segment
};

struct exe {
    struct minix_exec_hdr aout;
    struct elks_supl_hdr eshdr;
    struct image_dos_header dos;
    int (*checkStack)(struct exe *e);
    void (*handleInterrupt)(struct exe *e, int intno);
    /* disassembly */
    unsigned char * syms;       /* symbol table */
    uint16_t textseg;           /* text and data segments */
    uint16_t ftextseg;
    uint16_t dataseg;
    /* break management */
    uint16_t t_endseg;          /* end of data segment (data+bss+heap+stack) */
    uint16_t t_begstack;        /* start SP */
    uint16_t t_minstack;        /* min stack size */
    uint16_t t_enddata;         /* start heap = end of data+bss */
    uint16_t t_endbrk;          /* current break (end of heap) */

    /* stack overflow check */
    uint32_t t_stackLow;        /* lowest SS:SP allowed */
};

#define ELKSMAGIC   0x0301      /* magic number for ELKS executables */
#define DOSMAGIC    0x5a4d      /* magic number for DOS MZ executables */

/* loader entry points */
void loadExecutableElks(struct exe *e, const char *filename, int argc, char **argv, char **envp);
void loadExecutableDOS(struct exe *e, const char *filename, int argc, char **argv, char **envp);

#endif /* EXE_H_ */
