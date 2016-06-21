/* Sample code for /dev/kvm API
 *
 * Copyright (c) 2015 Intel Corporation
 * Author: Josh Triplett <josh@joshtriplett.org>
 *
 * Converted into a DPMI test harness by: Hamish Coleman <hamish@zot.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#include <err.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <unistd.h>
#include <stdarg.h>
#include <ctype.h>

#ifndef KVM_INTERNAL_ERROR_DELIVERY_EV
#define KVM_INTERNAL_ERROR_DELIVERY_EV  3
#endif

int debug_level = 2;
int debug_printf(unsigned char level, const char *fmt, ...)
{
    va_list args;
    char buf[1025];
    int i;

    if (level > debug_level)
        return 0;

    va_start(args, fmt);
    i=vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    fprintf(stderr,buf);

    return i;
}


#define SEG_TEXT 0x08 /* gdt[1] */
#define SEG_DATA 0x10 /* gdt[2] */
#define SEG_PSP  0x18
#define SEG_ENV  0x20
#define SEG_GO32 0x28
#define SEG_GO32_TEXT 0x30
#define SEG_SYS_MAX SEG_GO32_TEXT

#define SEG_PSP_SIZE  256
#define SEG_PSP_BASE  0xf0030000
#define SEG_ENV_SIZE  256
#define SEG_ENV_BASE  (SEG_PSP_BASE+SEG_PSP_SIZE)
#define SEG_GO32_SIZE (0x5000-SEG_PSP_SIZE-SEG_ENV_SIZE)
#define SEG_GO32_BASE (SEG_ENV_BASE+SEG_ENV_SIZE)

#define MEM_REGION_GDT   0
#define MEM_REGION_IDT   1
#define MEM_REGION_TEXT  2
#define MEM_REGION_PSP   3
#define MEM_REGION_ZERO  4
#define MEM_REGION_SYS_MAX   4
#define MEM_REGION_MAX   16

#define REGION_STACK_SIZE 0x1000
#define REGION_STACK_BASE 0xf0000000
#define REGION_IDT_SIZE   0x1000
#define REGION_IDT_BASE   0xf0010000
#define REGION_GDT_SIZE   0x1000
#define REGION_GDT_BASE   0xf0020000
#define REGION_PSP_SIZE   (SEG_PSP_SIZE+SEG_ENV_SIZE+SEG_GO32_SIZE)
#define REGION_PSP_BASE   0xf0030000

#define REGION_BSS_BASE   0x00200000
#define REGION_BSS_SIZE   0x00100000

struct __attribute__ ((__packed__)) gdt_entry {
    __u16 limit_l;
    __u16 base_l;
    __u8 base_m;
    __u8 type_flags;
    __u8 limit_flags;
    __u8 base_h;
};

struct __attribute__ ((__packed__)) idt_entry {
    __u16 offset_l;
    __u16 selector;
    __u8 always0;
    __u8 type_flags;
    __u16 offset_h;
};

struct __attribute__ ((__packed__)) idt {
    struct idt_entry entry[256];
    uint8_t hlt[256][4];
};

struct __attribute__ ((__packed__)) djgcc_stubinfo {
    char magic[16];
    __u32 size;             /* bytes in structure */
    __u32 minstack;         /* minimum amount of DPMI stack space */
    __u32 memory_handle;    /* DPMI memory handle */
    __u32 initial_size;     /* size of initial segment */
    __u16 minkeep;         /* size of transfer buffer */
    __u16 ds_selector;     /* selector used for transfer buffer */
    __u16 ds_segment;      /* segment address of transfer buffer */
    __u16 psp_selector;    /* PSP selector (PSP is at offset 0) */
    __u16 cs_selector;     /* to be freed */
    __u16 env_size;        /* number of bytes of environment */
    char basename[8];       /* base name of executable to load (asciiz if < 8) */
    char argv0[16];         /* used ONLY by the application (asciiz if < 16) */
    char dpmi_server[16];   /* used by stub to load DPMI server if no DPMI already present */
};

struct __attribute__ ((__packed__)) region_psp {
    char psp[128];
    char cmdline_len;
    char cmdline[127];
    char env[256];
    struct djgcc_stubinfo stubinfo; /* offset 0 in go32 */
    char padding[172];
    char buffer[16384];             /* offset 0x100 in go32 */
    char padding2[3328];
};

struct irq_handler_entry; /* forward definition */
struct emu {
    unsigned long entry; /* entry point for the binary - from config */

    int kvm;
    int vmfd;
    int vcpufd;
    struct kvm_run *run;
    struct kvm_userspace_memory_region mem[MEM_REGION_MAX];
    unsigned int region_stack; /* which slot contains the stack */
    unsigned int region_brk; /* start of available region slots */
    unsigned int bss_brk; /* start of available bss */
    unsigned int gdt_brk; /* start of available descriptors */

    struct irq_handler_entry *irq;
    __u32 mmio_next; /* if mmio matches this, avoid verbosity */
    int mmio_count; /* just how many mmio_next matches have we seen */

    int trace;          /* enable instruction tracing */
    __u32 debug_addr;
    int debug_count;
    int smi_count;      /* number of SMI io ops we have seen */
    __u32 smi_Buffer_Ptr_Address; /* Could set this by reading ACPI tables */
} emu_global;

struct irq_subhandler_entry {
    int subcode;
    char *name;
    int (*handler)(void *, struct emu *, struct kvm_regs *);
    void *data;
};

struct irq_handler_entry {
    char *name;
    int (*handler)(void *, struct emu *, struct kvm_regs *);
    void *data;
};

#define WANT_NONE     0
#define WANT_SET_REGS 1
#define WANT_NEWLINE  2
int handle_irqno(struct irq_handler_entry *, unsigned char, struct emu *, struct kvm_regs *); /* forward definition */

void *mem_guest2host(struct emu *emu, __u64 guestaddr) {
    for (int i=0; i<MEM_REGION_MAX; i++) {
        if (guestaddr >= emu->mem[i].guest_phys_addr && guestaddr <= emu->mem[i].guest_phys_addr + emu->mem[i].memory_size) {
            return (uint8_t *)emu->mem[i].userspace_addr + (guestaddr - emu->mem[i].guest_phys_addr);
        }
    }
    return NULL;
}

/*
 * Do the same as mem_guest2host, but take some extra steps
 * if it looks like we are running a strange stack
 */
void *mem_getstack(struct emu *emu, struct kvm_regs *regs) {
    if (regs->rsp>0 && regs->rsp<0x1000) {
        /* Stack is in the zero-page area, possibly we are using the
         * GO32 segment for the stack
         */

        struct kvm_sregs sregs;
        int ret = ioctl(emu->vcpufd, KVM_GET_SREGS, &sregs);
        if (ret == -1)
            err(1, "KVM_GET_SREGS");

        if (sregs.ss.selector == SEG_GO32) {
            return mem_guest2host(emu, SEG_GO32_BASE + regs->rsp);
        }
    }
    return mem_guest2host(emu, regs->rsp);
}

__u32 get_retaddr(struct emu *emu, struct kvm_regs *regs) {
    __u32 *stack = mem_getstack(emu,regs);
    if (stack) {
        return *stack;
    }
    return 0;
}

void gdt_setlimit(struct gdt_entry *gdt, __u32 limit) {
    if (limit > 0xfffff) {
        gdt->limit_flags |= 0x80; /* set G bit */
        limit = limit>>12;
    } else {
        gdt->limit_flags &= ~0x80; /* clear G bit */
    }
    gdt->limit_l = limit & 0xffff;
    gdt->limit_flags &= 0xf0;
    gdt->limit_flags |= (limit & 0xf0000) >> 16;
}

void gdt_setbase(struct gdt_entry *gdt, __u32 base) {
    gdt->base_l = base & 0xffff;
    gdt->base_m = (base & 0xff0000) >> 16;
    gdt->base_h = (base & 0xff000000) >> 24;
}

__u32 gdt_getbase(struct gdt_entry *gdt) {
    return gdt->base_l | (gdt->base_m <<16) | (gdt->base_h <<24);
}

void dump_backtrace(struct emu *emu, struct kvm_regs *called_regs) {
    struct kvm_regs regs;
    regs.rsp = called_regs->rsp;
    regs.rbp = called_regs->rbp;

    debug_printf(2,"Backtrace:");

    __u32 *stack = mem_getstack(emu,&regs);
    if (!stack) {
        return;
    }

    debug_printf(2," (0x%08llx 0x%08x)", called_regs->rip, *stack);

    int maxdepth = 18;
    int depth = 0;

    while (depth<maxdepth) {
        if (depth%7==0) {
            debug_printf(2,"\n ");
        }
        regs.rsp = regs.rbp;
        stack = mem_getstack(emu,&regs);
        if (!stack) {
            debug_printf(2,"!stack");
            break;
        }
        regs.rbp = stack[0];
        debug_printf(2,"0x%08x ",stack[1]);
        if (stack[1] == 0) {
            break;
        }
        depth++;
    }
    debug_printf(2,"\n");
}

void dump_kvm_run(struct kvm_run *run) {
    const char * kvm_exit_str[] = {
        "KVM_EXIT_UNKNOWN", "KVM_EXIT_EXCEPTION", "KVM_EXIT_IO",
        "KVM_EXIT_HYPERCALL", "KVM_EXIT_DEBUG", "KVM_EXIT_HLT",
        "KVM_EXIT_MMIO", "KVM_EXIT_IRQ_WINDOW_OPEN", "KVM_EXIT_SHUTDOWN",
        "KVM_EXIT_FAIL_ENTRY", "KVM_EXIT_INTR", "KVM_EXIT_SET_TPR",
        "KVM_EXIT_TPR_ACCESS", "KVM_EXIT_S390_SIEIC", "KVM_EXIT_S390_RESET",
        "KVM_EXIT_DCR", "KVM_EXIT_NMI", "KVM_EXIT_INTERNAL_ERROR",
        "KVM_EXIT_OSI", "KVM_EXIT_PAPR_HCALL",
    };

    debug_printf(1,"%s(%i)\n",kvm_exit_str[run->exit_reason],run->exit_reason);
    switch (run->exit_reason) {
    case KVM_EXIT_INTERNAL_ERROR:
        debug_printf(1,"\tsuberror: 0x%x\n",run->internal.suberror);
        debug_printf(1,"\textra data (%i):\n\t",run->internal.ndata);
        for (int i=0; i<run->internal.ndata; i++) {
            debug_printf(1,"0x%x ",run->internal.data[i]);
        }
        debug_printf(1,"\n");
        break;
    case KVM_EXIT_MMIO:
        debug_printf(1,"\tphys_addr: 0x%llx\n",run->mmio.phys_addr);
        break;
    case KVM_EXIT_IO:
        debug_printf(1,"\tport[0x%llx]",run->io.port);
        if (run->io.direction == KVM_EXIT_IO_OUT) {
            __u64 val = 0;
            /* FIXME - what if size is > 8 ? */
            memcpy(&val,((char *)run)+run->io.data_offset,run->io.size);
            debug_printf(1,"=0x%llx(%i)\n",val,run->io.size);
        } else {
            debug_printf(1,"\n");
        }
        break;
    }
}

void dump_dwords(void *data, int words) {
    __u32 *p = data;
    if (!data) {
        return;
    }
    int i = 0;
    /* FIXME - can run off the end of the segment easily */
    while(i<words) {
        if (i%7 == 0) {
            debug_printf(1,"\n ");
        }
        debug_printf(1,"0x%08x ",*p++);
        i++;
    }
    debug_printf(1,"\n");
}

void dump_kvm_regs(struct kvm_regs *regs) {
    debug_printf(1,"ax=0x%08llx bx=0x%08llx cx=0x%08llx dx=0x%08llx flags=0x%08llx\n",
        regs->rax,regs->rbx,regs->rcx,regs->rdx,regs->rflags);
#if 0
    debug_printf(1,"8=0x%08x 9=0x%08x 10=0x%08x 11=0x%08x 12=0x%08x\n",
        regs->r8,regs->r9,regs->r10,regs->r11,regs->r12);
#endif
    debug_printf(1,"si=0x%08llx di=0x%08llx sp=0x%08llx bp=0x%08llx ip=0x%08llx ",
        regs->rsi,regs->rdi,regs->rsp,regs->rbp,regs->rip);

    debug_printf(1,"(%07x)\n",get_retaddr(&emu_global,regs));
}

void dump_kvm_segment(struct kvm_segment *seg, char *name) {
    unsigned int limit;
    if (seg->g) {
        limit = (seg->limit <<12) + 0xfff;
    } else {
        limit = seg->limit;
    }
    debug_printf(1,"%s:%02x %08llx(%08x) type=%x dpl=%i %s%s%s%s%s\n",
        name,seg->selector,seg->base,limit,
        seg->type, seg->dpl,
        seg->present?"P":"_",
        seg->db?"B":"_",
        seg->s?"U":"S",
        seg->l?"L":"_",
        seg->g?"G":"_"
    );
}

void dump_descriptor(struct gdt_entry *gdt, __u16 selector) {
    struct kvm_segment seg;

    seg.base = gdt->base_l | gdt->base_m<<16 | gdt->base_h<<24;
    seg.limit = gdt->limit_l | (gdt->limit_flags & 0x0f)<<16;
    seg.selector = selector;
    seg.type = gdt->type_flags & 0xf;
    seg.present = (gdt->type_flags & 0x80)>>7;
    seg.dpl = (gdt->type_flags & 0x60)>>5;
    seg.db = (gdt->limit_flags & 0x40)>>6;
    seg.s = (gdt->type_flags & 0x10)>>4;
    seg.l = (gdt->limit_flags & 0x20)>>5;
    seg.g = (gdt->limit_flags & 0x80)>>7;

    dump_kvm_segment(&seg,"_dt");
}


void dump_kvm_dtable(struct kvm_dtable *seg, char *name) {
    debug_printf(1,"%s: %08llx(%08x)\n",
        name,seg->base,seg->limit);
}

void dump_kvm_sregs(struct emu *emu) {
    struct kvm_sregs sregs;
    int ret = ioctl(emu->vcpufd, KVM_GET_SREGS, &sregs);
    if (ret == -1)
        err(1, "KVM_GET_SREGS");
    debug_printf(1,"cr0=0x%08llx\n",
        sregs.cr0);
    dump_kvm_segment(&sregs.cs,"cs");
    dump_kvm_segment(&sregs.ds,"ds");
    dump_kvm_segment(&sregs.es,"es");
    dump_kvm_segment(&sregs.es,"fs");
    dump_kvm_segment(&sregs.es,"gs");
    dump_kvm_segment(&sregs.ss,"ss");
    // dump_kvm_segment(&sregs.tr,"tr");
    // dump_kvm_segment(&sregs.ldt,"ldt");
    dump_kvm_dtable(&sregs.gdt,"gdt");
    dump_kvm_dtable(&sregs.idt,"idt");

    struct gdt_entry *gdt = (struct gdt_entry *)emu->mem[MEM_REGION_GDT].userspace_addr;
    for (int i=1; i<emu->gdt_brk; i++) {
        dump_descriptor(&gdt[i],i<<3);
    }

#if 0
    debug_printf(1,"irq:");
    for (int i = 0; i < (KVM_NR_INTERRUPTS + 63) / 64; i++) {
        debug_printf(1,"%016llx",sregs.interrupt_bitmap[i]);
    }
#endif
    debug_printf(1,"\n");
}

void dump_kvm_memmap_one(struct kvm_userspace_memory_region *p) {
    debug_printf(1,"%i: 0x%08llx(0x%08llx) = 0x%08llx (flags=%x)\n",
        p->slot, p->guest_phys_addr, p->memory_size,
        p->userspace_addr, p->flags
    );
}

void dump_kvm_memmap(struct emu *emu) {
    struct kvm_userspace_memory_region *p = &emu->mem[0];
    debug_printf(1,"Memmap:\n");
    for (int i=0; i<MEM_REGION_MAX; i++,p++) {
        dump_kvm_memmap_one(p);
    }
}

void dump_kvm_exit(struct emu *emu) {
    struct kvm_regs regs;
    __u32 *stack;

    int ret = ioctl(emu->vcpufd, KVM_GET_REGS, &regs);
    if (ret == -1)
        err(1, "KVM_GET_REGS");

    debug_printf(1,"\n");
    dump_kvm_run(emu->run);
    dump_kvm_regs(&regs);
    switch(emu->run->exit_reason) {
    case KVM_EXIT_INTERNAL_ERROR:
    case KVM_EXIT_SHUTDOWN:
    case KVM_EXIT_MMIO:
    case KVM_EXIT_IO:
        stack = mem_guest2host(emu, regs.rsp);
        if (stack) {
            debug_printf(0,"Stack:");
            dump_dwords(stack,16);
        }
        dump_backtrace(emu,&regs);
        dump_kvm_sregs(emu);
        dump_kvm_memmap(emu);
        break;
    }
}

#define MEMR_REGISTER 1
#define MEMR_ANONYMOUS 2
#define MEMR_RDWR 4
int load_memory(struct emu *emu, __u32 phys_addr, __u32 size, char *filename, __u32 file_offset, __u32 flags) {
    int fd;
    int mmap_prot;
    int mmap_flags;

    if (!(flags & MEMR_ANONYMOUS)) {
        int oflag;
        if ((flags & MEMR_RDWR)) {
            oflag = O_RDWR;
        } else {
            oflag = O_RDONLY;
        }
        fd = open(filename, oflag);
        if (fd == -1)
            errx(1, "opening file %s",filename);
        mmap_prot = PROT_READ;
        mmap_flags = MAP_SHARED;
    } else {
        file_offset = 0;
        fd = -1;
        mmap_prot = PROT_READ;
        mmap_flags = MAP_SHARED | MAP_ANONYMOUS;
    }

    if ((flags & MEMR_RDWR)) {
        mmap_prot |= PROT_WRITE;
    }

    void *region = mmap(NULL, size, mmap_prot, mmap_flags, fd, file_offset);
    if (!region)
        errx(1, "mmap memory from %s",filename);

    int slot = emu->region_brk++;
    if (slot > MEM_REGION_MAX) {
        errx(1, "too many memory regions loading %s",filename);
    }

    emu->mem[slot].slot = slot;
    emu->mem[slot].guest_phys_addr = phys_addr;
    emu->mem[slot].memory_size = size;
    emu->mem[slot].userspace_addr = (uint64_t)region;

    if (flags & MEMR_REGISTER) {
        /*
         * by adding the region to the mem table, but not registering it, it becomes
         * straightforward to trace accesses as MMIO exits
         */

        int ret = ioctl(emu->vmfd, KVM_SET_USER_MEMORY_REGION, &emu->mem[slot]);
        if (ret == -1)
            errx(1, "KVM_SET_USER_MEMORY_REGION %i: %s",slot,filename);
    }

    return slot;
}

void setup_gdt(struct kvm_sregs *sregs, struct emu *emu) {
    struct gdt_entry *gdt = mmap(NULL, REGION_GDT_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (!gdt)
        err(1, "allocating gdt memory");

    memset(gdt,0,REGION_GDT_SIZE);

    /* code segment */
    gdt[1].type_flags  = 0x9e;
    gdt[1].limit_flags = 0x40; /* Set the 32bit segment flag */
    gdt_setlimit(&gdt[1],0xffffffff);
    gdt_setbase(&gdt[1],0);

    /* data segment */
    gdt[2].type_flags = 0x92;
    gdt[2].limit_flags = 0x40;
    gdt_setlimit(&gdt[2],0xffffffff);
    gdt_setbase(&gdt[2],0);

    /* PSP segment */
    gdt[3].type_flags = 0x92;
    gdt[3].limit_flags = 0x40;
    gdt_setlimit(&gdt[3],SEG_PSP_SIZE);
    gdt_setbase(&gdt[3],SEG_PSP_BASE);

    /* ENV segment */
    gdt[4].type_flags = 0x92;
    gdt[4].limit_flags = 0x40;
    gdt_setlimit(&gdt[4],SEG_ENV_SIZE);
    gdt_setbase(&gdt[4],SEG_ENV_BASE);

    /* GO32 segment */
    gdt[5].type_flags = 0x92;
    gdt[5].limit_flags = 0x40;
    gdt_setlimit(&gdt[5],SEG_GO32_SIZE);
    gdt_setbase(&gdt[5],SEG_GO32_BASE);

    /* Segment used for running the exit code */
    gdt[6].type_flags = 0x9e;
    gdt[6].limit_flags = 0x40;
    gdt_setlimit(&gdt[6],SEG_GO32_SIZE);
    gdt_setbase(&gdt[6],SEG_GO32_BASE);

    emu->mem[MEM_REGION_GDT].slot = MEM_REGION_GDT;
    emu->mem[MEM_REGION_GDT].guest_phys_addr = REGION_GDT_BASE;
    emu->mem[MEM_REGION_GDT].memory_size = REGION_GDT_SIZE;
    emu->mem[MEM_REGION_GDT].userspace_addr = (uint64_t)gdt;

    int ret = ioctl(emu->vmfd, KVM_SET_USER_MEMORY_REGION, &emu->mem[MEM_REGION_GDT]);
    if (ret == -1)
        errx(1, "KVM_SET_USER_MEMORY_REGION %i",__LINE__);

    emu->gdt_brk = (SEG_SYS_MAX>>3) +1;

    sregs->gdt.base = REGION_GDT_BASE;
    sregs->gdt.limit = REGION_GDT_SIZE;
}

void setup_idt(struct kvm_sregs *sregs,struct emu *emu) {
    struct idt *idt = mmap(NULL, REGION_IDT_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (!idt)
        err(1, "allocating idt memory");

    for (int i=0; i<256; i++) {
        idt->entry[i].offset_l = sizeof(idt->entry) + i*sizeof(idt->hlt[i]);
        idt->entry[i].selector = SEG_TEXT;
        idt->entry[i].always0 = 0;
        idt->entry[i].type_flags = 0xee; /* dpl=3, present, 32-bit interrupt */
        idt->entry[i].offset_h = REGION_IDT_BASE>>16;
        idt->hlt[i][0] = 0xe7; /* out imm8,ax */
        idt->hlt[i][1] = 0x7f; /* imm8 = 0x7f */
        idt->hlt[i][2] = 0xcf; /* iret */
        idt->hlt[i][3] = 0xf4; /* hlt */
    }

    emu->mem[MEM_REGION_IDT].slot = MEM_REGION_IDT;
    emu->mem[MEM_REGION_IDT].guest_phys_addr = REGION_IDT_BASE;
    emu->mem[MEM_REGION_IDT].memory_size = REGION_IDT_SIZE;
    emu->mem[MEM_REGION_IDT].userspace_addr = (uint64_t)idt;

    int ret = ioctl(emu->vmfd, KVM_SET_USER_MEMORY_REGION, &emu->mem[MEM_REGION_IDT]);
    if (ret == -1)
        errx(1, "KVM_SET_USER_MEMORY_REGION %i",__LINE__);

    sregs->idt.base = REGION_IDT_BASE;
    sregs->idt.limit = sizeof(idt->entry);
}

void setup_flat_segments(struct kvm_sregs *sregs) {
    sregs->cs.base = 0;
    sregs->cs.limit = 0xfffff;
    sregs->cs.selector = SEG_TEXT; /* gdt[1] */
    sregs->cs.db = 1;
    sregs->cs.g = 1;
    sregs->cs.type = 0xe; /* x=1, c=1, r=1, a=0 */
    memcpy(&sregs->ds,&sregs->cs,sizeof(sregs->cs));
    sregs->ds.selector = SEG_DATA; /* gdt[2] */
    sregs->ds.type = 2; /* x=0, e=0, w=1, a=0 */
    /* FIXME - set ds.type correctly sregs->ds.type = 2 ? */
    memcpy(&sregs->es,&sregs->ds,sizeof(sregs->ds));
    memcpy(&sregs->fs,&sregs->ds,sizeof(sregs->ds));
    sregs->fs.g = 0;
    sregs->fs.selector = SEG_GO32;
    sregs->fs.base = SEG_GO32_BASE;
    sregs->fs.limit = SEG_GO32_SIZE;
    memcpy(&sregs->gs,&sregs->ds,sizeof(sregs->ds));
    memcpy(&sregs->ss,&sregs->ds,sizeof(sregs->ds));
    sregs->ss.type = 6; /* x=0,e=1,w=1,a=0 */
    /* FIXME
     * - descriptor table too
     */
}

int kvm_init(struct emu *emu) {
    struct kvm_sregs sregs;

    emu->kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (emu->kvm == -1)
        err(1, "/dev/kvm");

    /* Make sure we have the stable version of the API */
    int ret = ioctl(emu->kvm, KVM_GET_API_VERSION, NULL);
    if (ret == -1)
        err(1, "KVM_GET_API_VERSION");
    if (ret != 12)
        errx(1, "KVM_GET_API_VERSION %d, expected 12", ret);

    emu->vmfd = ioctl(emu->kvm, KVM_CREATE_VM, (unsigned long)0);
    if (emu->vmfd == -1)
        err(1, "KVM_CREATE_VM");

    emu->vcpufd = ioctl(emu->vmfd, KVM_CREATE_VCPU, (unsigned long)0);
    if (emu->vcpufd == -1)
        err(1, "KVM_CREATE_VCPU");

    /* Map the shared kvm_run structure and following data. */
    ret = ioctl(emu->kvm, KVM_GET_VCPU_MMAP_SIZE, NULL);
    if (ret == -1)
        err(1, "KVM_GET_VCPU_MMAP_SIZE");
    size_t mmap_size = ret;
    if (mmap_size < sizeof(*emu->run))
        errx(1, "KVM_GET_VCPU_MMAP_SIZE unexpectedly small");
    emu->run = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, emu->vcpufd, 0);
    if (!emu->run)
        err(1, "mmap vcpu");

    /* Initialize CS to point at 0, via a read-modify-write of sregs. */
    ret = ioctl(emu->vcpufd, KVM_GET_SREGS, &sregs);
    if (ret == -1)
        err(1, "KVM_GET_SREGS");
    sregs.cr0 = 0x1; /* protected mode enable */
    setup_flat_segments(&sregs);
    setup_idt(&sregs,emu);
    setup_gdt(&sregs,emu);
    ret = ioctl(emu->vcpufd, KVM_SET_SREGS, &sregs);
    if (ret == -1)
        err(1, "KVM_SET_SREGS");

    debug_printf(1,"Map stack\n");
    ret = load_memory(emu,REGION_STACK_BASE,REGION_STACK_SIZE,"stack",0,MEMR_REGISTER|MEMR_ANONYMOUS|MEMR_RDWR);
    if (ret == -1)
        err(1, "load_memory stack");
    emu->region_stack = ret;

    /* Stack canary - this should point to unmapped memory */
    uint8_t *stack = mem_guest2host(emu, REGION_STACK_BASE+REGION_STACK_SIZE-4);
    *((__u32*)stack) = 0xbad0add0;

    debug_printf(1,"Map bss\n");
    ret = load_memory(emu,REGION_BSS_BASE,REGION_BSS_SIZE,"bss",0,MEMR_REGISTER|MEMR_ANONYMOUS|MEMR_RDWR);
    if (ret == -1)
        err(1, "load_memory bss");

    /* initialise the starting alloc brk */
    emu->bss_brk = 0;

    return 0;
}

int load_image(struct emu *emu, char *filename, char *cmdline) {
    int ret;

    const uint8_t code[] = {
        0xba, 0xf8, 0x03, 0,0, /* mov $0x3f8, %dx */
        0x00, 0xd8,       /* add %bl, %al */
        0x04, '0',        /* add $'0', %al */
        0xee,             /* out %al, (%dx) */
        0xb0, '\n',       /* mov $'\n', %al */
        0xee,             /* out %al, (%dx) */
        0xe7, /* out imm8,ax */
        0xb2, /* imm8 */
        0xf4,             /* hlt */
    };

    __u64 text_size;
    uint8_t *text;
    if (*filename == '-') {
        text_size = 0x2000;
        /* Allocate one aligned page of guest memory to hold the code. */
        text = mmap(NULL, text_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (!text)
            err(1, "allocating guest memory");
        memcpy(text+0x1000, code, sizeof(code));
    } else {
        int fd = open(filename, O_RDONLY);
        if (fd == -1)
            err(1, "opening file");
        struct stat s;
        ret = fstat(fd,&s);
        if (ret == -1)
            err(1, "statting file");
        text_size = ((s.st_size >>12) +1 )<<12;

        text = mmap(NULL, text_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (!text)
            err(1, "allocating guest memory");
        uint8_t *p = text;
        while(s.st_size) {
            ret = read(fd,p,4096);
            if (ret == -1)
                err(1, "reading file");
            s.st_size -= ret;
            p += ret;
        }
    }

    emu->mem[MEM_REGION_ZERO].slot = MEM_REGION_ZERO;
    emu->mem[MEM_REGION_ZERO].guest_phys_addr = 0;
    emu->mem[MEM_REGION_ZERO].memory_size = 0x1000;
    emu->mem[MEM_REGION_ZERO].userspace_addr = (uint64_t)text;

    emu->mem[MEM_REGION_TEXT].slot = MEM_REGION_TEXT;
    emu->mem[MEM_REGION_TEXT].guest_phys_addr = 0x1000;
    emu->mem[MEM_REGION_TEXT].memory_size = text_size;
    emu->mem[MEM_REGION_TEXT].userspace_addr = (uint64_t)(text+0x1000);

    ret = ioctl(emu->vmfd, KVM_SET_USER_MEMORY_REGION, &emu->mem[MEM_REGION_TEXT]);
    if (ret == -1)
        errx(1, "KVM_SET_USER_MEMORY_REGION %i",__LINE__);

    uint8_t *psp = mmap(NULL, REGION_PSP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (!psp)
        err(1, "allocating PSP area");

    emu->mem[MEM_REGION_PSP].slot = MEM_REGION_PSP;
    emu->mem[MEM_REGION_PSP].guest_phys_addr = REGION_PSP_BASE;
    emu->mem[MEM_REGION_PSP].memory_size = REGION_PSP_SIZE;
    emu->mem[MEM_REGION_PSP].userspace_addr = (uint64_t)psp;

    ret = ioctl(emu->vmfd, KVM_SET_USER_MEMORY_REGION, &emu->mem[MEM_REGION_PSP]);
    if (ret == -1)
        errx(1, "KVM_SET_USER_MEMORY_REGION %i",__LINE__);

    /* This segment is going to need more data, so fill it with a canary so
     * that it will be simpler to see
     */
    memset(psp,0xf5,REGION_PSP_SIZE);

    struct region_psp *region_psp = (struct region_psp *)psp;

    /* FIXME - define the PSP structure */
    *(__u16*)((__u8*)psp+0x2c) = SEG_ENV; /* environment segment */
    memset(region_psp->env,0,sizeof(region_psp->env));

    region_psp->cmdline_len=0;
    region_psp->cmdline[0]=0;
    if (cmdline) {
        strncat(region_psp->cmdline,cmdline,sizeof(region_psp->cmdline));
        strncat(region_psp->cmdline,"\r",sizeof(region_psp->cmdline));
        region_psp->cmdline_len = strlen(region_psp->cmdline);
    }

    memcpy(&region_psp->stubinfo.magic,"go32stub, v 2.HC",16);
    region_psp->stubinfo.size = sizeof(struct djgcc_stubinfo);
    region_psp->stubinfo.minstack = 0x80000; /* 512k */
    region_psp->stubinfo.memory_handle = 0xfeedbad0;
    region_psp->stubinfo.initial_size = text_size;
    region_psp->stubinfo.minkeep = 16384;
    region_psp->stubinfo.ds_selector = SEG_GO32;
    region_psp->stubinfo.ds_segment = 0x10; /* gets shl 4 and xref 0x0003de8d */
    region_psp->stubinfo.psp_selector = SEG_PSP;
    region_psp->stubinfo.cs_selector = SEG_GO32_TEXT;
    region_psp->stubinfo.env_size = 1;
    memset(&region_psp->stubinfo.basename,0,8);
    memset(&region_psp->stubinfo.argv0,0,16);
    memset(&region_psp->stubinfo.dpmi_server,0,16);

    /* Details from djgcc djlsr205.zip/src/stub/stub.asm
     *
     * Interface to 32-bit executable:
     *
     *    cs:eip     according to COFF header
     *    ds         32-bit data segment for COFF program
     *    fs         selector for our data segment (fs:0 is stubinfo)
     *    ss:sp      our stack (ss to be freed)
     *    <others>   All unspecified registers have unspecified values in them.
     */
    struct kvm_regs regs = {
        .rip = emu->entry,
        .rax = 0,
        .rbx = 0,
        .rflags = 0x2,
        .rsp = REGION_STACK_BASE + REGION_STACK_SIZE - 0x10,
    };
    ret = ioctl(emu->vcpufd, KVM_SET_REGS, &regs);
    if (ret == -1)
        err(1, "KVM_SET_REGS");

    *text = 0xf4; /* hlt - hack to allow the code to stop */
    return 0;
}

void load_patch_file(struct emu *emu, char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file)
        err(1, "opening patch file");

    debug_printf(0,"Patching memory image\n");

    char *line = NULL;
    size_t len = 0;
    ssize_t read;

    while ((read = getline(&line, &len, file)) != -1) {
        __u64 addr;
        int patch = 0;
        uint8_t buf[32]; /* we only expect lines of 16 bytes.. but .. */

        char *p = line;
        if (*p == '+') {
            patch = 1;
        } else if (*p != '-') {
            continue;
        }
        /* it is either a plus or a minus */
        p++;
        char *p2;
        addr = strtoul(p,&p2,16);
        if (p2==p) {
            debug_printf(0,"unexpected patch data\n");
            exit(1);
        }
        p=p2;

        uint8_t *data = mem_guest2host(emu, addr);
        if (!data) {
            debug_printf(0,"Could not locate address 0x%08llx\n",addr);
            exit(1);
        }

        int size=0;
        while(*p) {
            /* FIXME - can overflow buf */
            buf[size] = strtoul(p,&p2,16);
            if (p2==p) {
                /* nothing matched, this is a line end */
                break;
            }
            size++;
            p=p2;
        }

        debug_printf(0,"%s (host %p) 0x%08llx ",
            patch?"Patch":"Verify",
            data,
            addr
        );
        for (int i=0; i<size; i++) {
            debug_printf(0,"%02x ",buf[i]);
        }
        debug_printf(0,"\n");

        if (!patch) {
            /* not patch means verify */
            if (memcmp(data,&buf,size)) {
                debug_printf(0,"mismatched data\n");
                exit(1);
            }
        } else {
            /* patching */
            memcpy(data,&buf,size);
        }
    }
}

int load_configfile(struct emu *emu, char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file)
        errx(1, "opening config file: %s",filename);

    char buf[100]; /* Max line len */
    char *p = (char *)&buf;

    while (fgets(p,sizeof(buf),file)) {
        /* skip initial whitespace */
        while(isspace(*p)) { p++; };

        /* skip comment lines */
        if (*p == '#') {
            continue;
        }

        char * key = strtok(p," \n");

        /* no delimiter found, only keyword present */
        if (!key) {
            key = p;
        }

        if (!strcmp(key,"entry")) {
            emu->entry=strtoul(strtok(NULL," \n"),NULL,0);
        } else if (!strcmp(key,"trace")) {
            emu->trace=strtoul(strtok(NULL," \n"),NULL,0);
        } else if (!strcmp(key,"smi_Buffer_Ptr_Address")) {
            emu->smi_Buffer_Ptr_Address=strtoul(strtok(NULL," \n"),NULL,0);
        } else if (!strcmp(key,"include")) {
            if (load_configfile(emu,strtok(NULL," \n"))==-1) {
                return -1;
            }
        } else if (!strcmp(key,"load_patch")) {
            load_patch_file(emu,strtok(NULL," \n"));
        } else if (!strcmp(key,"load_memory")) {
            __u32 phys_addr = strtoul(strtok(NULL," "),NULL,0);
            __u32 size = strtoul(strtok(NULL," "),NULL,0);
            char *filename = strtok(NULL," ");
            __u32 file_offset = strtoul(strtok(NULL," "),NULL,0);
            int flags = strtoul(strtok(NULL," \n"),NULL,0);
            /* TODO - flags from config line */
            load_memory(emu,phys_addr,size,filename,file_offset,flags);
        }

        p = (char *)&buf;
    }
    return 0;
}

int alloc_bss(struct emu *emu, unsigned int size) {
    if (emu->bss_brk + size > REGION_BSS_SIZE) {
        return 0;
    }
    unsigned int guest_addr = REGION_BSS_BASE + emu->bss_brk;
    emu->bss_brk += size;
    return guest_addr;
}

void iret_setflags(struct kvm_regs *regs, unsigned int setflags) {
    __u32 *stack = mem_guest2host(&emu_global, regs->rsp);
    if (stack) {
        stack[2] |= setflags;
    }
}

void dump_fake_segments(struct kvm_regs *call) {
    debug_printf(1,"cs=0x%04llx ds=0x%04llx es=0x%04llx fs=0x%04llx gs=0x%04llx ss=0x%04llx\n",
        call->r8, call->r9, call->r10, call->r11, call->r12, call->r13
    );
}

int irq_dump_rm(void *data, struct emu *emu, struct kvm_regs *regs) {
    debug_printf(1,"\n");
    struct kvm_regs real_regs;
    int ret = ioctl(emu->vcpufd, KVM_GET_REGS, &real_regs);
    if (ret == -1)
        err(1, "KVM_GET_REGS");
    dump_kvm_regs(&real_regs);
    __u32 *stack = mem_getstack(emu, &real_regs);
    debug_printf(1,"Stack:");
    dump_dwords(stack,16);
    dump_backtrace(emu,&real_regs);
    debug_printf(1,"Real mode registers:\n");
    dump_kvm_regs(regs);
    dump_fake_segments(regs);
    return 0;
}

int irq_disk_status(void *data, struct emu *emu, struct kvm_regs *regs) {
    debug_printf(1,"drive=0x%02x - Faked",regs->rdx&0xff);
    irq_dump_rm(data,emu,regs);

    regs->rax &= ~0xffff; /* just indicate a successful completion */
    return WANT_SET_REGS;
}

int irq_dos_exit(void *data, struct emu *emu, struct kvm_regs *regs) {
    debug_printf(1," return=0x%02llx\n",regs->rax & 0xff);
    exit(0);
}

int irq_dos_version(void *data, struct emu *emu, struct kvm_regs *regs) {
    regs->rax = 0x0004; /* DOS 4.00 */
    regs->rbx = 0x0; /* DOS OEM is IBM */
    return WANT_NEWLINE|WANT_SET_REGS;
}

int irq_dos_write(void *data, struct emu *emu, struct kvm_regs *regs) {
    int handle = (regs->rbx & 0xffff);
    int count = (regs->rcx & 0xffff);
    int dos_bufaddr = (regs->r9 << 4) | (regs->rdx & 0xffff);
    uint8_t *buf =  mem_guest2host(emu, dos_bufaddr);

    debug_printf(1,"write(%i,0x%x,%i)\n",handle,dos_bufaddr,count);

    if (handle == 1 || handle == 2) {
        fwrite(buf,count,1,stdout);
        fflush(stdout);
    } else {
        debug_printf(1," - invalid handle\n");
        exit(1);
    }
    debug_printf(1,"\n");

    regs->rax = count; /* just claim to have written everything */

    irq_dump_rm(data,emu,regs);

    return WANT_SET_REGS;
}

int irq_dos_lseek(void *data, struct emu *emu, struct kvm_regs *regs) {
    int handle = regs->rbx & 0xffff;
    __s32 offset = (regs->rcx & 0xffff) <<16 | (regs->rdx & 0xffff);
    int whence = regs->rax & 0xff;

    /* convert dos whence to unix whence (null transform, but I'm paranoid) */
    switch(whence) {
    case 0: whence = SEEK_SET; break;
    case 1: whence = SEEK_CUR; break;
    case 2: whence = SEEK_END; break;
    }

    int new_pos = lseek(handle,offset,whence);
    regs->rdx = new_pos >> 16;
    regs->rax = new_pos & 0xffff;

    debug_printf(1,"lseek(%i,%i,%s) = %i\n",
        handle,offset,
        (whence==SEEK_SET)?"SEEK_SET":(whence==SEEK_CUR)?"SEEK_CUR":(whence==SEEK_END)?"SEEK_END":"UNK",
        new_pos
    );
    return WANT_SET_REGS;
}

int irq_dos_get_drive(void *data, struct emu *emu, struct kvm_regs *regs) {
    regs->rax = 0x02; /* drive C: */
    return WANT_NEWLINE|WANT_SET_REGS;
}

int irq_dos_lfn_volinfo(void *data, struct emu *emu, struct kvm_regs *regs) {
    int dos_bufaddr = (regs->r9 << 4) | (regs->rdx & 0xffff);
    uint8_t *buf =  mem_guest2host(emu, dos_bufaddr);
    debug_printf(1,"path='%s'\n",buf);

    regs->rax = 0;
    regs->rbx = 0x4003; /* supports LFN, case sensitive and preserving */
    regs->rcx = 0xff; /* max filename length */
    regs->rdx = 260; /* max path length */
    /* wants ES:DI filled in with filesystem name */
    regs->rflags &= ~1;
    return WANT_SET_REGS;
}

int irq_dos_lfn_attr(void *data, struct emu *emu, struct kvm_regs *regs) {
    /* note: r9 is a fake DS here */
    int dos_bufaddr = (regs->r9 << 4) | (regs->rsi & 0xffff);
    char *buf =  mem_guest2host(emu, dos_bufaddr);
    debug_printf(1,"path='%s', action=%i - Fail\n",buf,regs->rbx & 0xff);

    regs->rax = 5; /* access denied */
    regs->rflags |= 1;
    return WANT_SET_REGS;
}

int irq_dos_lfn_open(void *data, struct emu *emu, struct kvm_regs *regs) {
    /* note: r9 is a fake DS here */
    int dos_bufaddr = (regs->r9 << 4) | (regs->rsi & 0xffff);
    char *buf =  mem_guest2host(emu, dos_bufaddr);
    debug_printf(1,"path='%s'",buf);

    if (regs->rdx != 1) {
        /* 0x02 == truncate, 0x10 == create or fail */
        debug_printf(1," not open, fail\n");
        regs->rax = 5; /* access denied */
        /* FIXME - only works for nested real-mode calls */
        regs->rflags |= 1;
        return WANT_SET_REGS;
    }

    int fh =  open(buf,O_RDONLY);

    if (fh == -1) {
        debug_printf(1," error opening, fail\n");
        regs->rax = 5; /* access denied */
        /* FIXME - only works for nested real-mode calls */
        regs->rflags |= 1;
        return WANT_SET_REGS;
    }

    debug_printf(1," =%i\n",fh);
    regs->rcx = 1;
    regs->rax = fh;
    regs->rflags &= ~1;
    return WANT_SET_REGS;
}

/* allocate ldt desriptors */
int irq_dpmi_0000(void *data, struct emu *emu, struct kvm_regs *regs) {
    /* for the moment, try just giving it a GDT entry... */

    /* make it a copy of the data segment */
    struct gdt_entry *gdt = (struct gdt_entry *)emu->mem[MEM_REGION_GDT].userspace_addr;
    memcpy(&gdt[emu->gdt_brk],&gdt[SEG_DATA>>3],sizeof(*gdt));

    regs->rax = emu->gdt_brk<<3;
    emu->gdt_brk++;

    debug_printf(1,"selector=0x%llx\n",regs->rax);
    return WANT_SET_REGS;
}

/* get segment base address */
int irq_dpmi_0006(void *data, struct emu *emu, struct kvm_regs *regs) {
    struct gdt_entry *gdt = (struct gdt_entry *)emu->mem[MEM_REGION_GDT].userspace_addr;
    int selector = (regs->rbx & 0xffff);
    int entry = selector>>3;
    __u32 base = gdt_getbase(&gdt[entry]);
    debug_printf(1,"getbase(0x%x)=0x%08x\n",selector,base);

    regs->rcx = base >> 16;
    regs->rdx = base & 0xffff;
    return WANT_SET_REGS;
}

/* set segment base address */
int irq_dpmi_0007(void *data, struct emu *emu, struct kvm_regs *regs) {
    struct gdt_entry *gdt = (struct gdt_entry *)emu->mem[MEM_REGION_GDT].userspace_addr;

    if (regs->rbx & 0x7) {
        err(1, "Unexpected selector options");
    }
    int selector = (regs->rbx & 0xffff);
    if (selector <= SEG_SYS_MAX ) {
        debug_printf(1,"Cowardly refusing to change system segments\n");
        iret_setflags(regs,1); /* set CF */
        return WANT_NONE;
    }
    __u32 base = (regs->rcx & 0xffff)<<16 | (regs->rdx & 0xffff);
    debug_printf(1,"base(0x%x)=0x%08x\n",selector,base);

    int entry = selector>>3;
    gdt_setbase(&gdt[entry],base);
    return WANT_SET_REGS;
}

/* set segment limit */
int irq_dpmi_0008(void *data, struct emu *emu, struct kvm_regs *regs) {
    struct gdt_entry *gdt = (struct gdt_entry *)emu->mem[MEM_REGION_GDT].userspace_addr;

    if (regs->rbx & 0x7) {
        err(1, "Unexpected selector options");
    }
    int selector = (regs->rbx & 0xffff);
    if (selector <= SEG_SYS_MAX ) {
        debug_printf(1,"Cowardly refusing to change system segments\n");
        return WANT_NONE;
    }
    __u32 limit = (regs->rcx & 0xffff)<<16 | (regs->rdx & 0xffff);
    debug_printf(1,"limit(0x%x)=0x%08x\n",selector,limit);

    int entry = selector>>3;
    gdt_setlimit(&gdt[entry],limit);

    return WANT_SET_REGS;
}

/* create alias of a code segment */
int irq_dpmi_000a(void *data, struct emu *emu, struct kvm_regs *regs) {
    struct gdt_entry *gdt = (struct gdt_entry *)emu->mem[MEM_REGION_GDT].userspace_addr;

    if (regs->rbx & 0x7) {
        err(1, "Unexpected selector options");
    }

    int entry_orig = (regs->rbx & 0xffff)>>3;
    if (entry_orig >= emu->gdt_brk) {
        iret_setflags(regs,1); /* set CF */
        return WANT_NEWLINE|WANT_NONE;
    }

    memcpy(&gdt[emu->gdt_brk],&gdt[entry_orig],sizeof(*gdt));

    regs->rax = emu->gdt_brk<<3;
    emu->gdt_brk++;

    debug_printf(1,"selector=0x%llx\n",regs->rax);

    return WANT_SET_REGS;
}

/* GET REAL MODE INTERRUPT VECTOR */
int irq_dpmi_0200(void *data, struct emu *emu, struct kvm_regs *regs) {
    int irqno = regs->rbx & 0xff;
    debug_printf(1,"irq(0x%x)\n", irqno );
    regs->rcx = 0xfee1;
    regs->rdx = 0xbad2;
    return WANT_SET_REGS;
}

/* SET REAL MODE INTERRUPT VECTOR */
int irq_dpmi_0201(void *data, struct emu *emu, struct kvm_regs *regs) {
    debug_printf(1,"irq(0x%llx)=0x%04llx:0x%04llx - Ignored\n",
        regs->rbx & 0xff,
        regs->rcx & 0xffff,
        regs->rdx & 0xffff
    );
    regs->rax = 0;
    return WANT_SET_REGS;
}

/* GET PROCESSOR EXCEPTION HANDLER VECTOR */
int irq_dpmi_0202(void *data, struct emu *emu, struct kvm_regs *regs) {
    int exception = regs->rbx & 0xff;
    debug_printf(1,"exception(0x%x)\n", exception );
    regs->rax = 0;
    regs->rcx = SEG_TEXT;
    regs->rdx = REGION_IDT_BASE + 2048;
    return WANT_SET_REGS;
}

/* SET PROCESSOR EXCEPTION HANDLER VECTOR */
int irq_dpmi_0203(void *data, struct emu *emu, struct kvm_regs *regs) {
    debug_printf(1,"exception(0x%llx)=0x%llx:0x%08llx - Ignored\n",
        regs->rbx & 0xff,
        regs->rcx & 0xffff,
        regs->rdx
    );
    regs->rax = 0;
    return WANT_SET_REGS;
}

/* GET PROTECTED MODE INTERRUPT VECTOR */
int irq_dpmi_0204(void *data, struct emu *emu, struct kvm_regs *regs) {
    int irqno = regs->rbx & 0xff;
    debug_printf(1,"irq(0x%x)\n", irqno );
    regs->rcx = SEG_TEXT;
    regs->rdx = REGION_IDT_BASE + 2048 + 4 * irqno;
    return WANT_SET_REGS;
}

/* SET PROTECTED MODE INTERRUPT VECTOR */
int irq_dpmi_0205(void *data, struct emu *emu, struct kvm_regs *regs) {
    debug_printf(1,"irq(0x%llx)=0x%llx:0x%08llx - Ignored\n",
        regs->rbx & 0xff,
        regs->rcx & 0xffff,
        regs->rdx
    );
    regs->rax = 0;
    return WANT_SET_REGS;
}

struct __attribute__ ((__packed__)) dpmi_call16regs {
    __u32 edi,esi,ebp,reserved;
    __u32 ebx,edx,ecx,eax;
    __u16 flags;
    __u16 es,ds,fs,gs,ip,cs,sp,ss;
};

void dpmi_call2regs(void *data, struct kvm_regs *call) {
    struct dpmi_call16regs * call16 = data;
    call->rax = call16->eax;
    call->rbx = call16->ebx;
    call->rcx = call16->ecx;
    call->rdx = call16->edx;
    call->rsi = call16->esi;
    call->rdi = call16->edi;
    call->rsp = call16->sp;
    call->rbp = call16->ebp;
    call->rip = call16->ip;
    call->rflags = call16->flags;

    /* repurpose these registers to store the segments */
    call->r8 = call16->cs;
    call->r9 = call16->ds;
    call->r10 = call16->es;
    call->r11 = call16->fs;
    call->r12 = call16->gs;
    call->r13 = call16->ss;
}

void dpmi_regs2call(struct kvm_regs *call, void *data) {
    struct dpmi_call16regs * call16 = data;
    call16->eax = call->rax;
    call16->ebx = call->rbx;
    call16->ecx = call->rcx;
    call16->edx = call->rdx;
    call16->esi = call->rsi;
    call16->edi = call->rdi;
    call16->ebp = call->rbp;
    call16->flags = call->rflags;

    call16->cs = call->r8;
    call16->ds = call->r9;
    call16->es = call->r10;
    call16->fs = call->r11;
    call16->gs = call->r12;
    call16->ss = call->r13;
}

/* SIMULATE REAL MODE INTERRUPT */
int irq_dpmi_0300(void *data, struct emu *emu, struct kvm_regs *regs) {
    int irqno = regs->rbx & 0xff;
    debug_printf(1,"irq 0x%02x\n",irqno);

    void *call16 = mem_guest2host(emu, regs->rdi);
    if (!call16) {
        err(1, "could not map guest to host");
    }
    struct kvm_regs call;
    dpmi_call2regs(call16,&call);
    int ret = handle_irqno(emu->irq,irqno,emu,&call);

    /* always repopulate the call structure - it is just simpler */
    dpmi_regs2call(&call, call16);

    if (ret & WANT_NEWLINE) {
        return WANT_NEWLINE;
    }

    return WANT_NONE;
}

int irq_dpmi_0303(void *data, struct emu *emu, struct kvm_regs *regs) {
    debug_printf(1,"\n");
    debug_printf(1,"Callback to DS:0x%08llx\n", regs->rsi);

    void *call16 = mem_guest2host(emu, regs->rdi);
    if (!call16) {
        err(1, "could not map guest to host");
    }
    struct kvm_regs call;
    dpmi_call2regs(call16,&call);
    debug_printf(1,"Real mode registers:\n");
    dump_kvm_regs(&call);
    dump_fake_segments(&call);

    regs->rcx = SEG_TEXT;
    regs->rdx = 0xaa55aa55;
    return WANT_SET_REGS;
}

/* GET DPMI VERSION */
int irq_dpmi_0400(void *data, struct emu *emu, struct kvm_regs *regs) {
    regs->rax = 0x0100; /* DPMI version 1.0 */
    regs->rbx = 0x3; /* 386 and no v86 */
    regs->rcx = 0x04; /* 80486 */
    regs->rdx = 0x5a5a; /* some virtual interrupt thing */
    return WANT_NEWLINE|WANT_SET_REGS;
}

int irq_dpmi_0501(void *data, struct emu *emu, struct kvm_regs *regs) {
    unsigned int size = (regs->rbx & 0xffff) <<16 | (regs->rcx & 0xffff);
    unsigned int addr = alloc_bss(emu, size);

    debug_printf(1,"alloc(%i) = 0x%08x\n",size,addr);

    if (!addr) {
        iret_setflags(regs,1); /* set CF */
        return WANT_NONE;
    }

    regs->rbx = regs->rsi = addr >> 16;
    regs->rcx = regs->rdi = addr & 0xffff;

    return WANT_SET_REGS;
}

/* PHYSICAL ADDRESS MAPPING */
int irq_dpmi_0800(void *data, struct emu *emu, struct kvm_regs *regs) {
    __u32 phys_start = (regs->rbx & 0xffff) << 16 | (regs->rcx & 0xffff);
    __u32 size = (regs->rsi & 0xffff) << 16 | (regs->rdi & 0xffff);

    debug_printf(1," 0x%08x(0x%08x)",phys_start, size);

    int failed = 0;
    __u32 *hostaddr = mem_guest2host(emu, phys_start);
    if (hostaddr) {
        debug_printf(1," matched a known mapping");
        regs->rbx = (phys_start & 0xffff0000) >>16;
        regs->rcx = (phys_start & 0xffff);
    } else {
        failed = 1;
        /* for now, return a bogus mapping address */
        regs->rbx = 0;
        regs->rcx = 0;
    }

    if (failed) {
        debug_printf(1," - DENIED\n");

        dump_kvm_regs(regs);
        __u32 *stack = mem_guest2host(emu, regs->rsp);
        if (stack) {
            debug_printf(0,"Stack:");
            dump_dwords(stack,16);
        }
        dump_backtrace(emu,regs);
        dump_kvm_sregs(emu);
        dump_kvm_memmap(emu);

        exit(1);

        iret_setflags(regs,1); /* set CF */
        regs->rax = 0x8021; /* invalid value for numeric or flag parameter */
        return WANT_SET_REGS;
    }

    return WANT_NEWLINE|WANT_SET_REGS;

}

int irq_gpf(void *data, struct emu *emu, struct kvm_regs *regs) {
    debug_printf(0," - Protection Fault");
    __u32 *stack = mem_guest2host(emu, regs->rsp);
    if (stack) {
        __u32 errcode = stack[0];
        debug_printf(0," at addr 0x%08x with %s%s selector 0x%x\n",
            stack[1],
            (errcode&0x1)?"EXT ":"",
            (errcode&0x2)?"IDT": (errcode&0x4)?"LDT":"GDT",
            errcode>>3
        );
    }
    dump_kvm_regs(regs);
    if (stack) {
        debug_printf(0,"Stack:");
        dump_dwords(stack,16);
    }
    dump_backtrace(emu,regs);
    dump_kvm_sregs(emu);

#if 0
    struct kvm_sregs sregs;
    int ret = ioctl(emu->vcpufd, KVM_GET_SREGS, &sregs);
    if (ret == -1)
        err(1, "KVM_GET_SREGS");

    if (sregs.ds.selector == 0) {
        debug_printf(1,"Applying wierd segment fixup\n");

        sregs.ds.selector = SEG_DATA;
        sregs.ds.base = 0;
        sregs.ds.limit = 0xffffffff;
        sregs.ds.type = 3; /* x=0, e=0, w=1, a=1 */
        sregs.ds.dpl = 0;
        sregs.ds.present = 1;
        sregs.ds.db = 1;
        sregs.ds.s = 1;
        sregs.ds.g = 1;
        ret = ioctl(emu->vcpufd, KVM_SET_SREGS, &sregs);
        if (ret == -1)
            err(1, "KVM_SET_SREGS");

        regs->rsp+=4; /* pop the errcode dword */
        return WANT_SET_REGS;
    }
#endif

    exit(1);
}

int handle_subcode(struct irq_subhandler_entry *p, int subcode, struct emu *emu, struct kvm_regs *regs) {
    while (p && p->handler) {
        if (p->subcode == subcode) {
            if (p->name) {
                debug_printf(1," (%s):",p->name);
            }
            int ret = p->handler(p->data, emu, regs);
            return ret;
        }
        p++;
    }
    debug_printf(0," undefined subcode\n");
    exit(1);
}

int irq_subcode_cl(void *data, struct emu *emu, struct kvm_regs *regs) {
    struct irq_subhandler_entry *table = data;
    int subcode = regs->rcx & 0xff;
    debug_printf(1,"CL%02X",subcode);
    return handle_subcode(table, subcode, emu, regs);
}

int irq_subcode_ah(void *data, struct emu *emu, struct kvm_regs *regs) {
    struct irq_subhandler_entry *table = data;
    int subcode = (regs->rax & 0xff00) >>8;
    debug_printf(1,"%02X",subcode);
    return handle_subcode(table, subcode, emu, regs);
}

int irq_subcode_al(void *data, struct emu *emu, struct kvm_regs *regs) {
    struct irq_subhandler_entry *table = data;
    int subcode = regs->rax & 0xff;
    debug_printf(1,"%02X",subcode);
    return handle_subcode(table, subcode, emu, regs);
}

int irq_subcode_ax(void *data, struct emu *emu, struct kvm_regs *regs) {
    struct irq_subhandler_entry *table = data;
    int subcode = regs->rax & 0xffff;
    debug_printf(1,"%04X",subcode);
    return handle_subcode(table, subcode, emu, regs);
}

int irq_unhandled(void *data, struct emu *emu, struct kvm_regs *regs) {
    debug_printf(0,"unhandled irq\n");
    exit(1);
}

int irq_ignore(void *data, struct emu *emu, struct kvm_regs *regs) {
    debug_printf(1,"Ignored\n");
    return 0;
}

struct irq_subhandler_entry irq_dpmi_subcode[] = {
    { .subcode = 0x0000, .name = "ALLOCATE LDT DESCRIPTORS", .handler = irq_dpmi_0000 },
    { .subcode = 0x0001, .name = "FREE LDT DESCRIPTORS", .handler = irq_ignore },
    { .subcode = 0x0006, .name = "GET SEGMENT BASE ADDRESS", .handler = irq_dpmi_0006 },
    { .subcode = 0x0007, .name = "SET SEGMENT BASE ADDRESS", .handler = irq_dpmi_0007 },
    { .subcode = 0x0008, .name = "SET SEGMENT LIMIT", .handler = irq_dpmi_0008 },
    { .subcode = 0x0009, .name = "SET DESCRIPTOR ACCESS RIGHTS", .handler = irq_ignore },
    { .subcode = 0x000a, .name = "CREATE ALIAS DESCRIPTOR", .handler = irq_dpmi_000a },
    { .subcode = 0x0100, .name = "ALLOCATE DOS MEMORY BLOCK", .handler = irq_unhandled },
    { .subcode = 0x0200, .name = "GET REAL MODE INTERRUPT VECTOR", .handler = irq_dpmi_0200 },
    { .subcode = 0x0201, .name = "SET REAL MODE INTERRUPT VECTOR", .handler = irq_dpmi_0201 },
    { .subcode = 0x0202, .name = "GET PROCESSOR EXCEPTION HANDLER VECTOR", .handler = irq_dpmi_0202 },
    { .subcode = 0x0203, .name = "SET PROCESSOR EXCEPTION HANDLER VECTOR", .handler = irq_dpmi_0203 },
    { .subcode = 0x0204, .name = "GET PROTECTED MODE INTERRUPT VECTOR", .handler = irq_dpmi_0204 },
    { .subcode = 0x0205, .name = "SET PROTECTED MODE INTERRUPT VECTOR", .handler = irq_dpmi_0205 },
    { .subcode = 0x0300, .name = "SIMULATE REAL MODE INTERRUPT", .handler = irq_dpmi_0300 },
    { .subcode = 0x0303, .name = "ALLOCATE REAL MODE CALLBACK ADDRESS", .handler = irq_dpmi_0303 },
    { .subcode = 0x0304, .name = "FREE REAL MODE CALLBACK ADDRESS", .handler = irq_ignore },
    { .subcode = 0x0400, .name = "GET DPMI VERSION", .handler = irq_dpmi_0400 },
    { .subcode = 0x0501, .name = "ALLOCATE MEMORY BLOCK", .handler = irq_dpmi_0501 },
    { .subcode = 0x0502, .name = "FREE MEMORY BLOCK", .handler = irq_ignore },
    { .subcode = 0x0507, .name = "SET PAGE ATTRIBUTES", .handler = irq_ignore },
    { .subcode = 0x0600, .name = "LOCK LINEAR REGION", .handler = irq_ignore },
    { .subcode = 0x0800, .name = "PHYSICAL ADDRESS MAPPING", .handler = irq_dpmi_0800 },
    { .subcode = 0x0801, .name = "FREE PHYSICAL ADDRESS MAPPING", .handler = irq_ignore },
    { .subcode = 0x0e01, .name = "SET FP EMULATION", .handler = irq_ignore },
    { 0 },
};

struct irq_subhandler_entry irq_dos_ioctl[] = {
    { .subcode = 0x00, .name = "IOCTL - GET DEVICE INFO", .handler = irq_ignore },
    { 0 },
};

struct irq_subhandler_entry irq_dos_lfn[] = {
    { .subcode = 0x43, .name = "LFN - GET/SET FILE ATTR", .handler = irq_dos_lfn_attr },
    { .subcode = 0x6c, .name = "LFN - OPEN", .handler = irq_dos_lfn_open },
    { .subcode = 0xa0, .name = "LFN - GET VOL INFO", .handler = irq_dos_lfn_volinfo },
    { 0 },
};

struct irq_subhandler_entry irq_dos_subcode[] = {
    { .subcode = 0x19, .name = "GET DRIVE", .handler = irq_dos_get_drive },
    { .subcode = 0x30, .name = "VERSION", .handler = irq_dos_version },
    { .subcode = 0x3e, .name = "CLOSE", .handler = irq_ignore },
    { .subcode = 0x40, .name = "WRITE", .handler = irq_dos_write },
    { .subcode = 0x42, .name = "LSEEK", .handler = irq_dos_lseek },
    { .subcode = 0x44, .handler = irq_subcode_al, .data = irq_dos_ioctl },
    { .subcode = 0x4c, .name = "EXIT", .handler = irq_dos_exit },
    { .subcode = 0x71, .handler = irq_subcode_al, .data = irq_dos_lfn },
    { 0 },
};

struct irq_subhandler_entry irq_video_subcode[] = {
    { .subcode = 0x03, .name = "GET CURSOR POSITION", .handler = irq_ignore },
    { .subcode = 0x08, .name = "READ CHAR and ATTR", .handler = irq_ignore },
    { .subcode = 0x12, .name = "MISC STUFF", .handler = irq_ignore },
    { .subcode = 0x1a, .name = "DISPLAY COMBO", .handler = irq_ignore },
    { .subcode = 0xfe, .name = "GET SHADOW BUFFER", .handler = irq_ignore },
    { 0 },
};

struct irq_subhandler_entry irq_disk_subcode[] = {
    { .subcode = 0x01, .name = "DISK - GET STATUS", .handler = irq_disk_status},
    { .subcode = 0x03, .name = "DISK - WRITE SECTORS", .handler = irq_ignore },
    { 0 },
};

/*
 * Top level table of every IRQ possible
 */
struct irq_handler_entry irq_handlers[256] = {
    [0x0d] = { .name = "GPF",   .handler = irq_gpf },
    [0x10] = { .handler = irq_subcode_ah, .data = irq_video_subcode },
    [0x13] = { .handler = irq_subcode_ah, .data = irq_disk_subcode },
    [0x21] = { .handler = irq_subcode_ah, .data = irq_dos_subcode },
    [0x31] = { .handler = irq_subcode_ax, .data = irq_dpmi_subcode },
};

int handle_irqno(struct irq_handler_entry *p, unsigned char irqno, struct emu *emu, struct kvm_regs *regs) {
    debug_printf(1,"%07x: -%02X",get_retaddr(emu,regs),irqno);

    if (!p[irqno].handler) {
        debug_printf(0," undefined irq\n");
        dump_kvm_exit(emu);
        exit(1);
    }

    if (p[irqno].name) {
        debug_printf(1,"'%s'",p[irqno].name);
    }
    return p[irqno].handler(p[irqno].data,emu,regs);
}

int handle_softirq(struct emu *emu) {
    struct kvm_run *run = emu->run;
    if (run->io.direction != KVM_EXIT_IO_OUT || run->io.size != 4 || run->io.port != 0x7f || run->io.count != 1) {
        return 0;
    }

    struct kvm_regs regs;
    int ret = ioctl(emu->vcpufd, KVM_GET_REGS, &regs);
    if (ret == -1)
        err(1, "KVM_GET_REGS");

    __u64 idt_start = emu->mem[MEM_REGION_IDT].guest_phys_addr;
    __u64 idt_end = emu->mem[MEM_REGION_IDT].guest_phys_addr + emu->mem[MEM_REGION_IDT].memory_size;
    if (regs.rip < idt_start || regs.rip > idt_end) {
        err(1, "softirq from outside idt region");
    }

    unsigned char irqno = (regs.rip - REGION_IDT_BASE - 0x800) >> 2;
    ret = handle_irqno(emu->irq,irqno,emu,&regs);

    if (ret & WANT_SET_REGS) {
        int ret = ioctl(emu->vcpufd, KVM_SET_REGS, &regs);
        if (ret == -1)
            err(1, "KVM_SET_REGS");
    }
    if (ret & WANT_NEWLINE) {
        debug_printf(1,"\n");
    }

    return 1;
}

int handle_smi(struct emu *emu) {
    struct kvm_run *run = emu->run;
    if (run->io.direction != KVM_EXIT_IO_OUT || run->io.size != 1 || run->io.port != 178 || run->io.count != 1) {
        return 0;
    }

    __u64 val = 0;
    /* FIXME - what if size is > 8 ? */
    memcpy(&val,((char *)run)+run->io.data_offset,run->io.size);

    emu->smi_count++;

    struct kvm_regs regs;
    int ret = ioctl(emu->vcpufd, KVM_GET_REGS, &regs);
    if (ret == -1)
        err(1, "KVM_GET_REGS");
    debug_printf(1,"%07llx: SMI (port[0x%02llx] = 0x%02llx)\n", regs.rip, run->io.port, val);

    if (emu->smi_count>10) {
        /* crash-stop on the nth smi call */

        /* >10 is just after the open of the binary */
        return 0;
    }

    /* do nothing, yet? */
    return 1;
}

int handle_console(struct emu *emu) {
    struct kvm_run *run = emu->run;
    if (run->io.direction != KVM_EXIT_IO_OUT || run->io.size != 1 || run->io.port != 0x3f8 || run->io.count != 1) {
        return 0;
    }

    putchar(*(((char *)run) + run->io.data_offset));
    return 1;
}

int handle_mmio(struct emu *emu) {
    int mmio_verbose;
    struct kvm_run *run = emu->run;
    __u32 old_mmio_next = emu->mmio_next;

    void *addr = mem_guest2host(emu, run->mmio.phys_addr);
    if (!addr) {
        return 0;
    }

    /* Special addresses - TODO handle them?
    0x449 - CURRENT VIDEO MODE
    0x465 - CURRENT MODE SELECT REGISTER
    0x484 - ROWS ON SCREEN MINUS ONE
     */

    if (run->mmio.is_write) {
        memcpy(addr, run->mmio.data, run->mmio.len);
    } else {
        memcpy(run->mmio.data, addr ,run->mmio.len);
    }

    emu->mmio_next = run->mmio.phys_addr+run->mmio.len;

    if (run->mmio.phys_addr == old_mmio_next) {
        /* quickly detect repeated sequential access and be less verbose */
        emu->mmio_count++;
        mmio_verbose = 0;
    } else {
        emu->mmio_count = 0;
        mmio_verbose = 1;
    }

    if (emu->mmio_count%32768 == 0) {
        /* show data every now and again, regardless */
        mmio_verbose = 1;
    }

    if (mmio_verbose) {
        struct kvm_regs regs;
        int ret = ioctl(emu->vcpufd, KVM_GET_REGS, &regs);
        if (ret == -1)
            err(1, "KVM_GET_REGS");

        debug_printf(1,"%07llx: MMIO %s: 0x%08llx(0x%x)\n",
            regs.rip,
            run->mmio.is_write?"write":"read",
            run->mmio.phys_addr,run->mmio.len
        );
        dump_kvm_regs(&regs);
        dump_backtrace(emu,&regs);
    } else {
        debug_printf(1,".");
    }
    return 1;
}

int handle_debug(struct emu *emu) {
    struct kvm_regs regs;
    int ret = ioctl(emu->vcpufd, KVM_GET_REGS, &regs);
    if (ret == -1)
        err(1, "KVM_GET_REGS");

    int verbose;
    int old_debug_count = emu->debug_count;

    if (regs.rip == emu->debug_addr) {
        verbose = 0;
    } else if (regs.rip > emu->debug_addr && regs.rip < emu->debug_addr+8) {
        /* this looks like a continuation of the previous exec stream */
        emu->debug_count++;
        verbose = 0;
    } else {
        emu->debug_count = 0;
        verbose = 1;
    }

    if (emu->debug_count%256 == 0) {
        /* show data every now and again, regardless */
        verbose = 1;
    }

    if (verbose) {
        debug_printf(1,"T 0x%llx %i\n", regs.rip, old_debug_count);
    }
    emu->debug_addr = regs.rip;
    return 1;
}

int main(int argc, char **argv)
{
    int ret;
    struct emu * emu = &emu_global;

    emu->region_brk = MEM_REGION_SYS_MAX+1;

    if (argc<3) {
        printf("Need args: filename configfile\n");
        return 1;
    }
    char *filename=argv[1];
    char *configfile=argv[2];
    if (load_configfile(emu,configfile) == -1) {
        return 1;
    }

    char *cmdline=argv[3];

    kvm_init(emu);

    if (load_image(emu,filename,cmdline) == -1) {
        return 1;
    }

    emu->irq = &irq_handlers[0];

    struct kvm_guest_debug debug;
    debug.control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP;

    /* Repeatedly run code and handle VM exits. */
    while (1) {
        struct kvm_run *run = emu->run;
        if (emu->trace) {
            ret = ioctl(emu->vcpufd, KVM_SET_GUEST_DEBUG, &debug);
            if (ret == -1)
                err(1, "KVM_SET_GUEST_DEBUG");
        }
        ret = ioctl(emu->vcpufd, KVM_RUN, NULL);
        if (ret == -1)
            err(1, "KVM_RUN");

        switch (run->exit_reason) {
        case KVM_EXIT_HLT:
            dump_kvm_exit(emu);
            puts("KVM_EXIT_HLT");
            return 0;
        case KVM_EXIT_IO:
            if (handle_softirq(emu)) {
                continue;
            }
            if (handle_smi(emu)) {
                continue;
            }
            if (handle_console(emu)) {
                continue;
            }
            dump_kvm_exit(emu);
            errx(1, "unhandled KVM_EXIT_IO");
        case KVM_EXIT_MMIO:
            if (handle_mmio(emu)) {
                continue;
            }
            dump_kvm_exit(emu);
            err(1, "unhandled MMIO");
        case KVM_EXIT_FAIL_ENTRY:
            dump_kvm_exit(emu);
            errx(1, "KVM_EXIT_FAIL_ENTRY: hardware_entry_failure_reason = 0x%llx",
                 (unsigned long long)run->fail_entry.hardware_entry_failure_reason);
        case KVM_EXIT_INTERNAL_ERROR:
            dump_kvm_exit(emu);
            errx(1, "KVM_EXIT_INTERNAL_ERROR: suberror = 0x%x", run->internal.suberror);
        case KVM_EXIT_DEBUG:
            handle_debug(emu);
            break;
        default:
            dump_kvm_exit(emu);
            errx(1, "exit_reason = 0x%x", run->exit_reason);
        }
    }
}
