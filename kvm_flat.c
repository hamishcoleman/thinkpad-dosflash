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

#define MAX_MEM_REGIONS 6
#define MEM_REGION_GDT   0
#define MEM_REGION_IDT   1
#define MEM_REGION_STACK 2
#define MEM_REGION_TEXT  3
#define MEM_REGION_BIOS  4
#define MEM_REGION_BSS   5

struct irq_handler_entry; /* forward definition */
struct emu {
    int kvm;
    int vmfd;
    int vcpufd;
    struct kvm_run *run;
    struct kvm_userspace_memory_region mem[MAX_MEM_REGIONS];
    unsigned int bss_brk; /* start of available bss */
    unsigned int gdt_brk; /* start of available descriptors */

    struct irq_handler_entry *irq;
} emu_global;

#define STACK_SIZE 0x4000
#define STACK_BASE 0xf0000000
#define IDT_SIZE 0x1000
#define IDT_BASE 0xf0010000
#define GDT_SIZE 0x1000
#define GDT_BASE 0xf0020000

#define BIOS_BASE 0x000c0000
#define BIOS_SIZE 0x00040000

#define BSS_SIZE 0x00040000

#define SEL_TEXT 0x08 /* gdt[1] */
#define SEL_DATA 0x10 /* gdt[2] */
#define MAX_SYS_SEL SEL_DATA

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
int handle_irqno(struct irq_handler_entry *, unsigned char, struct emu *, struct kvm_regs *); /* forward definition */

void *mem_guest2host(struct emu *emu, __u64 guestaddr) {
    for (int i=0; i<MAX_MEM_REGIONS; i++) {
        if (guestaddr >= emu->mem[i].guest_phys_addr && guestaddr <= emu->mem[i].guest_phys_addr + emu->mem[i].memory_size) {
            return (uint8_t *)emu->mem[i].userspace_addr + (guestaddr - emu->mem[i].guest_phys_addr);
        }
    }
    return NULL;
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

    printf("%s(%i)\n",kvm_exit_str[run->exit_reason],run->exit_reason);
    switch (run->exit_reason) {
    case KVM_EXIT_INTERNAL_ERROR:
        printf("\tsuberror: 0x%x\n",run->internal.suberror);
        break;
    case KVM_EXIT_MMIO:
        printf("\tphys_addr: 0x%llx\n",run->mmio.phys_addr);
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
        if (i%8 == 0) {
            printf("\n ");
        }
        printf("0x%08x ",*p++);
        i++;
    }
    printf("\n");
}

void dump_kvm_regs(struct kvm_regs *regs) {
    printf("ax=0x%08llx bx=0x%08llx cx=0x%08llx dx=0x%08llx flags=0x%08llx\n",
        regs->rax,regs->rbx,regs->rcx,regs->rdx,regs->rflags);
#if 0
    printf("8=0x%08x 9=0x%08x 10=0x%08x 11=0x%08x 12=0x%08x\n",
        regs->r8,regs->r9,regs->r10,regs->r11,regs->r12);
#endif
    printf("si=0x%08llx di=0x%08llx sp=0x%08llx bp=0x%08llx ip=0x%08llx ",
        regs->rsi,regs->rdi,regs->rsp,regs->rbp,regs->rip);

    __u32 *stack = mem_guest2host(&emu_global, regs->rsp);
    if (stack) {
        printf("(%07x)\n",*stack);
#if 0
        printf("Stack:");
        dump_dwords(stack,6);
#endif
    }
}

void dump_kvm_segment(struct kvm_segment *seg, char *name) {
    unsigned int limit;
    if (seg->g) {
        limit = (seg->limit <<12) + 0xfff;
    } else {
        limit = seg->limit;
    }
    printf("%s:%02x %08llx(%08x) type=%x dpl=%i %s%s%s%s%s\n",
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
    printf("%s: %08llx(%08x)\n",
        name,seg->base,seg->limit);
}

void dump_kvm_sregs(struct emu *emu) {
    struct kvm_sregs sregs;
    int ret = ioctl(emu->vcpufd, KVM_GET_SREGS, &sregs);
    if (ret == -1)
        err(1, "KVM_GET_SREGS");
    printf("cr0=0x%08llx\n",
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
    printf("irq:");
    for (int i = 0; i < (KVM_NR_INTERRUPTS + 63) / 64; i++) {
        printf("%016llx",sregs.interrupt_bitmap[i]);
    }
#endif
    printf("\n");
}

void dump_kvm_memmap(struct emu *emu) {
    struct kvm_userspace_memory_region *p = &emu->mem[0];
    printf("Memmap:\n");
    for (int i=0; i<MAX_MEM_REGIONS; i++,p++) {
        printf("%i: 0x%08llx(0x%08llx) = 0x%08llx (flags=%x)\n",
            p->slot, p->guest_phys_addr, p->memory_size,
            p->userspace_addr, p->flags
        );
    }
}

void dump_kvm_exit(struct emu *emu) {
    struct kvm_regs regs;
    int ret = ioctl(emu->vcpufd, KVM_GET_REGS, &regs);
    if (ret == -1)
        err(1, "KVM_GET_REGS");

    printf("\n");
    dump_kvm_run(emu->run);
    dump_kvm_regs(&regs);
    switch(emu->run->exit_reason) {
    case KVM_EXIT_SHUTDOWN:
    case KVM_EXIT_MMIO:
        dump_kvm_sregs(emu);
        __u32 *stack = mem_guest2host(&emu_global, regs.rsp);
        printf("Stack:");
        dump_dwords(stack,16);
        dump_kvm_memmap(emu);
        break;
    }
}

void setup_gdt(struct kvm_sregs *sregs, struct emu *emu) {
    struct gdt_entry *gdt = mmap(NULL, GDT_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (!gdt)
        err(1, "allocating gdt memory");

    memset(gdt,0,GDT_SIZE);

    /* code segment */
    gdt[1].type_flags  = 0x9e;
    gdt[1].limit_flags = 0x40; /* Set the 32bit segment flag */
    gdt_setlimit(&gdt[1],0xffffffff);

    /* data segment */
    gdt[2].type_flags = 0x92;
    gdt[2].limit_flags = 0x40;
    gdt_setlimit(&gdt[2],0xffffffff);

    emu->mem[MEM_REGION_GDT].slot = MEM_REGION_GDT;
    emu->mem[MEM_REGION_GDT].guest_phys_addr = GDT_BASE;
    emu->mem[MEM_REGION_GDT].memory_size = GDT_SIZE;
    emu->mem[MEM_REGION_GDT].userspace_addr = (uint64_t)gdt;

    int ret = ioctl(emu->vmfd, KVM_SET_USER_MEMORY_REGION, &emu->mem[MEM_REGION_GDT]);
    if (ret == -1)
        err(1, "KVM_SET_USER_MEMORY_REGION");

    emu->gdt_brk = (MAX_SYS_SEL>>3) +1;

    sregs->gdt.base = GDT_BASE;
    sregs->gdt.limit = GDT_SIZE;
}

void setup_idt(struct kvm_sregs *sregs,struct emu *emu) {
    struct idt *idt = mmap(NULL, IDT_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (!idt)
        err(1, "allocating idt memory");

    for (int i=0; i<256; i++) {
        idt->entry[i].offset_l = sizeof(idt->entry) + i*sizeof(idt->hlt[i]);
        idt->entry[i].selector = SEL_TEXT;
        idt->entry[i].always0 = 0;
        idt->entry[i].type_flags = 0xee; /* dpl=3, present, 32-bit interrupt */
        idt->entry[i].offset_h = IDT_BASE>>16;
        idt->hlt[i][0] = 0xe7; /* out imm8,ax */
        idt->hlt[i][1] = 0x7f; /* imm8 = 0x7f */
        idt->hlt[i][2] = 0xcf; /* iret */
        idt->hlt[i][3] = 0xf4; /* hlt */
    }

    emu->mem[MEM_REGION_IDT].slot = MEM_REGION_IDT;
    emu->mem[MEM_REGION_IDT].guest_phys_addr = IDT_BASE;
    emu->mem[MEM_REGION_IDT].memory_size = IDT_SIZE;
    emu->mem[MEM_REGION_IDT].userspace_addr = (uint64_t)idt;

    int ret = ioctl(emu->vmfd, KVM_SET_USER_MEMORY_REGION, &emu->mem[MEM_REGION_IDT]);
    if (ret == -1)
        err(1, "KVM_SET_USER_MEMORY_REGION");

    sregs->idt.base = IDT_BASE;
    sregs->idt.limit = sizeof(idt->entry);
}

void setup_flat_segments(struct kvm_sregs *sregs) {
    sregs->cs.base = 0;
    sregs->cs.limit = 0xfffff;
    sregs->cs.selector = SEL_TEXT; /* gdt[1] */
    sregs->cs.db = 1;
    sregs->cs.g = 1;
    sregs->cs.type = 0xe; /* x=1, c=1, r=1, a=0 */
    memcpy(&sregs->ds,&sregs->cs,sizeof(sregs->cs));
    sregs->ds.selector = SEL_DATA; /* gdt[2] */
    sregs->ds.type = 2; /* x=0, e=0, w=1, a=0 */
    /* FIXME - set ds.type correctly sregs->ds.type = 2 ? */
    memcpy(&sregs->es,&sregs->ds,sizeof(sregs->ds));
    memcpy(&sregs->fs,&sregs->ds,sizeof(sregs->ds));
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

    void *stack = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (!stack)
        err(1, "allocating guest stack");

    emu->mem[MEM_REGION_STACK].slot = MEM_REGION_STACK;
    emu->mem[MEM_REGION_STACK].guest_phys_addr = STACK_BASE;
    emu->mem[MEM_REGION_STACK].memory_size = STACK_SIZE;
    emu->mem[MEM_REGION_STACK].userspace_addr = (uint64_t)stack;

    ret = ioctl(emu->vmfd, KVM_SET_USER_MEMORY_REGION, &emu->mem[MEM_REGION_STACK]);
    if (ret == -1)
        err(1, "KVM_SET_USER_MEMORY_REGION");

    void *bios = mmap(NULL, BIOS_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (!bios)
        err(1, "allocating bios area");

    emu->mem[MEM_REGION_BIOS].slot = MEM_REGION_BIOS;
    emu->mem[MEM_REGION_BIOS].guest_phys_addr = BIOS_BASE;
    emu->mem[MEM_REGION_BIOS].memory_size = BIOS_SIZE;
    emu->mem[MEM_REGION_BIOS].userspace_addr = (uint64_t)bios;

    ret = ioctl(emu->vmfd, KVM_SET_USER_MEMORY_REGION, &emu->mem[MEM_REGION_BIOS]);
    if (ret == -1)
        err(1, "KVM_SET_USER_MEMORY_REGION");

    return 0;
}

int load_image(struct emu *emu, char *filename, unsigned long entry) {
    int ret;

    const uint8_t code[] = {
        0xba, 0xf8, 0x03, 0,0, /* mov $0x3f8, %dx */
        0x00, 0xd8,       /* add %bl, %al */
        0x04, '0',        /* add $'0', %al */
        0xee,             /* out %al, (%dx) */
        0xb0, '\n',       /* mov $'\n', %al */
        0xee,             /* out %al, (%dx) */
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

    emu->mem[MEM_REGION_TEXT].slot = MEM_REGION_TEXT;
    emu->mem[MEM_REGION_TEXT].guest_phys_addr = 0;
    emu->mem[MEM_REGION_TEXT].memory_size = text_size;
    emu->mem[MEM_REGION_TEXT].userspace_addr = (uint64_t)text;

    ret = ioctl(emu->vmfd, KVM_SET_USER_MEMORY_REGION, &emu->mem[MEM_REGION_TEXT]);
    if (ret == -1)
        err(1, "KVM_SET_USER_MEMORY_REGION");

    __u64 bss_size = BSS_SIZE;
    uint8_t *bss = mmap(NULL, bss_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (!bss)
        err(1, "allocating bss");

    emu->mem[MEM_REGION_BSS].slot = MEM_REGION_BSS;
    emu->mem[MEM_REGION_BSS].guest_phys_addr = emu->mem[MEM_REGION_TEXT].memory_size + 0x1000;
    emu->mem[MEM_REGION_BSS].memory_size = bss_size;
    emu->mem[MEM_REGION_BSS].userspace_addr = (uint64_t)bss;

    ret = ioctl(emu->vmfd, KVM_SET_USER_MEMORY_REGION, &emu->mem[MEM_REGION_BSS]);
    if (ret == -1)
        err(1, "KVM_SET_USER_MEMORY_REGION");

    emu->bss_brk = STACK_SIZE; /* start a little from the bottom - silly things put stacks here */

    /* Initialize registers: instruction pointer for our code and
     * initial flags required by x86 architecture. */
    struct kvm_regs regs = {
        .rip = entry,
        .rax = 0,
        .rbx = 0,
        .rflags = 0x2,
        .rsp = STACK_BASE + emu->mem[MEM_REGION_STACK].memory_size - 0x10,
    };
    ret = ioctl(emu->vcpufd, KVM_SET_REGS, &regs);
    if (ret == -1)
        err(1, "KVM_SET_REGS");

    return 0;
}

int alloc_bss(struct emu *emu, unsigned int size) {
    if (emu->bss_brk + size > emu->mem[MEM_REGION_BSS].memory_size) {
        return 0;
    }
    unsigned int guest_addr = emu->mem[MEM_REGION_BSS].guest_phys_addr + emu->bss_brk;
    emu->bss_brk += size;
    return guest_addr;
}

void iret_setflags(struct kvm_regs *regs, unsigned int setflags) {
    __u32 *stack = mem_guest2host(&emu_global, regs->rsp);
    if (stack) {
        stack[1] |= setflags;
    }
}

int irq_dos_exit(void *data, struct emu *emu, struct kvm_regs *regs) {
    printf(" return=0x%02llx\n",regs->rax & 0xff);
    exit(0);
}

int irq_dos_version(void *data, struct emu *emu, struct kvm_regs *regs) {
    regs->rax = 0x0004; /* DOS 4.00 */
    regs->rbx = 0x0; /* DOS OEM is IBM */
    return WANT_SET_REGS;
}

/* allocate ldt desriptors */
int irq_dpmi_0000(void *data, struct emu *emu, struct kvm_regs *regs) {
    /* for the moment, try just giving it a GDT entry... */

    /* make it a copy of the data segment */
    struct gdt_entry *gdt = (struct gdt_entry *)emu->mem[MEM_REGION_GDT].userspace_addr;
    memcpy(&gdt[emu->gdt_brk],&gdt[SEL_DATA>>3],sizeof(*gdt));

    regs->rax = emu->gdt_brk<<3;
    emu->gdt_brk++;

    return WANT_SET_REGS;
}

/* get segment base address */
int irq_dpmi_0006(void *data, struct emu *emu, struct kvm_regs *regs) {
    regs->rcx = regs->rdx = 0;
    return WANT_SET_REGS;
}

/* set segment limit */
int irq_dpmi_0008(void *data, struct emu *emu, struct kvm_regs *regs) {
    struct gdt_entry *gdt = (struct gdt_entry *)emu->mem[MEM_REGION_GDT].userspace_addr;

    if (regs->rbx & 0x7) {
        err(1, "Unexpected selector options");
    }
    int selector = (regs->rbx & 0xffff);
    if (selector <= MAX_SYS_SEL ) {
        printf("Cowardly refusing to change system segments\n");
        return WANT_NONE;
    }
    __u32 limit = (regs->rcx & 0xffff)<<16 | (regs->rdx & 0xffff);
    printf("limit(0x%x)=0x%08x",selector,limit);

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
        return WANT_NONE;
    }

    memcpy(&gdt[emu->gdt_brk],&gdt[entry_orig],sizeof(*gdt));

    regs->rax = emu->gdt_brk<<3;
    emu->gdt_brk++;

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
}

/* SIMULATE REAL MODE INTERRUPT */
int irq_dpmi_0300(void *data, struct emu *emu, struct kvm_regs *regs) {
    int irqno = regs->rbx & 0xff;
    printf("irq 0x%02x\n",irqno);

    void *call16 = mem_guest2host(emu, regs->rdi);
    if (!call16) {
        err(1, "could not map guest to host");
    }
    struct kvm_regs call;
    dpmi_call2regs(call16,&call);
    printf("Real mode registers:\n");
    dump_kvm_regs(&call);
    handle_irqno(emu->irq,irqno,emu,&call); /* TODO - something with ret */

    /* always repopulate the call structure - it is just simpler */
    dpmi_regs2call(&call, call16);

    return WANT_NONE;
}

int irq_dpmi_0303(void *data, struct emu *emu, struct kvm_regs *regs) {
    printf("\n");
    printf("Callback to DS:0x%08llx\n", regs->rsi);

    void *call16 = mem_guest2host(emu, regs->rdi);
    if (!call16) {
        err(1, "could not map guest to host");
    }
    struct kvm_regs call;
    dpmi_call2regs(call16,&call);
    printf("Real mode registers:\n");
    dump_kvm_regs(&call);

    regs->rcx = 0;
    regs->rdx = 0xaa55aa55;
    return WANT_SET_REGS;

    dump_kvm_sregs(emu);
    __u32 *stack = mem_guest2host(&emu_global, regs->rsp);
    printf("Stack:");
    dump_dwords(stack,16);
    exit(1);
}

/* GET DPMI VERSION */
int irq_dpmi_0400(void *data, struct emu *emu, struct kvm_regs *regs) {
    regs->rax = 0x0100; /* DPMI version 1.0 */
    regs->rbx = 0x3; /* 386 and no v86 */
    regs->rcx = 0x04; /* 80486 */
    regs->rdx = 0x5aa5; /* some virtual interrupt thing */
    return WANT_SET_REGS;
}

int irq_dpmi_0501(void *data, struct emu *emu, struct kvm_regs *regs) {
    unsigned int size = (regs->rbx & 0xffff) <<16 | (regs->rcx & 0xffff);
    unsigned int addr = alloc_bss(emu, size);

    printf("alloc(%i) = 0x%08x",size,addr);

    if (!addr) {
        iret_setflags(regs,1); /* set CF */
        return WANT_NONE;
    }

    regs->rbx = regs->rsi = addr >> 16;
    regs->rcx = regs->rdi = addr & 0xffff;

    return WANT_SET_REGS;
}

int irq_gpf(void *data, struct emu *emu, struct kvm_regs *regs) {
    printf("- General Protection");
    __u32 *stack = mem_guest2host(emu, regs->rsp);
    if (stack) {
        __u32 errcode = stack[0];
        printf(" at address 0x%08x with %s%s selector 0x%x\n",
            stack[1],
            (errcode&0x1)?"EXT ":"",
            (errcode&0x2)?"IDT": (errcode&0x4)?"LDT":"GDT",
            errcode>>3
        );
        printf("Stack:");
        dump_dwords(stack,16);
    }

    dump_kvm_sregs(emu);
    exit(1);
}

int handle_subcode(struct irq_subhandler_entry *p, int subcode, struct emu *emu, struct kvm_regs *regs) {
    while (p && p->name) {
        if (p->subcode == subcode) {
            printf(" (%s):",p->name);
            int ret = p->handler(p->data, emu, regs);
            printf("\n");
            return ret;
        }
        p++;
    }
    printf("\nundefined subcode\n");
    exit(1);
}

int irq_subcode_ah(void *data, struct emu *emu, struct kvm_regs *regs) {
    struct irq_subhandler_entry *table = data;
    int subcode = (regs->rax & 0xff00) >>8;
    printf("%02X",subcode);
    return handle_subcode(table, subcode, emu, regs);
}

int irq_subcode_ax(void *data, struct emu *emu, struct kvm_regs *regs) {
    struct irq_subhandler_entry *table = data;
    int subcode = regs->rax & 0xffff;
    printf("%04X",subcode);
    return handle_subcode(table, subcode, emu, regs);
}

int irq_unhandled(void *data, struct emu *emu, struct kvm_regs *regs) {
    printf("unhandled irq");
    exit(1);
}

int irq_ignore(void *data, struct emu *emu, struct kvm_regs *regs) {
    printf("Ignored");
    return 0;
}

struct irq_subhandler_entry irq_dpmi_subcode[] = {
    { .subcode = 0x0000, .name = "ALLOCATE LDT DESCRIPTORS", .handler = irq_dpmi_0000 },
    { .subcode = 0x0006, .name = "GET SEGMENT BASE ADDRESS", .handler = irq_dpmi_0006 },
    { .subcode = 0x0007, .name = "SET SEGMENT BASE ADDRESS", .handler = irq_ignore },
    { .subcode = 0x0008, .name = "SET SEGMENT LIMIT", .handler = irq_dpmi_0008 },
    { .subcode = 0x0009, .name = "SET DESCRIPTOR ACCESS RIGHTS", .handler = irq_ignore },
    { .subcode = 0x000a, .name = "CREATE ALIAS DESCRIPTOR", .handler = irq_dpmi_000a },
    { .subcode = 0x0200, .name = "GET REAL MODE INTERRUPT VECTOR", .handler = irq_ignore },
    { .subcode = 0x0201, .name = "SET REAL MODE INTERRUPT VECTOR", .handler = irq_ignore },
    { .subcode = 0x0202, .name = "GET PROCESSOR EXCEPTION HANDLER VECTOR", .handler = irq_ignore },
    { .subcode = 0x0203, .name = "SET PROCESSOR EXCEPTION HANDLER VECTOR", .handler = irq_ignore },
    { .subcode = 0x0204, .name = "GET PROTECTED MODE INTERRUPT VECTOR", .handler = irq_ignore },
    { .subcode = 0x0205, .name = "SET PROTECTED MODE INTERRUPT VECTOR", .handler = irq_ignore },
    { .subcode = 0x0300, .name = "SIMULATE REAL MODE INTERRUPT", .handler = irq_dpmi_0300 },
    { .subcode = 0x0303, .name = "ALLOCATE REAL MODE CALLBACK ADDRESS", .handler = irq_dpmi_0303 },
    { .subcode = 0x0400, .name = "GET DPMI VERSION", .handler = irq_dpmi_0400 },
    { .subcode = 0x0501, .name = "ALLOCATE MEMORY BLOCK", .handler = irq_dpmi_0501 },
    { .subcode = 0x0507, .name = "SET PAGE ATTRIBUTES", .handler = irq_ignore },
    { .subcode = 0x0600, .name = "LOCK LINEAR REGION", .handler = irq_ignore },
    { 0 },
};

struct irq_subhandler_entry irq_dos_subcode[] = {
    { .subcode = 0x30, .name = "VERSION", .handler = irq_dos_version },
    { .subcode = 0x4c, .name = "EXIT", .handler = irq_dos_exit },
    { 0 },
};

/*
 * Top level table of every IRQ possible
 */
struct irq_handler_entry irq_handlers[256] = {
    [0x0d] = { .name = "GPF",  .handler = irq_gpf },
    [0x21] = { .name = "DOS",  .handler = irq_subcode_ah, .data = irq_dos_subcode },
    [0x31] = { .name = "DPMI", .handler = irq_subcode_ax, .data = irq_dpmi_subcode },
};

int handle_irqno(struct irq_handler_entry *p, unsigned char irqno, struct emu *emu, struct kvm_regs *regs) {
    printf("INT ");

    if (!p[irqno].name) {
        printf("-%02X ",irqno);
        __u32 *stack = mem_guest2host(emu, regs->rsp);
        if (stack) {
            printf("retaddr=0x%08x\n",stack[4]);
        }
        printf("undefined irq");
        exit(1);
    }

    printf("'%s' -%02X",p[irqno].name,irqno);
    return p[irqno].handler(p[irqno].data,emu,regs);
}

int handle_softirq(struct emu *emu) {
    struct kvm_regs regs;
    int ret = ioctl(emu->vcpufd, KVM_GET_REGS, &regs);
    if (ret == -1)
        err(1, "KVM_GET_REGS");

    __u64 idt_start = emu->mem[MEM_REGION_IDT].guest_phys_addr;
    __u64 idt_end = emu->mem[MEM_REGION_IDT].guest_phys_addr + emu->mem[MEM_REGION_IDT].memory_size;
    if (regs.rip < idt_start || regs.rip > idt_end) {
        err(1, "softirq from outside idt region");
    }

    unsigned char irqno = (regs.rip - IDT_BASE - 0x800) >> 2;
    ret = handle_irqno(emu->irq,irqno,emu,&regs);

    if (ret == WANT_SET_REGS) {
        int ret = ioctl(emu->vcpufd, KVM_SET_REGS, &regs);
        if (ret == -1)
            err(1, "KVM_SET_REGS");
    }

    return 0;
}

int main(int argc, char **argv)
{
    int ret;
    char *filename;
    unsigned long entry;
    struct emu * emu = &emu_global;

    if (argc<3) {
        printf("Need args: filename entry\n");
        return 1;
    }
    filename=argv[1];
    entry=strtoul(argv[2],NULL,0);

    kvm_init(emu);

    if (load_image(emu,filename,entry) == -1) {
        return 1;
    }

    emu->irq = &irq_handlers[0];

    /* Repeatedly run code and handle VM exits. */
    while (1) {
        struct kvm_run *run = emu->run;
        ret = ioctl(emu->vcpufd, KVM_RUN, NULL);
        if (ret == -1)
            err(1, "KVM_RUN");
        dump_kvm_exit(emu);
        switch (run->exit_reason) {
        case KVM_EXIT_HLT:
            puts("KVM_EXIT_HLT");
            return 0;
        case KVM_EXIT_IO:
            if (run->io.direction == KVM_EXIT_IO_OUT && run->io.size == 4 && run->io.port == 0x7f && run->io.count == 1) {
                handle_softirq(emu);
            } else if (run->io.direction == KVM_EXIT_IO_OUT && run->io.size == 1 && run->io.port == 0x3f8 && run->io.count == 1)
                putchar(*(((char *)run) + run->io.data_offset));
            else
                errx(1, "unhandled KVM_EXIT_IO");
            break;
        case KVM_EXIT_FAIL_ENTRY:
            errx(1, "KVM_EXIT_FAIL_ENTRY: hardware_entry_failure_reason = 0x%llx",
                 (unsigned long long)run->fail_entry.hardware_entry_failure_reason);
        case KVM_EXIT_INTERNAL_ERROR:
            errx(1, "KVM_EXIT_INTERNAL_ERROR: suberror = 0x%x", run->internal.suberror);
        default:
            errx(1, "exit_reason = 0x%x", run->exit_reason);
        }
    }
}
