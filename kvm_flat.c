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

struct irq_subhandler_entry {
    int subcode;
    char *name;
    void (*handler)(int, struct kvm_regs *);
};

struct irq_handler_entry {
    char *name;
    void (*handler)(void *,int, struct kvm_regs *);
    void *data;
};

struct gdt_entry {
    __u16 limit_l;
    __u16 base_l;
    __u8 base_m;
    __u8 type_flags;
    __u8 limit_flags;
    __u8 base_h;
};

struct idt_entry {
    __u16 offset_l;
    __u16 selector;
    __u8 always0;
    __u8 type_flags;
    __u16 offset_h;
};

struct idt {
    struct idt_entry entry[256];
    uint8_t hlt[256][4];
};

struct emu {
    int kvm;
    int vmfd;
    int vcpufd;
    struct kvm_run *run;
    struct gdt_entry *gdt;
    struct idt *idt;
    void *text;
    unsigned int text_size;
    void *stack;
    unsigned int stack_size;
    unsigned int bss_base;
    void *bss;
    unsigned int bss_size;
    unsigned int bss_brk;
} emu_global;

#define STACK_SIZE 0x4000
#define STACK_BASE 0xf0000000
#define IDT_SIZE 0x1000
#define IDT_BASE 0xf0010000
#define GDT_SIZE 0x1000
#define GDT_BASE 0xf0020000

#define BSS_SIZE 0x00040000

#define MEM_REGION_GDT   0
#define MEM_REGION_IDT   1
#define MEM_REGION_STACK 2
#define MEM_REGION_TEXT  3
#define MEM_REGION_BSS   4

#define SEL_TEXT 0x08 /* gdt[1] */
#define SEL_DATA 0x10 /* gdt[2] */
#define SEL_FAKE 0x18
#define SEL_STACK FIXME

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

void dump_kvm_regs(struct emu *emu) {
    struct kvm_regs regs;
    int ret = ioctl(emu->vcpufd, KVM_GET_REGS, &regs);
    if (ret == -1)
        err(1, "KVM_GET_REGS");
    printf("ax=0x%08llx bx=0x%08llx cx=0x%08llx dx=0x%08llx flags=0x%08llx\n",
        regs.rax,regs.rbx,regs.rcx,regs.rdx,regs.rflags);
#if 0
    printf("8=0x%08x 9=0x%08x 10=0x%08x 11=0x%08x 12=0x%08x\n",
        regs.r8,regs.r9,regs.r10,regs.r11,regs.r12);
#endif
    printf("si=0x%08llx di=0x%08llx sp=0x%08llx bp=0x%08llx ip=0x%08llx ",
        regs.rsi,regs.rdi,regs.rsp,regs.rbp,regs.rip);

    __u32 retaddr;
    __u32 stack_addr = regs.rsp - STACK_BASE;
    if (stack_addr < STACK_SIZE) {
        retaddr = *(__u32 *)(emu->stack + stack_addr);
    }
    printf("(%07x)\n",retaddr);
}

void dump_kvm_segment(struct kvm_segment *seg, char *name) {
    unsigned int limit;
    if (seg->g) {
        limit = (seg->limit <<12) + 0xfff;
    } else {
        limit = seg->limit;
    }
    printf("%s:%02x %08llx(%08x)\n",
        name,seg->selector,seg->base,limit);
}

void dump_kvm_dtable(struct kvm_dtable *seg, char *name) {
    printf("%s: %08llx(%08x)\n",
        name,seg->base,seg->limit);
}

void dump_kvm_sregs(int vcpufd) {
    struct kvm_sregs sregs;
    int ret = ioctl(vcpufd, KVM_GET_SREGS, &sregs);
    if (ret == -1)
        err(1, "KVM_GET_SREGS");
    printf("cr0=0x%08llx\n",
        sregs.cr0);
    dump_kvm_segment(&sregs.cs,"cs");
    dump_kvm_segment(&sregs.ds,"ds");
    dump_kvm_segment(&sregs.es,"es");
    dump_kvm_segment(&sregs.ss,"ss");
    dump_kvm_segment(&sregs.tr,"tr");
    dump_kvm_segment(&sregs.ldt,"ldt");
    dump_kvm_dtable(&sregs.gdt,"gdt");
    dump_kvm_dtable(&sregs.idt,"idt");
    printf("irq:");
    for (int i = 0; i < (KVM_NR_INTERRUPTS + 63) / 64; i++) {
        printf("%016llx",sregs.interrupt_bitmap[i]);
    }
    printf("\n");
}

void dump_kvm_exit(struct emu *emu) {
    printf("\n");
    dump_kvm_run(emu->run);
    dump_kvm_regs(emu);
    switch(emu->run->exit_reason) {
    case KVM_EXIT_SHUTDOWN:
    case KVM_EXIT_MMIO:
        dump_kvm_sregs(emu->vcpufd);
        break;
    }
}

void setup_gdt(struct kvm_sregs *sregs, struct emu *emu) {
    emu->gdt = mmap(NULL, GDT_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (!emu->gdt)
        err(1, "allocating gdt memory");

    memset(emu->gdt,0,GDT_SIZE);

    /* code segment */
    emu->gdt[1].limit_l     = 0xffff;
    emu->gdt[1].type_flags  = 0x9e;
    emu->gdt[1].limit_flags = 0xcf;

    /* data segment */
    emu->gdt[2].limit_l    = 0xffff;
    emu->gdt[2].type_flags = 0x92;
    emu->gdt[2].limit_flags = 0xcf;

    struct kvm_userspace_memory_region region = {
        .slot = MEM_REGION_GDT,
        .guest_phys_addr = GDT_BASE,
        .memory_size = GDT_SIZE,
        .userspace_addr = (uint64_t)emu->gdt,
    };
    int ret = ioctl(emu->vmfd, KVM_SET_USER_MEMORY_REGION, &region);
    if (ret == -1)
        err(1, "KVM_SET_USER_MEMORY_REGION");

    sregs->gdt.base = GDT_BASE;
    sregs->gdt.limit = GDT_SIZE;
}

void setup_idt(struct kvm_sregs *sregs,struct emu *emu) {
    emu->idt = mmap(NULL, IDT_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (!emu->idt)
        err(1, "allocating idt memory");

    for (int i=0; i<256; i++) {
        emu->idt->entry[i].offset_l = sizeof(emu->idt->entry) + i*sizeof(emu->idt->hlt[i]);
        emu->idt->entry[i].selector = SEL_TEXT;
        emu->idt->entry[i].always0 = 0;
        emu->idt->entry[i].type_flags = 0xee; /* dpl=3, present, 32-bit interrupt */
        emu->idt->entry[i].offset_h = IDT_BASE>>16;
        emu->idt->hlt[i][0] = 0xe7; /* out imm8,ax */
        emu->idt->hlt[i][1] = 0x7f; /* imm8 = 0x7f */
        emu->idt->hlt[i][2] = 0xcf; /* iret */
        emu->idt->hlt[i][3] = i;
    }

    struct kvm_userspace_memory_region region = {
        .slot = MEM_REGION_IDT,
        .guest_phys_addr = IDT_BASE,
        .memory_size = IDT_SIZE,
        .userspace_addr = (uint64_t)emu->idt,
    };
    int ret = ioctl(emu->vmfd, KVM_SET_USER_MEMORY_REGION, &region);
    if (ret == -1)
        err(1, "KVM_SET_USER_MEMORY_REGION");
    sregs->idt.base = IDT_BASE;
    sregs->idt.limit = sizeof(emu->idt->entry);
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

    emu->stack_size = STACK_SIZE;
    emu->stack = mmap(NULL, emu->stack_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (!emu->stack)
        err(1, "allocating guest stack");
    struct kvm_userspace_memory_region region2 = {
        .slot = MEM_REGION_STACK,
        .guest_phys_addr = STACK_BASE,
        .memory_size = emu->stack_size,
        .userspace_addr = (uint64_t)emu->stack,
    };
    ret = ioctl(emu->vmfd, KVM_SET_USER_MEMORY_REGION, &region2);
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

    if (*filename == '-') {
        emu->text_size = 0x2000;
        /* Allocate one aligned page of guest memory to hold the code. */
        emu->text = mmap(NULL, emu->text_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (!emu->text)
            err(1, "allocating guest memory");
        memcpy(emu->text+0x1000, code, sizeof(code));
    } else {
        int fd = open(filename, O_RDONLY);
        if (fd == -1)
            err(1, "opening file");
        struct stat s;
        ret = fstat(fd,&s);
        if (ret == -1) 
            err(1, "statting file");
        emu->text_size = ((s.st_size >>12) +1 )<<12;

        emu->text = mmap(NULL, emu->text_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (!emu->text)
            err(1, "allocating guest memory");
        uint8_t *p = emu->text;
        while(s.st_size) {
            ret = read(fd,p,4096);
            if (ret == -1)
                err(1, "reading file");
            s.st_size -= ret;
            p += ret;
        }
    }

    struct kvm_userspace_memory_region region1 = {
        .slot = MEM_REGION_TEXT,
        .guest_phys_addr = 0x0,
        .memory_size = emu->text_size,
        .userspace_addr = (uint64_t)emu->text,
    };
    ret = ioctl(emu->vmfd, KVM_SET_USER_MEMORY_REGION, &region1);
    if (ret == -1)
        err(1, "KVM_SET_USER_MEMORY_REGION");

    emu->bss_base = emu->text_size + 0x1000;
    emu->bss_brk = STACK_SIZE; /* start a little from the bottom - silly things put stacks here */
    emu->bss_size = BSS_SIZE;
    emu->bss = mmap(NULL, emu->bss_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (!emu->bss)
        err(1, "allocating bss");
    struct kvm_userspace_memory_region region2 = {
        .slot = MEM_REGION_BSS,
        .guest_phys_addr = emu->bss_base,
        .memory_size = emu->bss_size,
        .userspace_addr = (uint64_t)emu->bss,
    };
    ret = ioctl(emu->vmfd, KVM_SET_USER_MEMORY_REGION, &region2);
    if (ret == -1)
        err(1, "KVM_SET_USER_MEMORY_REGION");

    /* Initialize registers: instruction pointer for our code, addends, and
     * initial flags required by x86 architecture. */
    struct kvm_regs regs = {
        .rip = entry,
        .rax = 2,
        .rbx = 2,
        .rflags = 0x2,
        .rsp = STACK_BASE + emu->stack_size - 0x10,
    };
    ret = ioctl(emu->vcpufd, KVM_SET_REGS, &regs);
    if (ret == -1)
        err(1, "KVM_SET_REGS");

    return 0;
}

int alloc_bss(struct emu *emu, unsigned int size) {
    if (emu->bss_brk + size > emu->bss_size) {
        return 0;
    }
    unsigned int addr = emu->bss_base + emu->bss_brk;
    emu->bss_brk += size;
    return addr;
}

void iret_setflags(struct kvm_regs *regs, unsigned int setflags) {
    __u32 *flags = (__u32 *)(emu_global.stack + regs->rsp - STACK_BASE + 8);
    *flags |= setflags;
}

void irq_dos_exit(int vcpufd, struct kvm_regs *regs) {
    printf(" return=0x%02llx\n",regs->rax & 0xff);
    exit(0);
}

void irq_dpmi_0006(int vcpufd, struct kvm_regs *regs) {
    regs->rcx = regs->rdx = 0;

    int ret = ioctl(vcpufd, KVM_SET_REGS, regs);
    if (ret == -1)
        err(1, "KVM_SET_REGS");
}

void irq_dpmi_000a(int vcpufd, struct kvm_regs *regs) {
    /* Just fake it! */
    /* regs->rax = regs->rbx; */
    regs->rax = SEL_FAKE;

    int ret = ioctl(vcpufd, KVM_SET_REGS, regs);
    if (ret == -1)
        err(1, "KVM_SET_REGS");
}

void irq_dpmi_0501(int vcpufd, struct kvm_regs *regs) {
    unsigned int size = (regs->rbx & 0xffff) <<16 | (regs->rcx & 0xffff);
    unsigned int addr = alloc_bss(&emu_global, size);

    printf("alloc(%i) = 0x%08x",size,addr);

    if (!addr) {
        iret_setflags(regs,1); /* set CF */
        return;
    }

    regs->rbx = regs->rsi = addr >> 16;
    regs->rcx = regs->rdi = addr & 0xffff;

    int ret = ioctl(vcpufd, KVM_SET_REGS, regs);
    if (ret == -1)
        err(1, "KVM_SET_REGS");
}

void irq_gpf(void *data, int vcpufd, struct kvm_regs *regs) {
    __u32 retaddr;
    __u32 stack_addr = regs->rsp - STACK_BASE;
    if (stack_addr < STACK_SIZE) {
        retaddr = *(__u32 *)(emu_global.stack + stack_addr + 4);
    }
    printf("- retaddr=0x%08x\n",retaddr);

    dump_kvm_sregs(vcpufd);
    err(1, "GPF");
}

void handle_subcode(struct irq_subhandler_entry *p, int subcode, int vcpufd, struct kvm_regs *regs) {
    while (p && p->name) {
        if (p->subcode == subcode) {
            printf(" (%s):",p->name);
            p->handler(vcpufd, regs);
            printf("\n");
            return;
        }
        p++;
    }
    printf("\n");
    err(1, "undefined subcode");
}

void irq_subcode_ah(void *data, int vcpufd, struct kvm_regs *regs) {
    struct irq_subhandler_entry *table = data;
    int subcode = (regs->rax & 0xff00) >>8;
    printf("%02X",subcode);
    handle_subcode(table,subcode,vcpufd,regs);
}

void irq_subcode_ax(void *data, int vcpufd, struct kvm_regs *regs) {
    struct irq_subhandler_entry *table = data;
    int subcode = regs->rax & 0xffff;
    printf("%04X",subcode);
    handle_subcode(table,subcode,vcpufd,regs);
}

void irq_unhandled(int vcpufd, struct kvm_regs *regs) {
    err(1, "unhandled irq");
}

void irq_ignore(int vcpufd, struct kvm_regs *regs) {
    return;
}

struct irq_subhandler_entry irq_dpmi_subcode[] = {
    { .subcode = 0x0006, .name = "GET SEGMENT BASE ADDRESS", .handler = irq_dpmi_0006 },
    { .subcode = 0x0007, .name = "SET SEGMENT BASE ADDRESS", .handler = irq_ignore },
    { .subcode = 0x0008, .name = "SET SEGMENT LIMIT", .handler = irq_ignore },
    { .subcode = 0x0009, .name = "SET DESCRIPTOR ACCESS RIGHTS", .handler = irq_ignore },
    { .subcode = 0x000a, .name = "CREATE ALIAS DESCRIPTOR", .handler = irq_dpmi_000a },
    { .subcode = 0x0501, .name = "ALLOCATE MEMORY BLOCK", .handler = irq_dpmi_0501 },
    { .subcode = 0x0507, .name = "SET PAGE ATTRIBUTES", .handler = irq_ignore },
    { 0 },
};

struct irq_subhandler_entry irq_dos_subcode[] = {
    { .subcode = 0x4c, .name = "EXIT", .handler = irq_dos_exit },
    { 0 },
};

/*
 * Top level table of every IRQ possible
 */
struct irq_handler_entry handlers[256] = {
    [0x0d] = { .name = "GPF",  .handler = irq_gpf },
    [0x21] = { .name = "DOS",  .handler = irq_subcode_ah, .data = irq_dos_subcode },
    [0x31] = { .name = "DPMI", .handler = irq_subcode_ax, .data = irq_dpmi_subcode },
};

int handle_softirq(struct emu *emu) {
    struct kvm_regs regs;
    int ret = ioctl(emu->vcpufd, KVM_GET_REGS, &regs);
    if (ret == -1)
        err(1, "KVM_GET_REGS");

    if (regs.rip < IDT_BASE || regs.rip > IDT_BASE + IDT_SIZE) {
        err(1, "softirq from outside idt region");
    }

    int irqno = (regs.rip - IDT_BASE - 0x800) >> 2;
    printf("INT ");

    if (handlers[irqno].name) {
        printf("'%s' -%02X",handlers[irqno].name,irqno);
        handlers[irqno].handler(handlers[irqno].data,emu->vcpufd,&regs);
    } else {
        __u32 retaddr = *(__u32 *)(emu->stack + regs.rsp - STACK_BASE + 4);
        printf("-%02X retaddr=0x%08x\n",irqno,retaddr);
        err(1, "undefined irq");
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
