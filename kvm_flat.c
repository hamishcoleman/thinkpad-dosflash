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

const char * kvm_exit_str[] = {
    "KVM_EXIT_UNKNOWN", "KVM_EXIT_EXCEPTION", "KVM_EXIT_IO",
    "KVM_EXIT_HYPERCALL", "KVM_EXIT_DEBUG", "KVM_EXIT_HLT",
    "KVM_EXIT_MMIO", "KVM_EXIT_IRQ_WINDOW_OPEN", "KVM_EXIT_SHUTDOWN",
    "KVM_EXIT_FAIL_ENTRY", "KVM_EXIT_INTR", "KVM_EXIT_SET_TPR",
    "KVM_EXIT_TPR_ACCESS", "KVM_EXIT_S390_SIEIC", "KVM_EXIT_S390_RESET",
    "KVM_EXIT_DCR", "KVM_EXIT_NMI", "KVM_EXIT_INTERNAL_ERROR",
    "KVM_EXIT_OSI", "KVM_EXIT_PAPR_HCALL",
};

void dump_kvm_run(struct kvm_run *run) {
    printf("%s(%i)\n",kvm_exit_str[run->exit_reason],run->exit_reason);
    switch (run->exit_reason) {
    case KVM_EXIT_INTERNAL_ERROR:
        printf("\tsuberror: 0x%x\n",run->internal.suberror);
        break;
    }
}

void dump_kvm_regs(int vcpufd) {
    struct kvm_regs regs;
    int ret = ioctl(vcpufd, KVM_GET_REGS, &regs);
    if (ret == -1)
        err(1, "KVM_GET_REGS");
    printf("ax=0x%08x bx=0x%08x cx=0x%08x dx=0x%08x flags=0x%08x\n",
        regs.rax,regs.rbx,regs.rcx,regs.rdx,regs.rflags);
#if 0
    printf("8=0x%08x 9=0x%08x 10=0x%08x 11=0x%08x 12=0x%08x\n",
        regs.r8,regs.r9,regs.r10,regs.r11,regs.r12);
#endif
    printf("si=0x%08x di=0x%08x sp=0x%08x bp=0x%08x ip=0x%08x\n",
        regs.rsi,regs.rdi,regs.rsp,regs.rbp,regs.rip);

}

void setup_flat_segments(struct kvm_sregs *sregs) {
    sregs->cs.base = 0;
    sregs->cs.limit = 0xfffff;
    sregs->cs.selector = 0;
    sregs->cs.db = 1;
    sregs->cs.g = 1;
    memcpy(&sregs->ds,&sregs->cs,sizeof(sregs->cs));
    memcpy(&sregs->es,&sregs->cs,sizeof(sregs->cs));
    memcpy(&sregs->fs,&sregs->cs,sizeof(sregs->cs));
    memcpy(&sregs->gs,&sregs->cs,sizeof(sregs->cs));
    memcpy(&sregs->ss,&sregs->cs,sizeof(sregs->cs));
    sregs->ss.type = 6; /* x=0,e=1,w=1,a=0 */
    /* FIXME
     * - descriptor table too
     */
}

struct kvm_run *kvm_init(int *kvmp, int *vmfdp, int *vcpufdp) {
    struct kvm_run *run;
    struct kvm_sregs sregs;

    *kvmp = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (*kvmp == -1)
        err(1, "/dev/kvm");

    /* Make sure we have the stable version of the API */
    int ret = ioctl(*kvmp, KVM_GET_API_VERSION, NULL);
    if (ret == -1)
        err(1, "KVM_GET_API_VERSION");
    if (ret != 12)
        errx(1, "KVM_GET_API_VERSION %d, expected 12", ret);

    *vmfdp = ioctl(*kvmp, KVM_CREATE_VM, (unsigned long)0);
    if (*vmfdp == -1)
        err(1, "KVM_CREATE_VM");

    *vcpufdp = ioctl(*vmfdp, KVM_CREATE_VCPU, (unsigned long)0);
    if (*vcpufdp == -1)
        err(1, "KVM_CREATE_VCPU");

    /* Map the shared kvm_run structure and following data. */
    ret = ioctl(*kvmp, KVM_GET_VCPU_MMAP_SIZE, NULL);
    if (ret == -1)
        err(1, "KVM_GET_VCPU_MMAP_SIZE");
    size_t mmap_size = ret;
    if (mmap_size < sizeof(*run))
        errx(1, "KVM_GET_VCPU_MMAP_SIZE unexpectedly small");
    run = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, *vcpufdp, 0);
    if (!run)
        err(1, "mmap vcpu");

    /* Initialize CS to point at 0, via a read-modify-write of sregs. */
    ret = ioctl(*vcpufdp, KVM_GET_SREGS, &sregs);
    if (ret == -1)
        err(1, "KVM_GET_SREGS");
    sregs.cr0 = 0x1; /* protected mode enable */
    setup_flat_segments(&sregs);
    ret = ioctl(*vcpufdp, KVM_SET_SREGS, &sregs);
    if (ret == -1)
        err(1, "KVM_SET_SREGS");

    return run;
}

int load_image(int vmfd, int vcpufd, char *filename, unsigned long entry) {
    int ret;
    uint8_t *mem;
    int flat_size;

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
        flat_size = 0x1000;
        /* Allocate one aligned page of guest memory to hold the code. */
        mem = mmap(NULL, flat_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (!mem)
            err(1, "allocating guest memory");
        memcpy(mem, code, sizeof(code));
    } else {
        int fd = open(filename, O_RDONLY);
        if (fd == -1)
            err(1, "opening file");
        struct stat s;
        ret = fstat(fd,&s);
        if (ret == -1) 
            err(1, "statting file");
        flat_size = ((s.st_size >>12) +1 )<<12;

        mem = mmap(NULL, flat_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (!mem)
            err(1, "allocating guest memory");
        uint8_t *p = mem;
        while(s.st_size) {
            ret = read(fd,p,4096);
            if (ret == -1)
                err(1, "reading file");
            s.st_size -= ret;
            p += ret;
        }
    }

    struct kvm_userspace_memory_region region1 = {
        .slot = 0,
        .guest_phys_addr = 0x0,
        .memory_size = flat_size,
        .userspace_addr = (uint64_t)mem,
    };
    ret = ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &region1);
    if (ret == -1)
        err(1, "KVM_SET_USER_MEMORY_REGION");

    mem = mmap(NULL, 0x4000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (!mem)
        err(1, "allocating guest stack");
    struct kvm_userspace_memory_region region2 = {
        .slot = 1,
        .guest_phys_addr = 0xf0000000,
        .memory_size = 0x4000,
        .userspace_addr = (uint64_t)mem,
    };
    ret = ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &region2);
    if (ret == -1)
        err(1, "KVM_SET_USER_MEMORY_REGION");



    /* Initialize registers: instruction pointer for our code, addends, and
     * initial flags required by x86 architecture. */
    struct kvm_regs regs = {
        .rip = entry,
        .rax = 2,
        .rbx = 2,
        .rflags = 0x2,
        .rsp = 0xf0000000 + 0x4000 - 0x10,
    };
    ret = ioctl(vcpufd, KVM_SET_REGS, &regs);
    if (ret == -1)
        err(1, "KVM_SET_REGS");

    return 0;
}

int main(int argc, char **argv)
{
    int kvm, vmfd, vcpufd, ret;
    struct kvm_run *run;
    char *filename;
    unsigned long entry;

    if (argc<3) {
        printf("Need args: filename entry\n");
        return 1;
    }
    filename=argv[1];
    entry=strtoul(argv[2],NULL,0);

    run = kvm_init(&kvm,&vmfd,&vcpufd);
    if (run == NULL) {
        return 1;
    }

    if (load_image(vmfd,vcpufd,filename,entry) == -1) {
        return 1;
    }

    /* Repeatedly run code and handle VM exits. */
    while (1) {
        ret = ioctl(vcpufd, KVM_RUN, NULL);
        if (ret == -1)
            err(1, "KVM_RUN");
        dump_kvm_run(run);
        dump_kvm_regs(vcpufd);
        switch (run->exit_reason) {
        case KVM_EXIT_HLT:
            puts("KVM_EXIT_HLT");
            return 0;
        case KVM_EXIT_IO:
            if (run->io.direction == KVM_EXIT_IO_OUT && run->io.size == 1 && run->io.port == 0x3f8 && run->io.count == 1)
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
