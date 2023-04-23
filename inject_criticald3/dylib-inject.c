//
//  dylib-inject.c
//  dylib-inject
//
//  Created by CoolStar on 2/5/20.
//  Copyright © 2020 coolstar. All rights reserved.
//

#include "dylib-inject.h"
#include <stdlib.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include <pthread/pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#ifdef __arm64e
#include <ptrauth.h>
#endif

#ifdef INJECT_CRITICALD_DEBUG
#define CHK_KR(kr, msg) \
if (kr != KERN_SUCCESS){ \
printf(msg " failed: %d\n", kr); \
return kr; \
}
#else
#define CHK_KR(kr, msg) \
if (kr != KERN_SUCCESS)\
return kr;
#endif
#define STACK_SIZE (mach_vm_size_t) 0x4000

uint64_t minipow(uint64_t num, uint64_t base) {
    loop:
        if (base == 1) return num;
        else if (base == 0) return 1;

        num *= num;
        base -= 1;
        goto loop;
}

void movk_ptr(uint32_t *insns, char reg, void *ptr) {
    uint32_t base = 0xf2800000 | reg;
    uint64_t addr = (uint64_t) ptr;

    for (short i = 0; i < 4; i++) {
        insns[i] = base;
        short seg = (addr / minipow(65536, i)) % 65536;
        insns[i] |= (uint32_t) (seg << 5);
        insns[i] |= (uint32_t) (i << 21);
    }
}

kern_return_t mach_vm_allocate(vm_map_t target, mach_vm_address_t *address, mach_vm_size_t size, int flags);
kern_return_t mach_vm_protect(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection);
kern_return_t mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);
kern_return_t mach_vm_write(vm_map_t target_task, mach_vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt);
kern_return_t mach_vm_deallocate(mach_port_name_t target, mach_vm_address_t address, mach_vm_size_t size);

mach_vm_address_t copy_shc_into_mem(mach_port_t target, uint32_t *shc, uint32_t count) {
    mach_vm_address_t region;
    kern_return_t kr = KERN_SUCCESS;

    kr = mach_vm_allocate(target, &region, sizeof(uint32_t) * count, VM_FLAGS_ANYWHERE);
    CHK_KR(kr, "shc_mach_vm_allocate");
    kr = mach_vm_protect(target, region, sizeof(uint32_t) * count, 0, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    CHK_KR(kr, "shc_mach_vm_protect");

    kr = mach_vm_write(target, region, (mach_vm_address_t) shc, sizeof(uint32_t) * count);
    CHK_KR(kr, "shc_mach_vm_write");

    kr = mach_vm_protect(target, region, sizeof(uint32_t) * count, 0, VM_PROT_READ | VM_PROT_EXECUTE);
    CHK_KR(kr, "shc_mach_vm_protect2");

    return region;
}

kern_return_t inject_dylib(mach_port_t target, char *dylib){
    kern_return_t kr = KERN_SUCCESS;
    kr = mach_port_insert_right(mach_task_self(), target, target, MACH_MSG_TYPE_COPY_SEND);
    CHK_KR(kr, "mach_port_insert_right");
    
    mach_vm_address_t remoteStack;
    kr = mach_vm_allocate(target, &remoteStack, STACK_SIZE, VM_FLAGS_ANYWHERE);
    CHK_KR(kr, "mach_vm_allocate");
    kr = mach_vm_protect(target, remoteStack, STACK_SIZE, 1, VM_PROT_READ | VM_PROT_WRITE);
    CHK_KR(kr, "mach_vm_protect");
    
    mach_vm_address_t remoteStr;
    kr = mach_vm_allocate(target, &remoteStr, 0x100 + strlen(dylib) + 1, VM_FLAGS_ANYWHERE);
    CHK_KR(kr, "mach_vm_allocate2");
    kr = mach_vm_protect(target, remoteStr, 0x100 + strlen(dylib) + 1, 0, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    CHK_KR(kr, "mach_vm_protect2");
    kr = mach_vm_write(target, remoteStr + 0x100, (vm_offset_t)dylib, (mach_msg_type_number_t)strlen(dylib) + 1);
    CHK_KR(kr, "mach_vm_write2");
    
    uint64_t *localStack = malloc(STACK_SIZE);
    size_t stackPointer = (STACK_SIZE / 8) - 1;
    stackPointer--;

    kr = mach_vm_write(target, remoteStack, (vm_offset_t)localStack, (mach_msg_type_number_t)STACK_SIZE);
    CHK_KR(kr, "mach_vm_write3");

    void *libsystem = dlopen("/usr/lib/libSystem.B.dylib", RTLD_NOW);
    void *libdyld = dlopen("/usr/lib/system/libdyld.dylib", RTLD_NOW);
    void *pt_create = dlsym(libsystem, "pthread_create_from_mach_thread");
    void *dlopen_ptr = dlsym(libdyld, "dlopen");
    #ifdef __arm64e__
    ptrauth_strip(pt_create, ptrauth_key_function_pointer);
    ptrauth_strip(dlopen_ptr, ptrauth_key_function_pointer);
    #endif

    uint32_t dylib_movk[4];
    void *rStrAddr = (void *) remoteStr + 0x100;
    movk_ptr(dylib_movk, 0, rStrAddr);
    uint32_t dlopen_movk[4];
    movk_ptr(dlopen_movk, 10, dlopen_ptr);
    uint32_t create_movk[4];
    movk_ptr(create_movk, 10, pt_create);

    // store fp and lr onto the stack, dlopen the dylib, restore fp and lr from the stack
    // this is effectively this in C:
    // return dlopen(dylib, RTLD_NOW);
    uint32_t thread_target[14] = {
        0xa93f7bfd, // stp x29, x30, [sp, -0x10]
        0xd10043fd, // sub x29, sp, 0x10
        dylib_movk[0], // movk x0, {ptr 48-64 bits}
        dylib_movk[1], // movk x0, {ptr 32-48 bits}, lsl 16
        dylib_movk[2], // movk x0, {ptr 16-32 bits}, lsl 32
        dylib_movk[3], // movk x0, {ptr first 16 bits}, lsl 48
        0xd2800001 | RTLD_NOW, // mov x1, RTLD_NOW
        dlopen_movk[0], // movk x10, {ptr 48-64 bits}
        dlopen_movk[1], // movk x10, {ptr 32-48 bits}, lsl 16
        dlopen_movk[2], // movk x10, {ptr 16-32 bits}, lsl 32
        dlopen_movk[3], // movk x10, {ptr first 16 bits}, lsl 48
        0xd63f0140, // blr x10
        0xa97f7bfd, // ldp x29, x30, [sp, -0x10]
        0xd65f03c0  // ret
    };

    mach_vm_address_t target_addr = copy_shc_into_mem(target, thread_target, 14);

    // create the pthread to go to thread_target
    // x0 will be the thread, attrs & args (x1, x3) will be 0, x2 will be thread_target
    // this is effectively this in C:
    // pthread_create_from_mach_thread(sp - 8, 0, &thread_target, 0);
    uint32_t thread_start[11] = {
        0xd10023e0, // sub x0, sp, 8
        0xd100201f, // sub sp, x0, 8
        0xd2800001, // mov x1, 0
        #ifdef __arm64e__
        0xdac123e2, // paciza x2
        #endif
        0xd2800003, // mov x3, 0
        create_movk[0], // movk x10, {ptr 48-64 bits}
        create_movk[1], // movk x10, {ptr 32-48 bits}, lsl 16
        create_movk[2], // movk x10, {ptr 16-32 bits}, lsl 32
        create_movk[3], // movk x10, {ptr first 16 bits}, lsl 48
        0xd63f0140, // blr x10
        0x14000000  // b .
    };

    mach_vm_address_t start_addr = copy_shc_into_mem(target, thread_start, sizeof(thread_start) / sizeof(uint32_t));
    #ifdef __arm64e__
    start_addr = (mach_vm_address_t) ptrauth_sign_unauthenticated(ptrauth_strip((void *)start_addr, ptrauth_key_function_pointer), ptrauth_key_function_pointer, 0);
    #endif


    arm_thread_state64_t state = {};
    bzero(&state, sizeof(arm_thread_state64_t));

    state.__x[2] = target_addr;
    __darwin_arm_thread_state64_set_pc_fptr(state, (void *) start_addr);
    __darwin_arm_thread_state64_set_sp(state, (void *)(remoteStack + stackPointer*sizeof(uint64_t)));
    
    mach_port_t remoteThread;

    kr = thread_create_running(target, ARM_THREAD_STATE64, (thread_state_t) &state, ARM_THREAD_STATE64_COUNT, &remoteThread);
    CHK_KR(kr, "thread_create_running");

    if (remoteThread == 0) {
        fprintf(stderr, "Remote thread is NULL!\n");
        return 1;
    }
    
    kr = thread_resume(remoteThread);
    CHK_KR(kr, "thread_resume");

    usleep(500 * 1000);


    kr = thread_suspend(remoteThread);
    CHK_KR(kr, "thread_suspend");

    kr = thread_terminate(remoteThread);
    CHK_KR(kr, "thread_terminate");
    
    kr = mach_vm_deallocate(target, remoteStr, STACK_SIZE);
    CHK_KR(kr, "mach_vm_deallocate");

    /*
    kr = mach_vm_deallocate(target, remoteThread, STACK_SIZE);
    CHK_KR(kr, "mach_vm_deallocate2");
    */
    
    kr = mach_port_deallocate(mach_task_self(), target);
    CHK_KR(kr, "mach_port_deallocate");
    
    free(localStack);
    return kr;
}
