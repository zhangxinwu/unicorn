#include "unicorn/unicorn.h"
#include <stdio.h>
#include <string.h>
#include <cmath>
#include <pthread.h>
#include <errno.h>
#include <stdint.h>
#include <sstream>
#include <fstream>
#include <utility>
#include <set>

using namespace std;

#define STACKSIZE 0x20000

typedef struct {
    uint64_t l;
    uint64_t h;
}uint128_t;

set<pair<uint64_t, uint64_t> > ignoreMemRange;

void hook_block(uc_engine *uc, uint32_t address, uint32_t size, void *user_data)
{
    
}

void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    printf("%llx", address);
    for (int i = 0 ; i < size; i++)
    {
        printf(" %02x", ((uint8_t *)address)[i]);
    }
    printf("\n");
}

void hook_mem(uc_engine *uc, uc_mem_type type,
        uint64_t address, int size, int64_t value, void *user_data)
{
}

void hook_intr(uc_engine *uc, uint32_t intno, void *user_data);


extern "C" void* getAllRegister(uc_engine *uc)
{
    uc_err err;
    int size = UC_ARM_REG_ENDING*sizeof(uint128_t);
    uint128_t* regs = (uint128_t*)malloc(size);
    memset(regs, 0, size);
    for(int ri = UC_ARM_REG_INVALID+1; ri < UC_ARM_REG_ENDING; ri++)
    {
        err = uc_reg_read(uc, ri, regs+ri);
        //if (err != UC_ERR_OK) { printf("regs[ri] read error.", ri); exit(-1); }
    }
    return regs;
}


extern "C" void create_new_unicorn(uint32_t r0, void* user_data, uint128_t* regs)
{
    uc_engine *uc;
    uc_hook trace1, trace2;
    int err = uc_open(UC_ARCH_ARM, UC_MODE_ARM, &uc);

    for(int ri = UC_ARM_REG_INVALID+1; ri < UC_ARM_REG_ENDING; ri++)
    {
        err = uc_reg_write(uc, ri, regs+ri);
        // if (err != UC_ERR_OK) { printf("regs[ri] read error.", ri); exit(-1); }
    }
    
    uc_reg_write(uc, UC_ARM_REG_R0, &r0);
    
    // tracing all basic blocks with customized callback
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, (void *)hook_block, NULL, (uint64_t)0, (uint64_t)-1);
    
    // tracing one instruction at ADDRESS with customized callback
    // uc_hook_add(uc, &trace2, UC_HOOK_CODE, (void *)hook_code, NULL, 1, 0);

    uc_hook_add(uc, &trace2, UC_HOOK_INTR, (void *)hook_intr, NULL, 1, 0);
    
    uint64_t pc = regs[UC_ARM_REG_PC].l;
    // (CPUARMState*)(uc->cpu->env_ptr)->pc = pc;
    err = uc_emu_start(uc, pc, -1, 0, 0);
    if (err)
    {
        // printf("Failed on uc_emu_start() with error returned: %u\n", err);
    }
    free(regs);
    // free(stack);
    err = uc_errno(uc);
    // printf("uc_errno: %d err:\n", err);
    int64_t ret;
    uc_reg_read(uc, UC_ARM_REG_R0, &ret);
    uc_close(uc);
}

void hook_intr(uc_engine *uc, uint32_t intno, void *user_data) {
    // printf(">>> Tracing intr %x\n", intno);
    uint8_t inst[4];
    uint8_t* pc;
    uc_reg_read(uc, UC_ARM_REG_PC, &pc);
    uc_err err;
	// Just grab a bunch of registers here so we don't have to make a bunch of calls
	// Being lazy =)
    uint64_t lr = -1;
    uc_reg_read(uc, UC_ARM_REG_LR, &lr);

    uint32_t regs[8];
    memset(regs, 0, sizeof(regs));
    for (int regid = UC_ARM_REG_R0; regid <= UC_ARM_REG_R7; regid++)
        err = uc_reg_read(uc, regid, &regs[regid-UC_ARM_REG_R0]); if (err != UC_ERR_OK) { return; }
    uint128_t* allRegs = NULL;
    // new thread -> clone
    if (regs[7] == 0x78)
    {
        allRegs = (uint128_t*)getAllRegister(uc);
        allRegs[UC_ARM_REG_SP].l = regs[1];
        void* threadStack = malloc(STACKSIZE);
        regs[1] =  (uint64_t)threadStack + STACKSIZE-0x100;
        memcpy((void*)((uint64_t)threadStack + STACKSIZE - 0x100), (void*)allRegs[UC_ARM_REG_SP].l, 0x100);
    }
    
    uint32_t oregs[8];
    asm volatile (
        "str r0, [%0, #0x00]""\n\t"
        "str r1, [%0, #0x04]""\n\t"
        "str r2, [%0, #0x08]""\n\t"
        "str r3, [%0, #0x0c]""\n\t"
        "str r4, [%0, #0x10]""\n\t"
        "str r5, [%0, #0x14]""\n\t"
        "str r6, [%0, #0x18]""\n\t"
        "str r7, [%0, #0x1c]""\n\t"
        "ldr r0, [%1, #0x00]""\n\t"
        "ldr r1, [%1, #0x04]""\n\t"
        "ldr r2, [%1, #0x08]""\n\t"
        "ldr r3, [%1, #0x0c]""\n\t"
        "ldr r4, [%1, #0x10]""\n\t"
        "ldr r5, [%1, #0x14]""\n\t"
        "ldr r6, [%1, #0x18]""\n\t"
        "ldr r7, [%1, #0x1c]""\n\t"
        "svc #0""\n\t"
        "str r0, [%1, #0x00]""\n\t"
        "cmp r0, #0x0""\n\t"
        "bne not_should_jmp""\n\t"
        "cmp r7, #0x78""\n\t" 
        "bne not_should_jmp""\n\t"
        "mov r2, %3""\n\t"
        "mov r1, %2""\n\t"
        "mov r0, #0""\n\t"
        "b create_new_unicorn""\n\t"
        "not_should_jmp:""\n\t"
        "ldr r0, [%0, #0x00]""\n\t"
        "ldr r1, [%0, #0x04]""\n\t"
        "ldr r2, [%0, #0x08]""\n\t"
        "ldr r3, [%0, #0x0c]""\n\t"
        "ldr r4, [%0, #0x10]""\n\t"
        "ldr r5, [%0, #0x14]""\n\t"
        "ldr r6, [%0, #0x18]""\n\t"
        "ldr r7, [%0, #0x1c]""\n\t"
        ::"r"(oregs),"r"(regs), "r"(user_data), "r"(allRegs):"r0","r1","r2","r3","r4","r5","r6","r7");
	err = uc_reg_write(uc, UC_ARM_REG_R0, &regs[0]); if (err != UC_ERR_OK) { return; }
}

int arr[2] = {0, 0};
int add(int a, int b)
{
    for (int i = 0; i < a; i++)
        b += 1;
    return b;
}

int sum(int a, int b, int c)
{
    arr[0] = add(c, add(a, b));
    arr[1] = strlen("a324nmcdsmdkcdscmdskmd");
    return arr[0];
}

int openfile()
{
    FILE *fp = NULL;
    fp = fopen("test.txt", "w+");
    fprintf(fp, "ok!!!");
    fputs("hello world!\n", fp);
    fclose(fp);
    return 0;
}

void print_message_function( void *ptr ) {
    printf("pthread newthread start2\n");
    int i = 0;
    for (i; i<5; i++) {
        printf("%s:%d\n", (char *)ptr, i);
    }
}

int newthread()
{
    pthread_t thread;
    char* threadstr = "thead1";
    printf("pthread newthread start0\n");
    printf("pthread newthread start1\n");
    int err = pthread_create(&thread, NULL, (void *(*)(void *))print_message_function, threadstr);
    if(err != 0)
    {
        printf("create thread error %d\n", err);
        return -1;
    }
    void* ret;
    err = pthread_join(thread, &ret);
    if(err != 0)
    {
        printf("join thread error %d\n", err);
        return -1;
    }
    printf("thread ok!\n");
    return 0;
}

void test_arm(void)
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace1, trace2, trace3, trace4;

    int64_t r0 = 0x1234; // R0 register
    int64_t r1 = 0x2222; // R1 register
    int64_t r2 = 0x1111; // R1 register
    int64_t r3 = 0x3333; // R2 register
    int8_t *stack = (int8_t*)malloc(STACKSIZE);
    printf("Emulate ARM code\n");

    // Initialize emulator in ARM mode
    err = uc_open(UC_ARCH_ARM, UC_MODE_ARM, &uc);
    if (err)
    {
        printf("Failed on uc_open() with error returned: %u (%s)\n",
               err, uc_strerror(err));
        return;
    }
    uc_reg_write(uc, UC_ARM_REG_R0, &r0);
    uc_reg_write(uc, UC_ARM_REG_R1, &r1);
    uc_reg_write(uc, UC_ARM_REG_R2, &r2);
    uc_reg_write(uc, UC_ARM_REG_R3, &r3);
    
    void *st = ((uint64_t *)&stack[STACKSIZE]);
    printf("stack: %p\n", st);
    uc_reg_write(uc, UC_ARM_REG_SP, &st);

    int64_t lr = -1;
    uc_reg_write(uc, UC_ARM_REG_LR, &lr);

    // tracing all basic blocks with customized callback
    // uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, (void *)hook_block, NULL, (uint64_t)-1, (uint64_t)sum + 0xfff);

    // tracing one instruction at ADDRESS with customized callback
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, (void *)hook_code, NULL, -1, 0);


    // StackInfo stackInfo{.stackSt = stack, .size = STACKSIZE};
    // tracing one intr with customized callback
    uc_hook_add(uc, &trace3, UC_HOOK_INTR, (void *)hook_intr, NULL, -1, 0);

    // uc_hook_add(uc, &trace4, UC_HOOK_MEM_FETCH, (void*)hook_mem, NULL, -1, 0);

    // emulate machine code in infinite time (last param = 0), or when
    // finishing all the code.
    err = uc_emu_start(uc, (uint64_t)openfile, -1, 0, 0);
    if (err)
    {
        printf("Failed on uc_emu_start() with error returned: %u\n", err);
    }
    free(stack);
    err = uc_errno(uc);
    printf("uc_errno: %d err: %s\n",err, uc_strerror(err));;

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    int64_t sp, r8, r9;
    uc_reg_read(uc, UC_ARM_REG_R0, &r0);
    uc_reg_read(uc, UC_ARM_REG_R1, &r1);
    uc_reg_read(uc, UC_ARM_REG_R8, &r8);
    uc_reg_read(uc, UC_ARM_REG_R9, &r9);
    uc_reg_read(uc, UC_ARM_REG_SP, &sp);
    printf(">>> R0 = %p\n", r0);
    printf(">>> R1 = %p\n", r1);
    printf(">>> R8 = %p\n", r8);
    printf(">>> R9 = %p\n", r9);
    printf(">>> sp = %p\n", sp);
    printf(">>> stack = %p\n", st);
    for (int i = 0; i < 16; i++)
        printf("%d:%p, ", i, stack[i]);
    printf("\n");

    uc_close(uc);
}

int main(){
    test_arm();
    // openfile();
    printf("arr %x %x\n", arr[0], arr[1]);
    return 0;
}