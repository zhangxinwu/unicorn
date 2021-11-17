#include "unicorn/unicorn.h"
#include <stdio.h>
#include <string.h>
#include <cmath>
#include <pthread.h>
#include <errno.h>
#include <stdint.h>  

using namespace std;

#define ARM_CODE "\x00\x37\x00\xa0\xe3\x03\x10\x42\xe0" // mov r0, #0x37; sub r1, r2, r3

#define STACKSIZE 0x20000

typedef struct {
    uint64_t l;
    uint64_t h;
}uint128_t;

struct StackInfo
{
    void* stackSt;
    uint64_t size;
};


static void hook_block(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_intr(uc_engine *uc, uint32_t intno, void *user_data);

extern "C" void create_new_unicorn(uint64_t x0, StackInfo* stackInfo, uint128_t* regs)
{
    uc_engine *uc;
    uc_hook trace1, trace2;
    int err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc);

    for(int ri = UC_ARM64_REG_INVALID+1; ri < UC_ARM64_REG_ENDING; ri++)
    {
        err = uc_reg_write(uc, ri, regs+ri);
        if (err != UC_ERR_OK) { printf("regs[ri] read error.", ri); exit(-1); }
    }

    // uint8_t *stack = (uint8_t*)malloc(stackInfo->size);
    // memcpy(stack, stackInfo->stackSt, stackInfo->size);
    // uint8_t* osp = (uint8_t*)regs[UC_ARM64_REG_SP].l;
    // void* st = stack + (osp - (uint8_t*)stackInfo->stackSt);
    // uc_reg_write(uc, UC_ARM64_REG_SP, &st);
    // uint8_t* olr = (uint8_t*)regs[UC_ARM64_REG_LR].l;
    // void* lr = stack + (olr - (uint8_t*)stackInfo->stackSt);
    // uc_reg_write(uc, UC_ARM64_REG_LR, &lr);
    // uc_reg_write(uc, UC_ARM64_REG_FP, &stack);
    
    uint64_t tpidr_el0=0, cpacr_el1=0;
    asm("mrs  x18, tpidr_el0\n\tstr x18, %0"::"m"(tpidr_el0):);
    uc_reg_write(uc, UC_ARM64_REG_TPIDR_EL0, &tpidr_el0);
    uc_reg_read(uc, UC_ARM64_REG_CPACR_EL1, &cpacr_el1);
    uint64_t CPACR_FPEN_MASK = (0x3 << 20);
    uint64_t CPACR_FPEN_TRAP_NONE = (0x3 << 20);
    cpacr_el1 = (cpacr_el1 & ~CPACR_FPEN_MASK) | CPACR_FPEN_TRAP_NONE;
    uc_reg_write(uc, UC_ARM64_REG_CPACR_EL1, &cpacr_el1);

    uc_reg_write(uc, UC_ARM64_REG_X0, &x0);
    
    // tracing all basic blocks with customized callback
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, (void *)hook_block, NULL, (uint64_t)0, (uint64_t)-1);
    
    // tracing one instruction at ADDRESS with customized callback
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, (void *)hook_code, NULL, 1, 0);

    // StackInfo sStackInfo{.stackSt = stack, .size = STACKSIZE};
    // tracing one intr with customized callback
    // uc_hook_add(uc, &trace2, UC_HOOK_INTR, (void *)hook_intr, (void*)&sStackInfo, 1, 0);
    
    uint64_t pc = regs[UC_ARM64_REG_PC].l;
    // (CPUARMState*)(uc->cpu->env_ptr)->pc = pc;
    err = uc_emu_start(uc, pc, -1, 0, 0);
    if (err)
    {
        printf("Failed on uc_emu_start() with error returned: %u\n", err);
    }
    free(regs);
    // free(stack);
    err = uc_errno(uc);
    printf("uc_errno: %d err:\n", err);
    uc_close(uc);
    char* ret = "ok";
    pthread_exit((void*)ret);
}


/*arm
.text:00064590 0C D0 4D E2                 SUB             SP, SP, #0xC
.text:00064594 08 00 8D E5                 STR             R0, [SP,#0xC+var_4]
.text:00064598 04 10 8D E5                 STR             R1, [SP,#0xC+var_8]
.text:0006459C 00 20 8D E5                 STR             R2, [SP,#0xC+var_C]
.text:000645A0 11 01 01 E3                 MOVW            R0, #0x1111
.text:000645A4 0C D0 8D E2                 ADD             SP, SP, #0xC
.text:000645A8 1E FF 2F E1                 BX              LR
*/
/*arm64
FF 43 00 D1 SUB             SP, SP, #0x10
E0 0F 00 B9 STR             W0, [SP,#0x10+var_4]
E1 0B 00 B9 STR             W1, [SP,#0x10+var_8]
E8 0F 40 B9 LDR             W8, [SP,#0x10+var_4]
E9 0B 40 B9 LDR             W9, [SP,#0x10+var_8]
00 01 09 0B ADD             W0, W8, W9
FF 43 00 91 ADD             SP, SP, #0x10
C0 03 5F D6 RET
*/
// \xFF\x43\x00\xD1\xE0\x0F\x00\xB9\xE1\x0B\x00\xB9\xE8\x0F\x40\xB9\xE9\x0B\x40\xB9\x00\x01\x09\x0B\xFF\x43\x00\x91
#define ARM_SUM "\xFF\x43\x00\xD1\xE0\x0F\x00\xB9\xE1\x0B\x00\xB9\xE8\x0F\x40\xB9\xE9\x0B\x40\xB9\x00\x01\x09\x0B\xFF\x43\x00\x91\xC0\x03\x5F\xD6"
// #define ARM_SUM "\xFF\x43\x00\xD1\x08\x00\x8D\xE5\xE1\x0B\x00\xB9\xE8\x0F\x40\xB9"

static void hook_block(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    printf(">>> Tracing basic block at %p, block size = 0x%x\n", address, size);
}

static void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{

    printf(">>> Tracing instruction at %p, instruction size = 0x%x \n", address, size);
    for (int i = 0 ; i < 4; i++)
        printf("%02x ", ((uint8_t *)address)[i]);
    printf("\n");
}

extern "C" void* getAllRegister(uc_engine *uc)
{
    uc_err err;
    uint128_t* regs = (uint128_t*)malloc(UC_ARM64_REG_ENDING*sizeof(uint128_t));
    for(int ri = UC_ARM64_REG_INVALID+1; ri < UC_ARM64_REG_ENDING; ri++)
    {
        err = uc_reg_read(uc, ri, regs+ri);
        if (err != UC_ERR_OK) { printf("regs[ri] read error.", ri); exit(-1); }
    }
    return regs;
}

static void hook_intr(uc_engine *uc, uint32_t intno, void *user_data) {
    printf(">>> Tracing intr %x\n", intno);
    uint8_t inst[4];
    uint8_t* pc;
    uc_reg_read(uc, UC_ARM64_REG_PC, &pc);

    printf(">>> Tracing intr->pc %x %x %x %x\n", pc[0], pc[1], pc[2], pc[3]);
    
    uc_err err;
	// Just grab a bunch of registers here so we don't have to make a bunch of calls
	// Being lazy =)
    uint64_t lr = -1;
    uc_reg_read(uc, UC_ARM64_REG_LR, &lr);

    uint64_t regs[9];
    err = uc_reg_read(uc, UC_ARM64_REG_X0, &regs[0]); if (err != UC_ERR_OK) { return; }
	err = uc_reg_read(uc, UC_ARM64_REG_X1, &regs[1]); if (err != UC_ERR_OK) { return; }
	err = uc_reg_read(uc, UC_ARM64_REG_X2, &regs[2]); if (err != UC_ERR_OK) { return; }
	err = uc_reg_read(uc, UC_ARM64_REG_X3, &regs[3]); if (err != UC_ERR_OK) { return; }
	err = uc_reg_read(uc, UC_ARM64_REG_X4, &regs[4]); if (err != UC_ERR_OK) { return; }
	err = uc_reg_read(uc, UC_ARM64_REG_X5, &regs[5]); if (err != UC_ERR_OK) { return; }
	err = uc_reg_read(uc, UC_ARM64_REG_X6, &regs[6]); if (err != UC_ERR_OK) { return; }
	err = uc_reg_read(uc, UC_ARM64_REG_X7, &regs[7]); if (err != UC_ERR_OK) { return; }
	err = uc_reg_read(uc, UC_ARM64_REG_X8, &regs[8]); if (err != UC_ERR_OK) { return; }

    uint128_t* allRegs = NULL;
    // new thread -> clone
    if (regs[8] == 0xdc)
    {
        allRegs = (uint128_t*)getAllRegister(uc);
        allRegs[UC_ARM64_REG_SP].l = regs[1];
        void* threadStack = malloc(STACKSIZE);
        regs[1] = (uint64_t)threadStack;
    }

    void* n = (void*)&create_new_unicorn;
    uint64_t oregs[9];
    asm volatile (
        "str x0, [%0, #0x00]""\n\t"
        "str x1, [%0, #0x08]""\n\t"
        "str x2, [%0, #0x10]""\n\t"
        "str x3, [%0, #0x18]""\n\t"
        "str x4, [%0, #0x20]""\n\t"
        "str x5, [%0, #0x28]""\n\t"
        "str x6, [%0, #0x30]""\n\t"
        "str x7, [%0, #0x38]""\n\t"
        "str x8, [%0, #0x40]""\n\t"
        "ldr x0, [%1, #0x00]""\n\t"
        "ldr x1, [%1, #0x08]""\n\t"
        "ldr x2, [%1, #0x10]""\n\t"
        "ldr x3, [%1, #0x18]""\n\t"
        "ldr x4, [%1, #0x20]""\n\t"
        "ldr x5, [%1, #0x28]""\n\t"
        "ldr x6, [%1, #0x30]""\n\t"
        "ldr x7, [%1, #0x38]""\n\t"
        "ldr x8, [%1, #0x40]""\n\t"
        "svc #0""\n\t"
        "str x0, [%1, #0x00]""\n\t"
        "cbnz x0, not_should_jmp""\n\t"
        "cmp x8, #0xdc""\n\t" 
        "bne not_should_jmp""\n\t"
        "mov x2, %3""\n\t"
        "mov x1, %2""\n\t"
        "mov x0, #0""\n\t"
        "b create_new_unicorn""\n\t"
        "not_should_jmp:""\n\t"
        "ldr x0, [%0, #0x00]""\n\t"
        "ldr x1, [%0, #0x08]""\n\t"
        "ldr x2, [%0, #0x10]""\n\t"
        "ldr x3, [%0, #0x18]""\n\t"
        "ldr x4, [%0, #0x20]""\n\t"
        "ldr x5, [%0, #0x28]""\n\t"
        "ldr x6, [%0, #0x30]""\n\t"
        "ldr x7, [%0, #0x38]""\n\t"
        "ldr x8, [%0, #0x40]""\n\t"
        ::"r"(oregs),"r"(regs), "r"(user_data), "r"(allRegs):"x0","x1","x2","x3","x4","x5","x6","x7","x8");
	err = uc_reg_write(uc, UC_ARM64_REG_X0, &regs[0]); if (err != UC_ERR_OK) { return; }
    if(regs[8] == 0xdc)
    {
        // while(1) sleep(100);
    }
}
/*

        "mov x0, sp""\n\t"
        "sub x0, x0, #0x10""\n\t"
        "lsr x0, x0, #0x4""\n\t"
        "lsl x0, x0, #0x4""\n\t"
*/
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

/*
FF 83 00 D1 SUB             SP, SP, #0x20
FD 7B 01 A9 STP             X29, X30, [SP,#0x10+var_s0]
FD 43 00 91 ADD             X29, SP, #0x10
FF 07 00 F9 STR             XZR, [SP,#0x10+stream]
E0 FF FF F0+ADRL            X0, aTestTxt ; "test.txt"
00 A0 18 91
E1 FF FF F0+ADRL            X1, aW  ; "w+"
21 3C 19 91
2C 00 00 94 BL              .fopen
E0 07 00 F9 STR             X0, [SP,#0x10+stream]
E0 07 40 F9 LDR             X0, [SP,#0x10+stream] ; stream
E1 FF FF F0+ADRL            X1, aThisIsTestingF ; "This is testing for fprintf...\n"
21 20 18 91
2B 00 00 94 BL              .fprintf
E1 07 40 F9 LDR             X1, [SP,#0x10+stream] ; stream
E0 FF FF F0+ADRL            X0, aThisIsTestingF_0 ; "This is testing for fputs...\n"
00 C4 18 91
2B 00 00 94 BL              .fputs
E0 07 40 F9 LDR             X0, [SP,#0x10+stream] ; stream
2D 00 00 94 BL              .fclose
20 00 20 D4 BRK             #1
*/
#define OPENFILE "\xFF\x03\x01\xD1\xFD\x7B\x03\xA9\xFD\xC3\x00\x91\xBF\x83\x1F\xF8\xA0\x47\x00\xD1\xE0\x07\x00\xF9\x88\x0E\x80\x52\xA8\xF3\x1E\x38\xA9\x0C\x80\x52\xA9\x03\x1F\x38\x69\x0E\x80\x52\xA9\x13\x1F\x38\xA8\x23\x1F\x38\xC9\x05\x80\x52\xA9\x33\x1F\x38\xA8\x43\x1F\x38\x09\x0F\x80\x52\xA9\x53\x1F\x38\xA8\x63\x1F\x38\xBF\x73\x1F\x38\xA1\x53\x00\xD1\xE1\x0B\x00\xF9\xE8\x0E\x80\x52\xA8\xC3\x1E\x38\x68\x05\x80\x52\xA8\xD3\x1E\x38\xBF\xE3\x1E\x38\x2B\x00\x00\x94\xE1\x07\x40\xF9\xA0\x83\x1F\xF8\xA0\x83\x5F\xF8\x2B\x00\x00\x94\xE0\x0B\x40\xF9\xA1\x83\x5F\xF8\x2C\x00\x00\x94\xA0\x83\x5F\xF8\x2E\x00\x00\x94\x20\x00\x20\xD4"
int openfile()
{
    // asm("svc #0":::);
    // asm("stp q1, q2, [x0]");

    FILE *fp = NULL;
    fp = fopen("test.txt", "w+");
    fprintf(fp, "ok!!!");
    fputs("hello world!\n", fp);
    fclose(fp);
    return 0;
}

void print_message_function( void *ptr ) {
    int i = 0;
    for (i; i<5; i++) {
        printf("%s:%d\n", (char *)ptr, i);
    }
}

int newthread()
{
    pthread_t thread;
    char* threadstr = "thead1";
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


// extern void run();
// __asm__(
//     ".global run\n\t"
//     ".type func, @function\n\t"
//     ".run,\n\t"
//     ""

// );

static void test_arm(void)
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace1, trace2;

    uint64_t tpidr_el0=0;
    asm("mrs  x18, tpidr_el0\n\tstr x18, %0"::"m"(tpidr_el0):);

    uint64_t CPACR_FPEN_MASK = (0x3 << 20);
    uint64_t CPACR_FPEN_TRAP_NONE = (0x3 << 20);

    uint64_t cpacr_el1 = 0;

    int64_t r0 = 0x1234; // R0 register
    int64_t r1 = 0x2222; // R1 register
    int64_t r2 = 0x1111; // R1 register
    int64_t r3 = 0x3333; // R2 register
    int8_t *stack = (int8_t*)malloc(STACKSIZE);
    printf("Emulate ARM code\n");

    // Initialize emulator in ARM mode
    err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc);
    if (err)
    {
        printf("Failed on uc_open() with error returned: %u (%s)\n",
               err, uc_strerror(err));
        return;
    }
    uc_reg_write(uc, UC_ARM64_REG_W0, &r0);
    uc_reg_write(uc, UC_ARM64_REG_W1, &r1);
    uc_reg_write(uc, UC_ARM64_REG_W2, &r2);
    uc_reg_write(uc, UC_ARM64_REG_W3, &r3);
    uc_reg_write(uc, UC_ARM64_REG_TPIDR_EL0, &tpidr_el0);
    
    uc_reg_read(uc, UC_ARM64_REG_CPACR_EL1, &cpacr_el1);
    cpacr_el1 = (cpacr_el1 & ~CPACR_FPEN_MASK) | CPACR_FPEN_TRAP_NONE;
    uc_reg_write(uc, UC_ARM64_REG_CPACR_EL1, &cpacr_el1);
    void *st = ((uint64_t *)&stack[STACKSIZE]);
    printf("stack: %p\n", st);
    uc_reg_write(uc, UC_ARM64_REG_SP, &st);

    int64_t lr = -1;
    uc_reg_write(uc, UC_ARM64_REG_LR, &lr);

    // tracing all basic blocks with customized callback
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, (void *)hook_block, NULL, (uint64_t)openfile, (uint64_t)sum + 0xfff);

    // tracing one instruction at ADDRESS with customized callback
    // uc_hook_add(uc, &trace2, UC_HOOK_CODE, (void *)hook_code, NULL, 1, 0);


    StackInfo stackInfo{.stackSt = stack, .size = STACKSIZE};
    // tracing one intr with customized callback
    uc_hook_add(uc, &trace2, UC_HOOK_INTR, (void *)hook_intr, (void*)&stackInfo, 1, 0);

    // emulate machine code in infinite time (last param = 0), or when
    // finishing all the code.
    err = uc_emu_start(uc, (uint64_t)newthread, -1, 0, 0);
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
    uc_reg_read(uc, UC_ARM64_REG_W0, &r0);
    uc_reg_read(uc, UC_ARM64_REG_W1, &r1);
    uc_reg_read(uc, UC_ARM64_REG_W8, &r8);
    uc_reg_read(uc, UC_ARM64_REG_W9, &r9);
    uc_reg_read(uc, UC_ARM64_REG_SP, &sp);
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

int main(int argc, char **argv, char **envp)
{
    test_arm();
    printf("result: arr[0] %p\n", arr[0]);
    printf("result: arr[1] %p\n", arr[1]);
    return 0;
}
// 0xfffed9dc
// 0x7ffffffed9e0