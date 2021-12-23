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
#include "android/log.h"

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

struct stPthreadFunc
{
    void* func;
    void* arg;
};

set<pair<uint64_t, uint64_t> > ignoreMemRange;


void hook_block(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void hook_intr(uc_engine *uc, uint32_t intno, void *user_data);

extern "C" void create_new_unicorn(uint64_t x0, StackInfo* stackInfo, uint128_t* regs)
{
    uc_engine *uc;
    uc_hook trace1, trace2;
    int err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc);

    for(int ri = UC_ARM64_REG_INVALID+1; ri < UC_ARM64_REG_ENDING; ri++)
    {
        err = uc_reg_write(uc, ri, regs+ri);
        // if (err != UC_ERR_OK) { printf("regs[ri] read error.", ri); exit(-1); }
    }
    
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
    // uc_hook_add(uc, &trace2, UC_HOOK_CODE, (void *)hook_code, NULL, 1, 0);

    uc_hook_add(uc, &trace2, UC_HOOK_INTR, (void *)hook_intr, NULL, 1, 0);
    
    uint64_t pc = regs[UC_ARM64_REG_PC].l;
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
    uc_reg_read(uc, UC_ARM64_REG_X0, &ret);
    uc_close(uc);
    asm volatile(
        "mov x0, %0""\n\t"
        "mov x8, #0x5d""\n\t"
        "svc #0""\n\t"
        ::"r"(ret):"x0","x8"
    );
}

void hook_block(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    
}

void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    auto itr = ignoreMemRange.lower_bound(pair<uint64_t, uint64_t>(address, 0));
    if(itr != ignoreMemRange.end() && itr->first >= address && address <= itr->second)
        return;
    FILE* fp = (FILE*)(user_data);
    fprintf(fp, "%llx", address);
    for (int i = 0 ; i < size; i++)
    {
        fprintf(fp, " %02x", ((uint8_t *)address)[i]);
    }
    fprintf(fp, "\n");
    fflush(fp);
}

void hook_mem(uc_engine *uc, uc_mem_type type,
        uint64_t address, int size, int64_t value, void *user_data)
{
}


extern "C" void* getAllRegister(uc_engine *uc)
{
    uc_err err;
    uint128_t* regs = (uint128_t*)malloc(UC_ARM64_REG_ENDING*sizeof(uint128_t));
    for(int ri = UC_ARM64_REG_INVALID+1; ri < UC_ARM64_REG_ENDING; ri++)
    {
        err = uc_reg_read(uc, ri, regs+ri);
        //if (err != UC_ERR_OK) { printf("regs[ri] read error.", ri); exit(-1); }
    }
    return regs;
}

void hook_intr(uc_engine *uc, uint32_t intno, void *user_data) {
    // printf(">>> Tracing intr %x\n", intno);
    uint8_t inst[4];
    uint8_t* pc;
    uc_reg_read(uc, UC_ARM64_REG_PC, &pc);

    // printf(">>> Tracing intr->pc %x %x %x %x\n", pc[0], pc[1], pc[2], pc[3]);
    
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
        regs[1] =  (uint64_t)threadStack + STACKSIZE-0x100;
        memcpy((void*)((uint64_t)threadStack + STACKSIZE - 0x100), (void*)allRegs[UC_ARM64_REG_SP].l, 0x100);
    }

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
    // uc_hook_add(uc, &trace2, UC_HOOK_CODE, (void *)hook_code, NULL, (uint64_t)printf, ((uint64_t)printf)+1);


    StackInfo stackInfo{.stackSt = stack, .size = STACKSIZE};
    // tracing one intr with customized callback
    uc_hook_add(uc, &trace3, UC_HOOK_INTR, (void *)hook_intr, (void*)&stackInfo, -1, 0);

    uc_hook_add(uc, &trace4, UC_HOOK_MEM_FETCH, (void*)hook_mem, NULL, -1, 0);

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
pair<uint64_t, uint64_t> get_mem_range(int pid, uint64_t ptr) {
    stringstream ss;
    ss << "/proc/" << pid << "/maps";
    fstream sf(ss.str().c_str(), sf.in);
    string line;
    uint64_t st, ed;
    pair<uint64_t, uint64_t> pi(0, 0);
    while(std::getline(sf, line))
    {
        sscanf(line.c_str(), "%llx-%llx ", &st, &ed);
        if (st <= ptr && ptr <= ed)
        {
            pi.first = st;
            pi.second = ed;
        }
    }
    return pi;
}

void addIgnoreRange(uint64_t ptr)
{
    static set<uint64_t> st;
    if (st.count(ptr))
        return;
    st.insert(ptr);
    ignoreMemRange.insert(get_mem_range(getpid(), ptr));
}

// setprop use_libanduni 1
// setprop anduni_method "int com.xtgo.nbtest.MainActivity.stringFromJNI(int, int, int)"
extern "C" int android_jni_call(uint64_t* method, uint32_t* args, uint32_t argsize, void* self, void* result, const char* shorty, int isStatic, const void* func, const char* method_name)
{
    __android_log_print(6, "libanduni", "call method %s", method_name);
    // check func entrypoint and method_name
    if(1 && method_name && func && shorty && args) {
        __android_log_print(6, "libanduni", "call method %s[%p]{%s}", method_name, func, shorty);
        if (strcmp(method_name, "int com.xtgo.nbtest.MainActivity.stringFromJNI(int, int, int)"))
        {
            return -1;
        }
        // return -1;
    } else {
        return -1;
    }

    addIgnoreRange((uint64_t)printf);
    // addIgnoreRange((uint64_t)__android_log_print);

    uc_engine *uc;
    uc_err err;
    uc_hook trace1, trace2, trace3, trace4;

    // Initialize emulator in ARM mode
    err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc);
    if (err)
    {
        __android_log_print(6, "libanduni", "Failed on uc_open() with error returned: %u (%s)\n",
               err, uc_strerror(err));
        return -1;
    }
    // init regs
    uint64_t tpidr_el0=0;
    asm("mrs  x18, tpidr_el0\n\tstr x18, %0"::"m"(tpidr_el0):);
    uc_reg_write(uc, UC_ARM64_REG_TPIDR_EL0, &tpidr_el0);

    uint64_t CPACR_FPEN_MASK = (0x3 << 20);
    uint64_t CPACR_FPEN_TRAP_NONE = (0x3 << 20);
    uint64_t cpacr_el1 = 0;
    uc_reg_read(uc, UC_ARM64_REG_CPACR_EL1, &cpacr_el1);
    cpacr_el1 = (cpacr_el1 & ~CPACR_FPEN_MASK) | CPACR_FPEN_TRAP_NONE;
    uc_reg_write(uc, UC_ARM64_REG_CPACR_EL1, &cpacr_el1);

    int8_t *stack = (int8_t*)malloc(STACKSIZE);
    memset(stack, 0, STACKSIZE);
    uint64_t *st = ((uint64_t *)&stack[STACKSIZE]);

    int64_t lr = -1;
    uc_reg_write(uc, UC_ARM64_REG_LR, &lr);

    //init args
    // load "this" parameter
    int xi = 1, di = 0;
    if(isStatic)
        xi = 0;
    else
        uc_reg_write(uc, UC_ARM64_REG_W1, args++);
    for (const char* cptr = shorty; *cptr != '\0'; cptr++) {
        if (*cptr == 'F') { // is float?
            float f = *(float*)args++;
            if(di < 8)
            {
                uc_reg_write(uc, UC_ARM64_REG_S0 + di, &f);
                di++;
            }
            else
            {
                st--;
                *(float*)st = f;
            }
        } else if (*cptr == 'D') { // is double?
            double d = *(double*)args;
            args+=2;
            if(di < 8)
            {
                uc_reg_write(uc, UC_ARM64_REG_D0 + di, &d);
                di++;
            }
            else
            {
                st--;
                *(double*)st = d;
            }
        } else if (*cptr == 'J') { // is long?
            uint64_t j = *(uint64_t*)args;
            args+=2;
            if(xi < 7)
            {
                uc_reg_write(uc, UC_ARM64_REG_X1 + xi, &j);
                xi++;
            }
            else
            {
                st--;
                *(uint64_t*)st = j;
            }
        } else {
            uint32_t i = *(uint32_t*)args++;
            if(xi < 7)
            {
                uc_reg_write(uc, UC_ARM64_REG_W1 + xi, &i);
                xi++;
            }
            else
            {
                st--;
                *(uint32_t*)st = i;
            }
        }
    }
    for (uint64_t *sts = st, *std = ((uint64_t *)&stack[STACKSIZE]) - 1; sts < std; sts++, std--) {
        swap(*sts, *std);
    }
    uc_reg_write(uc, UC_ARM64_REG_SP, &st);

    // hook
    // tracing one intr with customized callback
    uc_hook_add(uc, &trace3, UC_HOOK_INTR, (void *)hook_intr, nullptr, -1, 0);

    FILE* fp = fopen("/data/data/com.xtgo.nbtest/trace.log", "w");
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, (void *)hook_code, fp, -1, 0);

    
    // run
    // emulate machine code in infinite time (last param = 0), or when
    // finishing all the code.
    err = uc_emu_start(uc, (uint64_t)func, -1, 0, 0);
    if (err)
    {
        __android_log_print(6, "libanduni", "Failed on uc_emu_start() with error returned: %u\n", err);
    }
    //save result
    if (shorty[0] == 'D') {
        uc_reg_read(uc, UC_ARM64_REG_D0, result);
    } else if(shorty[0] == 'F') {
        uc_reg_read(uc, UC_ARM64_REG_S0, result);
    } else if(shorty[0] != 'V') {
        uc_reg_read(uc, UC_ARM64_REG_X0, result);
    }
    free(stack);
    uc_close(uc);
    fclose(fp);
    return 0;
}

extern "C" void android_update_config(const char* config)
{
    
}
