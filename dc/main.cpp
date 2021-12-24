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

#define STACKSIZE 0x20000

typedef struct {
    uint64_t l;
    uint64_t h;
}uint128_t;

set<pair<uint64_t, uint64_t> > ignoreMemRange;

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

void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    auto itr = ignoreMemRange.lower_bound(pair<uint64_t, uint64_t>(address, 0));
    if(itr != ignoreMemRange.end() && itr->first >= address && address <= itr->second)
        return;
    else 
        ;
    FILE* fp = (FILE*)(user_data);
    fprintf(fp, "%llx", address);
    for (int i = 0 ; i < size; i++)
    {
        fprintf(fp, " %02x", ((uint8_t *)address)[i]);
    }
    fprintf(fp, "\n");
    fflush(fp);
}

void hook_block(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
}

void hook_mem(uc_engine *uc, uc_mem_type type,
        uint64_t address, int size, int64_t value, void *user_data)
{
}


extern "C" void create_new_unicorn(uint64_t x0, void* user_data, uint128_t* regs)
{
    uc_engine *uc;
    uc_hook trace1, trace2;
    int err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc);

    for(int ri = UC_ARM64_REG_INVALID+1; ri < UC_ARM64_REG_ENDING; ri++)
    {
        err = uc_reg_write(uc, ri, regs+ri);
        // if (err != UC_ERR_OK) { printf("regs[ri] read error.", ri); exit(-1); }
    }
    
    uint64_t tpidr_el0=0, cpacr_el1=0, tpidr_el0_tmp, cpacr_el1_tmp;
    asm("mrs  %0, tpidr_el0\n\t str %0, %1"::"r"(tpidr_el0_tmp),"m"(tpidr_el0):);

    uc_reg_write(uc, UC_ARM64_REG_TPIDR_EL0, &tpidr_el0);
    // asm("mrs  %0, cpacr_el1\n\t str %0, %1"::"r"(cpacr_el1_tmp), "m"(cpacr_el1):);
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

extern "C" int android_native_call(uint64_t* method, uint32_t* args, uint32_t argsize, void* self, void* result, const char* shorty, int isStatic, const void* func, const char* method_name)
{
    if(method_name && func && shorty && args) {
        __android_log_print(ANDROID_LOG_DEBUG, "libanduni", "call method %s[%p]{%s}", method_name, func, shorty);
        if (strcmp(method_name, "int com.xtgo.nbtest.MainActivity.stringFromJNI(int, int, int)") && strcmp(method_name, "int com.xtgo.nbtest.MainActivity.stringFromJNI3(int, int, int, int, int, int, int, int, int, float, float, float, float, float, float, float, float, float, float, float)"))
            return -1;
    } else
        return -1;
    
    __android_log_print(ANDROID_LOG_INFO, "libanduni", "unicall start! method %s[%p]{%s}", method_name, func, shorty);
    __android_log_print(ANDROID_LOG_INFO, "libanduni", "printf[%llx] log[%llx]", (uint64_t)printf, (uint64_t)__android_log_print);
    // addIgnoreRange((uint64_t)printf);
    // addIgnoreRange((uint64_t)__android_log_print);

    uc_engine *uc;
    uc_err err;
    uc_hook trace1, trace2, trace3, trace4;

    // Initialize emulator in ARM mode
    err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc);
    if (err)
    {
        __android_log_print(ANDROID_LOG_ERROR, "libanduni", "Failed on uc_open() with error returned: %u (%s)\n",
               err, uc_strerror(err));
        return -1;
    }
    // init regs
    uint64_t tpidr_el0=0, tpidr_el0_tmp;
    asm("mrs  %0, tpidr_el0\n\t str %0, %1"::"r"(tpidr_el0_tmp),"m"(tpidr_el0):);
    uc_reg_write(uc, UC_ARM64_REG_TPIDR_EL0, &tpidr_el0);

    uint64_t CPACR_FPEN_MASK = (0x3 << 20);
    uint64_t CPACR_FPEN_TRAP_NONE = (0x3 << 20);
    uint64_t cpacr_el1 = 0, cpacr_el1_tmp;
    // asm("mrs  %0, cpacr_el1\n\t str %0, %1"::"r"(cpacr_el1_tmp), "m"(cpacr_el1):);
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
    // is static eq 0
    if(!isStatic)
        xi = 0;
    else
        uc_reg_write(uc, UC_ARM64_REG_W1, args++);
    for (const char* cptr = shorty; *cptr != '\0'; cptr++) {
        if (*cptr == 'F') { // is float?
            float f = *(float*)args;
            args+=1;
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
            uint32_t i = *(uint32_t*)args;
            args+=1;
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
        __android_log_print(ANDROID_LOG_ERROR, "libanduni", "Failed on uc_emu_start() with error returned: %u\n", err);
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

extern "C" int android_native_call_force(uint64_t* method, uint32_t* args, uint32_t argsize, void* self, void* result, const char* shorty, int isStatic, const void* func, const char* method_name)
{
    if(method_name && func && shorty && args) {
        __android_log_print(ANDROID_LOG_DEBUG, "libanduni", "call force method %s[%p]{%s}", method_name, func, shorty);
        if (strcmp(method_name, "int com.xtgo.nbtest.MainActivity.stringFromJNI(int, int, int)") && strcmp(method_name, "int com.xtgo.nbtest.MainActivity.stringFromJNI3(int, int, int, int, int, int, int, int, int, float, float, float, float, float, float, float, float, float, float, float)"))
            return -1;
    } else
        return -1;
    
    __android_log_print(ANDROID_LOG_INFO, "libanduni", "unicall start! method %s[%p]{%s}", method_name, func, shorty);
    __android_log_print(ANDROID_LOG_INFO, "libanduni", "printf[%llx] log[%llx]", (uint64_t)printf, (uint64_t)__android_log_print);
    // addIgnoreRange((uint64_t)printf);
    // addIgnoreRange((uint64_t)__android_log_print);

    uc_engine *uc;
    uc_err err;
    uc_hook trace1, trace2, trace3, trace4;

    // Initialize emulator in ARM mode
    err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc);
    if (err)
    {
        __android_log_print(ANDROID_LOG_ERROR, "libanduni", "Failed on uc_open() with error returned: %u (%s)\n",
               err, uc_strerror(err));
        return -1;
    }
    // init regs
    uint64_t tpidr_el0=0, tpidr_el0_tmp;
    asm("mrs  %0, tpidr_el0\n\t str %0, %1"::"r"(tpidr_el0_tmp),"m"(tpidr_el0):);
    uc_reg_write(uc, UC_ARM64_REG_TPIDR_EL0, &tpidr_el0);

    uint64_t CPACR_FPEN_MASK = (0x3 << 20);
    uint64_t CPACR_FPEN_TRAP_NONE = (0x3 << 20);
    uint64_t cpacr_el1 = 0, cpacr_el1_tmp;
    // asm("mrs  %0, cpacr_el1\n\t str %0, %1"::"r"(cpacr_el1_tmp), "m"(cpacr_el1):);
    uc_reg_read(uc, UC_ARM64_REG_CPACR_EL1, &cpacr_el1);
    cpacr_el1 = (cpacr_el1 & ~CPACR_FPEN_MASK) | CPACR_FPEN_TRAP_NONE;
    uc_reg_write(uc, UC_ARM64_REG_CPACR_EL1, &cpacr_el1);

    int8_t *stack = (int8_t*)malloc(STACKSIZE);
    memset(stack, 0, STACKSIZE);
    uint64_t *st = ((uint64_t *)&stack[STACKSIZE]);

    int64_t lr = -1;
    uc_reg_write(uc, UC_ARM64_REG_LR, &lr);

    //init args
    uc_reg_write(uc, UC_ARM64_REG_SP, &st);
    // (this, args, args_size, self, result, shorty)
    uc_reg_write(uc, UC_ARM64_REG_X0, &method);
    uc_reg_write(uc, UC_ARM64_REG_X1, &args);
    uc_reg_write(uc, UC_ARM64_REG_W2, &argsize);
    uc_reg_write(uc, UC_ARM64_REG_X3, &self);
    uc_reg_write(uc, UC_ARM64_REG_X4, &result);
    uc_reg_write(uc, UC_ARM64_REG_X5, &shorty);

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
        __android_log_print(ANDROID_LOG_ERROR, "libanduni", "Failed on uc_emu_start() with error returned: %u\n", err);
    }
    free(stack);
    uc_close(uc);
    fclose(fp);
    return 0;
}