#include "unicorn/unicorn.h"
#include <stdio.h>
#include <string.h>
#include <cmath>

using namespace std;

#define ARM_CODE "\x00\x37\x00\xa0\xe3\x03\x10\x42\xe0" // mov r0, #0x37; sub r1, r2, r3

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
    printf(">>> Tracing instruction at %p, instruction size = 0x%x  %p\n", address, size, *(uint32_t *)address);
}

struct SvcCall
{
	uint32_t b1 : 1;				// 1
	uint32_t b2 : 1;				// 0
	uint32_t b3 : 3;				// 0 0 0
	uint32_t svcNumber : 16;		//
	uint32_t b4 : 3;				// 0 0 0
	uint32_t b5 : 8;				// 0 0 1 0 1 0 1 1
};

static void hook_intr(uc_engine *uc, uint32_t intno, void *user_data) {
    printf(">>> Tracing intr %x\n", intno);
    uint8_t inst[4];
    uint64_t pc;
    uc_reg_read(uc, UC_ARM64_REG_PC, &pc);

    uc_mem_read(uc, pc, inst, 4);
    printf(">>> Tracing intr->pc %x %x %x %x\n", inst[0], inst[1], inst[2], inst[3]);
    
    uc_err err;
	// Just grab a bunch of registers here so we don't have to make a bunch of calls
	// Being lazy =)
	uint64_t x0 = 0, x1 = 0, x2 = 0, x3 = 0, x4 = 0, x5 = 0, x6 = 0, x7 = 0;
    uint64_t lr = -1;
    uc_reg_read(uc, UC_ARM64_REG_LR, &lr);

    err = uc_reg_read(uc, UC_ARM64_REG_X0, &x0); if (err != UC_ERR_OK) { return; }
	err = uc_reg_read(uc, UC_ARM64_REG_X1, &x1); if (err != UC_ERR_OK) { return; }
	err = uc_reg_read(uc, UC_ARM64_REG_X2, &x2); if (err != UC_ERR_OK) { return; }
	err = uc_reg_read(uc, UC_ARM64_REG_X3, &x3); if (err != UC_ERR_OK) { return; }
	err = uc_reg_read(uc, UC_ARM64_REG_X4, &x4); if (err != UC_ERR_OK) { return; }
	err = uc_reg_read(uc, UC_ARM64_REG_X5, &x5); if (err != UC_ERR_OK) { return; }
	err = uc_reg_read(uc, UC_ARM64_REG_X6, &x6); if (err != UC_ERR_OK) { return; }
	err = uc_reg_read(uc, UC_ARM64_REG_X7, &x7); if (err != UC_ERR_OK) { return; }

    #define SVC_CALL(svc_num) \
        asm volatile ("ldr x0, %0" ::"m"(x0):);\
        asm volatile ("ldr x1, %0" ::"m"(x1):);\
        asm volatile ("ldr x2, %0" ::"m"(x2):);\
        asm volatile ("ldr x3, %0" ::"m"(x3):);\
        asm volatile ("ldr x4, %0" ::"m"(x4):);\
        asm volatile ("ldr x5, %0" ::"m"(x5):);\
        asm volatile ("ldr x6, %0" ::"m"(x6):);\
        asm volatile ("ldr x7, %0" ::"m"(x7):);\
        asm volatile ("svc #"#svc_num"":::);\
        asm volatile ("str x0, %0" ::"m"(x0):);\
        asm volatile ("str x1, %0" ::"m"(x1):);\
        asm volatile ("str x2, %0" ::"m"(x2):);\
        asm volatile ("str x3, %0" ::"m"(x3):);\
        asm volatile ("str x4, %0" ::"m"(x4):);\
        asm volatile ("str x5, %0" ::"m"(x5):);\
        asm volatile ("str x6, %0" ::"m"(x6):);\
        asm volatile ("str x7, %0" ::"m"(x7):);\

    if (intno == 0) { SVC_CALL(0);}
    if (intno == 1) { SVC_CALL(1);}
	#undef SVC_CALL

	err = uc_reg_write(uc, UC_ARM64_REG_X0, &x0); if (err != UC_ERR_OK) { return; }
	err = uc_reg_write(uc, UC_ARM64_REG_X1, &x1); if (err != UC_ERR_OK) { return; }
	err = uc_reg_write(uc, UC_ARM64_REG_X2, &x2); if (err != UC_ERR_OK) { return; }
	err = uc_reg_write(uc, UC_ARM64_REG_X3, &x3); if (err != UC_ERR_OK) { return; }
	err = uc_reg_write(uc, UC_ARM64_REG_X4, &x4); if (err != UC_ERR_OK) { return; }
	err = uc_reg_write(uc, UC_ARM64_REG_X5, &x5); if (err != UC_ERR_OK) { return; }
	err = uc_reg_write(uc, UC_ARM64_REG_X6, &x6); if (err != UC_ERR_OK) { return; }
	err = uc_reg_write(uc, UC_ARM64_REG_X7, &x7); if (err != UC_ERR_OK) { return; }
    
    uc_reg_write(uc, UC_ARM64_REG_PC, &lr);
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
    FILE *fp = NULL;
    char filename[] = "test.txt\0";
    char fileopt[] = "w+\0";
    fp = fopen(filename, fileopt);
    fprintf(fp, filename);
    fputs(fileopt, fp);
    fclose(fp);
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

    int64_t r0 = 0x1234; // R0 register
    int64_t r1 = 0x2222; // R1 register
    int64_t r2 = 0x1111; // R1 register
    int64_t r3 = 0x3333; // R2 register
    int64_t stack[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
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
    void *st = (void *)&stack[8];
    printf("stack: %p\n", st);
    uc_reg_write(uc, UC_ARM64_REG_SP, &st);

    int64_t lr = -1;
    uc_reg_write(uc, UC_ARM64_REG_LR, &lr);

    // tracing all basic blocks with customized callback
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, (void *)hook_block, NULL, (uint64_t)openfile, (uint64_t)sum + 0xfff);

    // tracing one instruction at ADDRESS with customized callback
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, (void *)hook_code, NULL, 1, 0);

    // tracing one intr with customized callback
    uc_hook_add(uc, &trace2, UC_HOOK_INTR, (void *)hook_intr, NULL, 1, 0);

    // emulate machine code in infinite time (last param = 0), or when
    // finishing all the code.
    err = uc_emu_start(uc, (uint64_t)OPENFILE, -1, 0, 0);
    if (err)
    {
        printf("Failed on uc_emu_start() with error returned: %u\n", err);
    }
    err = uc_errno(uc);
    printf("uc_errno: %d err: %s\n",uc_strerror(err));;

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