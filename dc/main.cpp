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
int sum(int a, int b, int c)
{
    return 0x1111;
}

static void test_arm(void)
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace1, trace2;

    int64_t r0 = 0x1234;     // R0 register
    int64_t r1 = 0x2222;     // R1 register
    int64_t r2 = 0x6789;     // R1 register
    int64_t r3 = 0x3333;     // R2 register
    int64_t stack[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}; 
    printf("Emulate ARM code\n");

    // Initialize emulator in ARM mode
    err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n",
                err, uc_strerror(err));
        return;
    }
    uc_reg_write(uc, UC_ARM64_REG_W0, &r0);
    uc_reg_write(uc, UC_ARM64_REG_W1, &r1);
    uc_reg_write(uc, UC_ARM64_REG_W2, &r2);
    uc_reg_write(uc, UC_ARM64_REG_W3, &r3);
    void* st = (void*)&stack[8];
    uc_reg_write(uc, UC_ARM64_REG_SP, &st);

    // emulate machine code in infinite time (last param = 0), or when
    // finishing all the code.
    err = uc_emu_start(uc, (uint64_t)ARM_SUM, ((uint64_t)ARM_SUM)+sizeof(ARM_SUM)-1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u\n", err);
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    int64_t sp, r8,r9;
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
    for (int i =0; i < 16; i++)
        printf("%d:%d, ", i, stack[i]);
    printf("\n");


    uc_close(uc);
}

int main(int argc, char **argv, char **envp)
{
    test_arm();
    return 0;
}
// 0xfffed9dc
// 0x7ffffffed9e0