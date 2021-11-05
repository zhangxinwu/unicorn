#include "unicorn/unicorn.h"
#include <stdio.h>
#include <string.h>
#include <cmath>

using namespace std;

#define ARM_CODE "\x00\x37\x00\xa0\xe3\x03\x10\x42\xe0" // mov r0, #0x37; sub r1, r2, r3

/*
.text:00064590 0C D0 4D E2                 SUB             SP, SP, #0xC
.text:00064594 08 00 8D E5                 STR             R0, [SP,#0xC+var_4]
.text:00064598 04 10 8D E5                 STR             R1, [SP,#0xC+var_8]
.text:0006459C 00 20 8D E5                 STR             R2, [SP,#0xC+var_C]
.text:000645A0 11 01 01 E3                 MOVW            R0, #0x1111
.text:000645A4 0C D0 8D E2                 ADD             SP, SP, #0xC
.text:000645A8 1E FF 2F E1                 BX              LR
*/

#define ARM_SUM "\x0C\xD0\x4D\xE2\x08\x00\x8D\xE5\x04\x10\x8D\xE5\x00\x20\x8D\xE5\x11\x01\x01\xE3\x0C\xD0\x8D\xE2\x1E\xFF\x2F\xE1"
int sum(int a, int b, int c)
{
    return 0x1111;
}

static void test_arm(void)
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace1, trace2;

    int r0 = 0x1234;     // R0 register
    int r1 = 0x2222;     // R1 register
    int r2 = 0x6789;     // R1 register
    int r3 = 0x3333;     // R2 register
    int stack[] = {r0, r1, r2, r3, r0, r1, r2, r3}; 
    printf("Emulate ARM code\n");

    // Initialize emulator in ARM mode
    err = uc_open(UC_ARCH_ARM, UC_MODE_ARM, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n",
                err, uc_strerror(err));
        return;
    }
    uc_reg_write(uc, UC_ARM_REG_R0, &r0);
    uc_reg_write(uc, UC_ARM_REG_R1, &r1);
    uc_reg_write(uc, UC_ARM_REG_R2, &r2);
    uc_reg_write(uc, UC_ARM_REG_R3, &r3);
    uint64_t st = (uint64_t)&stack[4];
    uc_reg_write(uc, UC_ARM_REG_R13, &st);

    // emulate machine code in infinite time (last param = 0), or when
    // finishing all the code.
    err = uc_emu_start(uc, (uint64_t)ARM_SUM, ((uint64_t)ARM_SUM)+sizeof(ARM_SUM)-1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u\n", err);
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    uc_reg_read(uc, UC_ARM_REG_R0, &r0);
    uc_reg_read(uc, UC_ARM_REG_R1, &r1);
    printf(">>> R0 = 0x%x\n", r0);
    printf(">>> R1 = 0x%x\n", r1);

    uc_close(uc);
}

int main(int argc, char **argv, char **envp)
{
    test_arm();
    return 0;
}
