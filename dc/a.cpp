#include <stdio.h>
/**
.text:00000000000017A8 FF 03 01 D1 SUB             SP, SP, #0x40
.text:00000000000017AC FD 7B 03 A9 STP             X29, X30, [SP,#0x30+var_s0]
.text:00000000000017B0 FD C3 00 91 ADD             X29, SP, #0x30
.text:00000000000017B4 BF 83 1F F8 STUR            XZR, [X29,#fp]
.text:00000000000017B8 A0 47 00 D1 SUB             X0, X29, #-filename ; filename
.text:00000000000017BC E0 07 00 F9 STR             X0, [SP,#0x30+format]
.text:00000000000017C0 88 0E 80 52 MOV             W8, #0x74 ; 't'
.text:00000000000017C4 A8 F3 1E 38 STURB           W8, [X29,#filename]
.text:00000000000017C8 A9 0C 80 52 MOV             W9, #0x65 ; 'e'
.text:00000000000017CC A9 03 1F 38 STURB           W9, [X29,#filename+1]
.text:00000000000017D0 69 0E 80 52 MOV             W9, #0x73 ; 's'
.text:00000000000017D4 A9 13 1F 38 STURB           W9, [X29,#filename+2]
.text:00000000000017D8 A8 23 1F 38 STURB           W8, [X29,#filename+3]
.text:00000000000017DC C9 05 80 52 MOV             W9, #0x2E ; '.'
.text:00000000000017E0 A9 33 1F 38 STURB           W9, [X29,#filename+4]
.text:00000000000017E4 A8 43 1F 38 STURB           W8, [X29,#filename+5]
.text:00000000000017E8 09 0F 80 52 MOV             W9, #0x78 ; 'x'
.text:00000000000017EC A9 53 1F 38 STURB           W9, [X29,#filename+6]
.text:00000000000017F0 A8 63 1F 38 STURB           W8, [X29,#filename+7]
.text:00000000000017F4 BF 73 1F 38 STURB           WZR, [X29,#filename+8]
.text:00000000000017F8 A1 53 00 D1 SUB             X1, X29, #-fileopt ; modes
.text:00000000000017FC E1 0B 00 F9 STR             X1, [SP,#0x30+s]
.text:0000000000001800 E8 0E 80 52 MOV             W8, #0x77 ; 'w'
.text:0000000000001804 A8 C3 1E 38 STURB           W8, [X29,#fileopt]
.text:0000000000001808 68 05 80 52 MOV             W8, #0x2B ; '+'
.text:000000000000180C A8 D3 1E 38 STURB           W8, [X29,#fileopt+1]
.text:0000000000001810 BF E3 1E 38 STURB           WZR, [X29,#fileopt+2]
.text:0000000000001814 2B 00 00 94 BL              .fopen
.text:0000000000001818 E1 07 40 F9 LDR             X1, [SP,#0x30+format] ; format
.text:000000000000181C A0 83 1F F8 STUR            X0, [X29,#fp]
.text:0000000000001820 A0 83 5F F8 LDUR            X0, [X29,#fp] ; stream
.text:0000000000001824 2B 00 00 94 BL              .fprintf
.text:0000000000001828 E0 0B 40 F9 LDR             X0, [SP,#0x30+s] ; s
.text:000000000000182C A1 83 5F F8 LDUR            X1, [X29,#fp] ; stream
.text:0000000000001830 2C 00 00 94 BL              .fputs
.text:0000000000001834 A0 83 5F F8 LDUR            X0, [X29,#fp] ; stream
.text:0000000000001838 2E 00 00 94 BL              .fclose
.text:000000000000183C 20 00 20 D4 BRK             #1
 */
#define OPENFILE "\xFF\x03\x01\xD1\xFD\x7B\x03\xA9\xFD\xC3\x00\x91\xBF\x83\x1F\xF8\xA0\x47\x00\xD1\xE0\x07\x00\xF9\x88\x0E\x80\x52\xA8\xF3\x1E\x38\xA9\x0C\x80\x52\xA9\x03\x1F\x38\x69\x0E\x80\x52\xA9\x13\x1F\x38\xA8\x23\x1F\x38\xC9\x05\x80\x52\xA9\x33\x1F\x38\xA8\x43\x1F\x38\x09\x0F\x80\x52\xA9\x53\x1F\x38\xA8\x63\x1F\x38\xBF\x73\x1F\x38\xA1\x53\x00\xD1\xE1\x0B\x00\xF9\xE8\x0E\x80\x52\xA8\xC3\x1E\x38\x68\x05\x80\x52\xA8\xD3\x1E\x38\xBF\xE3\x1E\x38\x2B\x00\x00\x94\xE1\x07\x40\xF9\xA0\x83\x1F\xF8\xA0\x83\x5F\xF8\x2B\x00\x00\x94\xE0\x0B\x40\xF9\xA1\x83\x5F\xF8\x2C\x00\x00\x94\xA0\x83\x5F\xF8\x2E\x00\x00\x94\x20\x00\x20\xD4"
int openfile()
{
    FILE *fp = NULL;
    char filename[9];
    char fileopt[3];
    filename[0] = 't';
    filename[1] = 'e';
    filename[2] = 's';
    filename[3] = 't';
    filename[4] = '.';
    filename[5] = 't';
    filename[6] = 'x';
    filename[7] = 't';
    filename[8] = '\0';
    fileopt[0] = 'w';
    fileopt[1] = '+';
    fileopt[2] = '\0';
    fp = fopen(filename, fileopt);
    fprintf(fp, filename);
    fputs(fileopt, fp);
    fclose(fp);
}

int test()
{
    uint64_t x0 = 1, x1 = 2, x2 = 3, x3 = 4, x4 = 5, x5,x6,x7;
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

    SVC_CALL(0);
}

int main()
{
    test();
    openfile();
    return 0;
}