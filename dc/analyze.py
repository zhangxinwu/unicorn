from capstone import *

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
mdd = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
with open("trace.log", "r") as f:
    for line in f.readlines():
        l = line.split()
        addr = int(l[0], base=16)
        code = b''
        for i in l[1:]:
            code += int(i, base=16).to_bytes(1, 'little')
        if len(l) > 3:
            for i in md.disasm(code, addr):
                print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
        else:
            for i in mdd.disasm(code, addr):
                print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
        
