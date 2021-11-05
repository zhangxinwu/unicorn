funcs = []
with open("trace.txt") as f:
    lines = f.readlines()
    t = 0
    for i in range(len(lines)):
        sp = lines[i].split()
        if sp[0]=='':
            sp = sp[1:]
        if len(sp) > 1 and sp[1].startswith('.'):
            st = []
            if '+' in sp[1]:
                st = sp[1].split('+')
            else:
                st = sp[1].split(':')
                if len(st) > 2:
                    st = [':'.join(st[:-1]), st[-1]]
                else:
                    st = [sp[1]]
                # print(st)
            fc = st[0]
            if len(funcs) == 0:
                funcs.append((t, fc))
            else:
                ti, fi = funcs[-1]
                if fi == fc:
                    continue
                else:
                    cl = lines[i-1].split()[2]
                    if 'call' in cl:
                        t+=1
                        funcs.append((t, fc))
                    if 'ret' in cl:
                        t-=1
                        funcs.append((t, fc))
                    if cl.startswith('j') and fc == fi:
                        t = ti
                        funcs.append(t,fc)

for (ti, fi) in funcs:
    print(' '*ti, fi)
    pass
