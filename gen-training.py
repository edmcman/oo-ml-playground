#!/usr/bin/python3

#import json
import pandas
import re
import os
import subprocess
import sys
from tempfile import NamedTemporaryFile

gname = sys.argv[1]
bname = sys.argv[2]
oname = sys.argv[3]

linere = re.compile(r"symbol\(([^,]+), (func|method), ([^)]+)\)\.")


anafile = NamedTemporaryFile(prefix=os.path.basename(bname) + "_", suffix=".bat_ana")
ananame = anafile.name

subprocess.check_output("/data/research/rose/install-latest/bin/bat-ana -o %s %s 2>/dev/null" % (ananame, bname), shell=True)

def get_all_dis():

    output = subprocess.check_output("/data/research/rose/install-latest/bin/bat-dis --no-bb-cfg-arrows --color=off %s 2>/dev/null" % (ananame), shell=True)
    output = re.sub(b' +', b' ', output)

    func_dis = {}
    last_func = None
    current_output = []

    for l in output.splitlines():
        if l.startswith(b";;; function 0x"):
            if last_func is not None:
                func_dis[last_func] = b"\n".join(current_output)
            last_func = int(l.split()[2], 16)
            current_output.clear()

        if not b";;" in l:
            current_output.append(l)

    if last_func is not None:
        if last_func in func_dis:
            print("Warning: Ignoring multiple functions at the same address")
        else:
            func_dis[last_func] = b"\n".join(current_output)

    return func_dis

def get_dis_from_all_dis(addr):
    if addr in all_dis:
        return all_dis[addr]
    else:
        return None

def get_dis(addr):
    try:
        output = subprocess.check_output("/data/research/rose/install-latest/bin/bat-dis --no-bb-cfg-arrows --function %s --color=off %s 2>/dev/null | fgrep -v ';;'" % (addr, ananame), shell=True)
        output = re.sub(b' +', b' ', output)
        # print(output)
        return output
    except subprocess.CalledProcessError:
        return None

all_dis = get_all_dis()
#objs = []
df = pandas.DataFrame(columns=['Binary', 'Addr', 'Name', 'Type', 'Disassembly'])

with open(gname, "r") as f:
    for l in f:

        if linere.match(l):
            m = linere.match(l)
            addr = m.group(1)
            typ = m.group(2)
            name = m.group(3)
            #print([addr, typ, name])

            dis = get_dis_from_all_dis(int(addr, 16))
            #objs.append((addr, typ, name, dis))
            if dis is not None:
                df = df.append({'Binary': bname, 'Addr': addr, 'Name': name, 'Type': typ, 'Disassembly': dis}, ignore_index=True)
            
            if False:
                df.to_csv(oname, index=False)
            #print(df.head())
    
df.to_csv(oname, index=False)

#with open(jname, "w") as f:
#    output = {"file": bname, "d": objs}
#    json.dump(output, f)
