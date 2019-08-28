from idaapi import *
from idautils import *
import base64
import json

# Adapted from keystone; see: https://github.com/keystone-engine/keypatch/blob/bfcaef11de3a90efb08ed4f0c39dccf40d5613d0/keypatch.py
def get_meta():
    binary_info = dict()
    # heuristically detect hardware setup
    info = idaapi.get_inf_structure()

    try:
        cpuname = info.procname.lower()
    except:
        cpuname = info.procName.lower()
    try:
        # since IDA7 beta 3 (170724) renamed inf.mf -> is_be()/set_be()
        is_be = idaapi.cvar.inf.is_be()
    except:
        # older IDA versions
        is_be = idaapi.cvar.inf.mf
    binary_info['bits'] = 'Bits64' if info.is_64bit() else 'Bits32'
    binary_info['endian'] = 'Big' if is_be else 'Little'

    if cpuname.startswith("arm"):
        binary_info['arch'] = 'Arm'
    elif cpuname.startswith("mips"):
        binary_info['arch'] = 'Mips'
    else:
        binary_info['arch'] = 'NotSupported'
    return binary_info

image = get_meta()
autoWait()
functions = []

for ea in Segments():
    for fn_entry_address in Functions(SegStart(ea), SegEnd(ea)):
        fn_name = GetFunctionName(fn_entry_address)
        fn = get_func(fn_entry_address)
        inst = dict()
        inst['name'] = fn_name
        inst['start_addr'] = fn.startEA
        inst['end_addr'] = fn.endEA
        inst['blocks'] = []
        for fn_block in FlowChart(fn):
            block = dict()
            block['start_addr'] = fn_block.startEA
            block['end_addr'] = fn_block.endEA
            if image["arch"] == 'Arm':
                block['t_reg'] = GetReg(fn_block.startEA, 'T') == 1
            block['dests'] = []
            for block_succ in fn_block.succs():
                block['dests'].append(block_succ.startEA)
            inst['blocks'].append(block)
        functions.append(inst)
with open('{}', 'w+') as f:
    json.dump(image, f)
Exit(0)
