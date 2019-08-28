from idaapi import *
from idautils import *
import base64
import json

autoWait()
function_names = []

for ea in Segments():
    for fn_entry_address in Functions(SegStart(ea), SegEnd(ea)):
        fn_name = GetFunctionName(fn_entry_address)
        function_names.append(fn_name)

with open('{}', 'w+') as f:
    json.dump(function_names, f)
Exit(0)
