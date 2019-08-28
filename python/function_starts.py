from idaapi import *
from idautils import *
import base64
import json

autoWait()
function_entries = []

for ea in Segments():
    for fn_entry_address in Functions(SegStart(ea), SegEnd(ea)):
        fn = get_func(fn_entry_address)
        function_entries.append((fn.startEA, fn.endEA))
with open('{}', 'w+') as f:
    json.dump(image, f)
Exit(0)
