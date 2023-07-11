#!/usr/bin/env python3

import sys
import tplink_smartplug as tpl

err = 0
s1 = b'test string 1'
e1 = b'\xdf\xba\xc9\xbd\x9d\xee\x9a\xe8\x81\xef\x88\xa8\x99'

e = tpl.encrypt(s1)
if e != e1:
    print(f"failed encrypt: {s1!r} => {e!r} != {e1!r}", file=sys.stderr)
    err += 1

s = tpl.decrypt(e1)
if s != s1:
    print(f"failed decrypt: {e1!r} => {s!r} != {s1!r}", file=sys.stderr)
    err += 1

if err:
    print(f"Failed: {err}")
else:
    print("Success.")
