#!/usr/bin/python

import re
import sys
import copy

FIND1 = r':c:type:`([\w\d_]+\(\))`'
FIND2 = r':c:type:`([\w\d_]+)`\(\)'

inf = file(sys.argv[1])
s = inf.read()
s0 = copy.copy(s)
inf.close()


def repl(m):
    return r':c:type:`%s` ()' % m.group(1)


s = re.sub(FIND1, repl, s)
s = re.sub(FIND2, repl, s)

if s != s0:
    outf = file(sys.argv[2], "wt")
    outf.write(s)
    outf.close()
