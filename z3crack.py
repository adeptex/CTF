#!/usr/bin/env python

'''
Example function pseudocode:
==============================================

bool __cdecl validate_key(char *s)
{
  unsigned int v2;  // [esp+4h] [ebp-14h]
  int i;            // [esp+8h] [ebp-10h]
  size_t v4;        // [esp+Ch] [ebp-Ch]

  v4 = strlen(s);
  v2 = 0;
  for ( i = 0; (signed int)(v4 - 1) > i; ++i )
    v2 += ((char)convert(s[i]) + 1) * (i + 1);
  return v2 % 0x24 == (char)convert(s[v4 - 1]);
}
'''


from z3 import *

def generate_string(base, length):
    return [Int('%s%d' % (base, i)) for i in range(length)]

def alpha(c):
    return Or(And(c > 47, c <= 57), And(c > 64, c <= 90))

def convert(c):
    return If(And(c > 47, c <= 57), c - 48, c - 55)

def validate_key(serial):
    cs = 0
    for i in range(len(serial) - 1):
        cs += (convert(serial[i]) + 1) * (i + 1)
    return cs % 0x24


s = Solver()
serial = generate_string('s', 16)

s.add(And(map(alpha, serial)))
s.add(validate_key(serial) == convert(serial[-1]))

if s.check() == sat:
    print(s.model())
    flag = ''
    for i in range(len(serial)):
        v = s.model()[serial[i]]
        flag += chr(v.as_long())
    print(flag)
else:
    print('failed')
