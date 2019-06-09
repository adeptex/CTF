'''
python xor_strings.py asdf 123456
'''

def xor(s1, s2):
    if len(s1) < len(s2):
        key = s1
        value = s2
    else:
        key = s2
        value = s1
    ret = ''
    for i in range(len(value)):
        ret += chr(ord(key[i%len(key)]) ^ ord(value[i]))
    return ret

from sys import argv
print(xor(argv[1], argv[2]))
