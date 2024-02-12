# ROT13 or anything
from sys import argv
from string import ascii_lowercase, ascii_uppercase


def rot(text, offset):
    roted = ""

    for ch in text:
        if ch in ascii_lowercase:
            roted += ascii_lowercase[(ascii_lowercase.index(ch) + offset) % 26]
        elif ch in ascii_uppercase:
            roted += ascii_uppercase[(ascii_uppercase.index(ch) + offset) % 26]
        else:
            roted += ch
    
    return roted


for i in range(1, 26):
    print(f"{i:02d}", rot(argv[1], i))
