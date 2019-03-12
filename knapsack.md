
# TamuCTF 2019: Holey Knapsack (crypto)
https://github.com/tamuctf/TAMUctf-2019/tree/master/Crypto/HoleyKnapsack

## Challenge:
```
11b90d6311b90ff90ce610c4123b10c40ce60dfa123610610ce60d450d000ce61061106110c4098515340d4512361534098509270e5d09850e58123610c9
```  
Public key: `{99, 1235, 865, 990, 5, 1443, 895, 1477}`

## Solution:

```python
#!/usr/bin/env sagemath
'''
Documentation:
    http://www.cs.sjsu.edu/faculty/stamp/papers/topics/topic16/Knapsack.pdf
    https://github.com/timcardenuto/cryptology/tree/d12825b7eabf2f8a0b1bb4590675aeb4705e3b74/knapsacks
'''

def is_short_vector(vector):
    for v in vector:
        if v != 1 and v != 0:
            return False
    return True

def find_short_vector(matrix):
    for row in matrix:
        if is_short_vector(row):
            return row

pubKey = [99, 1235, 865, 990, 5, 1443, 895, 1477]
c = '11b90d6311b90ff90ce610c4123b10c40ce60dfa123610610ce60d450d000ce61061106110c4098515340d4512361534098509270e5d09850e58123610c9'
c = [int('0x'+c[x:x+4],16) for x in range(0,len(c),4)]
nbit = len(pubKey)
flag = []

for encoded in c:

    A = Matrix(ZZ,nbit+1,nbit+1)

    for i in xrange(nbit):
        A[i,i] = 1

    for i in xrange(nbit):
        A[i,nbit] = pubKey[i]

    A[nbit,nbit] = -int(encoded)

    res = A.LLL()
    print res.str()
    short_vector = find_short_vector(res)
    try:
        short_vector = chr(int(''.join([str(x) for x in short_vector[::-1]]), 2))
        flag.append(short_vector)
        print short_vector
    except:
        flag.append('_')
        pass

print ''.join(flag)


#gigem{merkle-hellman-knapsack}
```
