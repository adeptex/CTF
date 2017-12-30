'''
Usage: ./crackme password
'''

import angr, claripy

flag_addr = 0x40064A
avoid_addrs = [0x40060D, 0x400658]
f_main = 0x400604 #main function

flag = claripy.BVS('flag', 18*8)

exe = angr.Project('crackme30')
state = exe.factory.blank_state(addr=f_main)

state.memory.store(state.regs.rsp, claripy.BVV(0x4141414141414141, 64), endness='Iend_LE')      # set fake return address
state.memory.store(state.regs.rsp + 8, state.regs.rsp + 64, endness='Iend_LE')                  # I can't remember if I even need this... better safe than sorry
state.memory.store(state.regs.rsp + 16, claripy.BVV(0, 64), endness='Iend_LE')                  # see above
state.memory.store(state.regs.rsp + 64, state.regs.rsp + 128, endness='Iend_LE')                # set first argv string pointer
state.memory.store(state.regs.rsp + 72, state.regs.rsp + 129, endness='Iend_LE')                # set second argv string pointer
state.memory.store(state.regs.rsp + 80, claripy.BVV(0, 64), endness='Iend_LE')
state.memory.store(state.regs.rsp + 128, claripy.BVV(0, 8))                                     # set first argv string to the empty string
state.memory.store(state.regs.rsp + 129, flag)                                                  # set second argv string to symbolic flag!
state.regs.rdi = 2                                                                              # set argc = 2
state.regs.rsi = state.regs.rsp + 64                                                            # set argv = args
state.regs.rdx = state.regs.rsp + 80                                                            # set envp = empty list

sm = exe.factory.simgr(state)
sm.explore(find=flag_addr, avoid=avoid_addrs)

found = sm.found[0]
print hex(found.solver.eval(flag)), '-->', hex(found.solver.eval(flag))[2:-1].decode('hex')
