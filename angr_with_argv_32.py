import angr, claripy

flag_addr = 0x08048817
avoid_addrs = [0x8048761, 0x804883A]
f_main = 0x80486C1 #main function

flag = claripy.BVS('flag', 32*8)

exe = angr.Project('re30')
state = exe.factory.blank_state(addr=f_main)

state.memory.store(0xd0000000, 're30') # content of argv[0], which is the executable name
state.memory.store(0xd0000010, flag) # content of argv[1], which is our flag
state.stack_push(0xd0000010) # pointer to argv[1]
state.stack_push(0xd0000000) # pointer to argv[0]
state.stack_push(state.regs.esp) # argv
state.stack_push(2) # argc
state.stack_push(f_main) # address of main

sm = exe.factory.simgr(state)
sm.explore(find=flag_addr, avoid=avoid_addrs)

found = sm.found[0]
print hex(found.solver.eval(flag)), '-->', hex(found.solver.eval(flag))[2:-1].decode('hex')
