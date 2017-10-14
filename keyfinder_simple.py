import angr

flag_addr = 0x000000000040064A
avoid_addrs = [0x000000000040060D, 0x0000000000400658]

exe = angr.Project('crackme30')
state = exe.factory.entry_state()
sm = exe.factory.simgr(state)
sm.explore(find=flag_addr, avoid=avoid_addr)
flag = sm.found[0].posix.dumps(0).strip()
print flag
print repr(flag)
