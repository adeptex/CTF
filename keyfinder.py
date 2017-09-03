import angr

start_addr = 0x080485AB
flag_addr = 0x08048679
stdin_buffer_size = 4

exe = angr.Project('rev_rev_rev')
state = exe.factory.blank_state(addr=start_addr)
def constrain_char(state, c):
    return state.se.And(c <= 0xff, c >= 0x1)
for i in range(stdin_buffer_size):
    c = state.posix.files[0].read_from(1)
    state.se.add(constrain_char(state, c))
state.posix.files[0].seek(0)
state.posix.files[0].length = stdin_buffer_size
sm = exe.factory.simgr(state)
sm.explore(find=flag_addr)

flag = sm.found[0].posix.dumps(0).strip()
print flag
print repr(flag)
