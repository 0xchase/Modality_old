from tabulate import *

# Chage commands to kill/revive state by numbers rather than addresses

# ========== Commands ========== #

def kill(main, command, simgr):
    if "0x" in command[1]:
        addr = int(command[1], 16)
        simgr.move(from_stash='active', to_stash='deadended', filter_func=lambda s: s.addr == addr)
    else:
        num = int(command[1])
        simgr.deadended.append(simgr.active[num])
        simgr.active.remove(simgr.active[num])
        

def revive(main, command, simgr):
    addr = int(command[1], 16)
    simgr.move(from_stash='deadended', to_stash='active', filter_func=lambda s: s.addr == addr)

def list(main, command, simgr):
    table = []
    if len(command) == 1:
        for i in range(0, len(simgr.active)):
            table.append([str(i), hex(simgr.active[i].addr)])
    print(tabulate(table))

def name(main, command, simgr):
    print("Stash name")

def stdout(main, command, simgr):
    if len(command) == 1:
        for state in simgr.active:
            print_decode(state.posix.dumps(1))

def stdin(main, command, simgr):
    if len(command) == 1:
        for state in simgr.active:
            print_decode(state.posix.dumps(0))

# ========== Utilities ========== #

def get_name(state):
    if hasattr(state, "name"):
        return state.name
    else:
        return hex(state.addr)

def print_decode(data):
    try:
        print(data.decode())
    except:
        print(str(data))
