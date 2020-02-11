#!/usr/bin/python3

import angr
import claripy
import code
import r2pipe
from tabulate import tabulate

# Continue until fork, syscall, memory_write, etc. All in angr breakpoint docs.
# Hook memory writes, returns, etc with breakpoints to print what is happening
# Manager for moving and storing different simgr states

command_global = []

print("Imported libraries")

project = angr.Project("lockpick")
state = project.factory.entry_state()
simgr = project.factory.simgr(state)


print("Setup angr")

r = r2pipe.open("lockpick")
r.cmd("aa")

temp_addrs = r.cmd("afll~[0]").split("\n")
temp_names = r.cmd("afll~[14]").split("\n")

functions = []
for i in range(0, len(temp_addrs)):
    if "xref" not in temp_names[i] and temp_addrs[i] != "" and "imp" not in temp_names[i]:
        functions.append((hex(int(temp_addrs[i], 16)), temp_names[i]))

def hit_call():
    print("Calling this")

def hit_return():
    print("Returning this")

state.inspect.b("call", hit_call)
state.inspect.b("return", hit_return)

def symbol_to_address(s):
    for addr, name in functions:
        if name == s:
            return addr

def debug_continue():
    simgr.run()

def debug_explore_until():
    global state
    global simgr
    if "0x" in command_global[1]:
        addr = int(command_global[1], 16)
    else:
        addr = int(symbol_to_address(command_global[1]), 16)
        
    print("Debug explore until " + hex(addr))
    simgr.explore(find=addr)
    state = simgr.found[0]
    simgr = project.factory.simgr(state)

def debug_continue_until():
    print("Debug continue until main")
    state.inspect.b("call")
    #simgr.run(until=lambda sm: sm.active[0].addr == 0x400815)
    simgr.run()

def debug_continue_until_ret():
    print("Debug continue until ret")
    simgr.run()

def debug_continue_until_call():
    print("Debug continue until call")
    simgr.run()

def debug_continue_until_branch():
    print("Debug continue until branch")
    while len(simgr.active) == 1:
        simgr.step()

def disass_states():
    output = []
    num = 10
    if len(command_global) > 1:
        num = int(command_global[1])
    for s in simgr.active:
        output.append(r.cmd("pi " + str(num) + " @ " + hex(s.addr)))
    print(tabulate([output]))

def current_location():
    return state.regs.rip

def print_stdin():
    print(state.posix.dumps(0).decode())

def get_addr():
    ret = ""
    if len(simgr.active) < 4:
        for s in simgr.active:
            ret += str(hex(s.addr)) + " "
        ret = ret[0:-1]
    else:
        ret += str(len(simgr.active))
    return ret

def interactive():
    global project
    global state
    global simgr
    code.interact(local=locals())

commands = [("dc", debug_continue),
            ("dcu", debug_continue_until),
            ("dcub", debug_continue_until_branch),
            ("deu", debug_explore_until),
            ("pd", disass_states),
            ("pi", print_stdin),
            ("i", interactive),
            ("exit", exit),
            ("q", exit)]

print("Setup commands")

def main():
    global command_global

    while True:
        print("[" + get_addr() + "|" + str(len(simgr.deadended)) + "]> ", end='')
        command = input().strip().split(" ")
        command_global = command

        for c, f in commands:
            if c == command[0]:
                f()
main()

