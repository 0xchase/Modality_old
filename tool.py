#!/usr/bin/python3

import angr
import claripy
import code
import r2pipe
from tabulate import tabulate
import sys

# Continue until fork, syscall, memory_write, etc. All in angr breakpoint docs.
# Hook memory writes, returns, etc with breakpoints to print what is happening
# Manager for moving and storing different simgr states
# When hit calls like strlen(), choose to simulate or constrain
# Replace state variable with stash
# in state, add_options=angr.options.unicorn
# Command to generate angr script from command history
# Will save information about avoids, etc
# Command to edit "base script", (which is contents of main.py which run every time it starts), then can use debug commands
# Avoid commands like dea+ dea- dea--
# Commands for filtering stash
# Backwards slicing and backtracing for stash
# Commands for declaring BVS, pushing BVS
# Print stdout as it executes
# Coolor output
# Make all commands run on every state or all states
# Divide up files
# Replace radare2 calls with capstone

if len(sys.argv) < 2:
    print("Usage: ./tool.py <binary>")
    exit()

def temp():
    print("Temp")

command_global = []

print("Imported libraries")

#bvs_stdin = claripy.BVS("bvs_stdin", 8*32)

project = angr.Project(sys.argv[1])
state = project.factory.entry_state(add_options=angr.options.unicorn)
simgr = project.factory.simgr(state)
old_state = state

#project.hook(0x8048d7b, angr.SIM_PROCEDURES["libc"]["strcmp"]())
#project.hook(0x8048d3b, angr.SIM_PROCEDURES["libc"]["strlen"]())

print("Setup angr")

r = r2pipe.open(sys.argv[1])
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

def debug_step():
    num = int(command_global[1])
    for i in range(0, num):
        simgr.step()

def debug_explore_until():
    global state
    global simgr
    global old_state

    if "0x" in command_global[1]:
        addr = int(command_global[1], 16)
    else:
        addr = int(symbol_to_address(command_global[1]), 16)
        
    print("Debug explore until " + hex(addr))
    old_state = state
    #simgr.explore(find=addr)
    simgr.explore(find=addr).unstash(from_stash="found", to_stash="active")
    #if simgr.found:
    if simgr.active:
        print("Found " + str(len(simgr.active)) + " solutions")
        # This would cause problems if only one would work in the future
        #state = simgr.found[0]
        #simgr = project.factory.simgr(state)
    else:
        print("Exploration failed")
        state = old_state
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
    for s in simgr.active:
        try:
            print(s.posix.dumps(0).decode())
        except:
            print(s.posix.dumps(0))

def print_stdout():
    for s in simgr.active:
        try:
            print(s.posix.dumps(1).decode())
        except:
            print(s.posix.dumps(1))

def debug_registers():
    print("rax = " + str(state.regs.rax))
    print("rbx = " + str(state.regs.rbx))
    print("rcx = " + str(state.regs.rcx))
    print("rdx = " + str(state.regs.rdx))
    print("rsi = " + str(state.regs.rsi))
    print("rdi = " + str(state.regs.rdi))
    print("rsp = " + str(state.regs.rsp))
    print("rbp = " + str(state.regs.rbp))
    print("rip = " + str(state.regs.rip))
    

def kill_state():
    addr = int(command_global[1], 16)
    simgr.move(from_stash='active', to_stash='deadended', filter_func=lambda s: s.addr == addr)

def revive_state():
    addr = int(command_global[1], 16)
    simgr.move(from_stash='deadended', to_stash='active', filter_func=lambda s: s.addr == addr)

def debug_initialize():
    global state
    global simgr

    if len(command_global) == 1:
        print("Initializing at entry state")
        state = project.factory.entry_state()
        simgr = project.factory.simgr(state)
    else:
        print("Initializing blank state at " + command_global[1])
        state = project.factory.blank_state(addr=int(command_global[1],16))
        simgr = project.factory.simgr(state)

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
            ("ds", debug_step),
            ("dcub", debug_continue_until_branch),
            ("deu", debug_explore_until),
            ("dr", debug_registers),
            ("ood", debug_initialize),
            ("pd", disass_states),
            ("pi", print_stdin),
            ("po", print_stdout),
            ("kill", kill_state),
            ("revive", revive_state),
            ("i", interactive),
            ("temp", temp),
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

