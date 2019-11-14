#!/usr/bin/python3

# Scripting engine for this script. Lines of commands.

import angr
import claripy
import copy

address = 0x000000

#project = angr.Project("hashme", auto_load_libs=False)
project = angr.Project("hashme", use_sim_procedures=True)

flag = claripy.BVS('flag', 11*8)

state = project.factory.entry_state(stdin=flag)
simgr = project.factory.simgr(state)

def main():
    global simgr
    global state

    update_addr()

    while True:
        print("[" + hex(address) + "]> ", end='')
        cmd = input().strip().split(" ")
        if cmd[0] == "dcu":
            print("Continue until")
        if cmd[0] == "de":
            simgr.explore(find=0x400970, avoid=(0x400928, 0x40095c, 0x400a06))
            #temp_state = copy.deepcopy(state)
            if simgr.found:
                print("Found " + str(len(simgr.found)) + " solutions")
                print(str(simgr.found[0].solver.eval(flag, cast_to=bytes)))
            else:
                print("Didn't find solution... reverting state")
                #state = temp_state
        if cmd[0] == "dc":
            simgr.run(until=lambda sm: sm.active[0].addr == 0x4008d6)
        if cmd[0] == "ds":
            simgr.step()
        if cmd[0] == "di":
            state = project.factory.entry_state()
            simgr = project.factory.simgr(state)
        if cmd[0] == "q":
            exit()

        update_addr()

def update_addr():
    global address
    try:
        address = simgr.active[0].addr
    except:
        address = 0x0

main()

