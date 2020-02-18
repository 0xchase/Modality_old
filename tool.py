#!/usr/bin/python3

import sys

if len(sys.argv) < 2:
    print("Usage: ./tool.py <binary>")
    exit()

import angr
import claripy

sys.path.append("src/")

# Import rest of code base
import stash
from debug import *
from disass import *
from hooks import *
from util import *

print("Imported libraries")

filename = sys.argv[1]
project = angr.Project(filename)
state = project.factory.entry_state()
simgr = project.factory.simgr(state, veritesting=False)

disassembler = Disassembler(filename)
debugger = Debugger(disassembler.functions)

# ========== Initialization code ==========

#@project.hook(0x4007fd, length=0)
#def hook_merge(state):
#    print(colored(" Filtering states", "cyan"))
#    simgr.active = [simgr.active[-1]]

# ========== Initialization code ==========

debugger_commands = [
            ("dc", debugger.debug_continue),
            ("dcu", debugger.debug_continue_until),
            ("ds", debugger.debug_step),
            ("dw", debugger.debug_watch),
            ("dcub", debugger.debug_continue_until_branch),
            ("deu", debugger.debug_explore_until),
            ("deuo", debugger.debug_explore_until_stdout),
            ("dr", debugger.debug_registers),
            ("doo", debugger.debug_initialize)]

disassembler_commands = [
            ("pd", disassembler.disassemble)]

stash_commands = [
            ("sl", stash.list),
            ("sk", stash.kill),
            ("sr", stash.revive),
            ("sra", stash.revive_all),
            ("sn", stash.name),
            ("si", stash.stdin),
            ("sia", stash.stdin_all),
            ("so", stash.stdout),
            ("sfo", stash.filter_stdout),
            ("soa", stash.stdout_all)]

util_commands = [
            ("c", clear),
            ("q", exit)]


def main():
    global simgr
    global debugger
    global project

    while True:
        print(colored("[" + get_addr() + "|", "yellow") + colored(str(len(simgr.deadended)), "red") + colored("]> ", "yellow"), end='')
        command = input().strip().split(" ")

        for cmd, function in debugger_commands:
            if cmd == command[0]:
                debugger.project = project
                debugger.simgr = simgr
                debugger.command = command
                function()
        for cmd, function in disassembler_commands:
            if cmd == command[0]:
                disassembler.simgr = simgr
                disassembler.command = command
                function()
        for cmd, function in stash_commands:
            if cmd == command[0]:
                function(lambda: null, command, simgr)
        for cmd, function in util_commands:
            if cmd == command[0]:
                function()

def get_addr():
    ret = ""
    if len(simgr.active) < 4:
        for s in simgr.active:
            ret += str(hex(s.addr)) + " "
        ret = ret[0:-1]
    else:
        ret += str(len(simgr.active))
    return ret

main()

