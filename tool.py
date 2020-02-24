#!/usr/bin/python3

import sys

if len(sys.argv) < 2:
    print("Usage: ./tool.py <binary> <arg count>")
    exit()

import angr
import claripy

sys.path.append("src/")

# Import rest of code base
import stash
from debug import *
from disass import *
from printer import *
from hooks import *
from util import *
from hooks import *

print("Imported libraries")

stdin = claripy.BVS("stdin", 8*16)
argv = []

argv.append(sys.argv[1])
arg_num = 1

if len(sys.argv) == 3:
    arg_num = int(sys.argv[2])

print(str(argv))

filename = sys.argv[1]
project = angr.Project(filename)
state = project.factory.entry_state(args=argv, stdin=stdin)
simgr = project.factory.simgr(state, veritesting=False)


#for i in range(0, arg_num):
#    for b in argv[-1].chop(8):
#        state.solver.And(b >= ord(' '), b <= ord('~'))

def initialize(pr, st, si):
    global project
    global state
    global simgr

    project = pr
    state = st
    simgr = si

disassembler = Disassembler(filename)
debugger = Debugger(disassembler.functions)
printer = Printer()
hooks = Hooks()
hooks.setup_loops(angr, project, simgr, filename, colored)
hooks.functions = disassembler.functions
hooks.library_functions = disassembler.library_functions
hooks.setup_functions()

#for b in stdin.chop(8):
#    state.solver.And(b >= ord(' '), b <= ord('~'))

for b in stdin.chop(8):
    #state.solver.add(b > 0x20)
    #state.solver.add(b < 0x7f)
    state.solver.add(b > 43)
    state.solver.add(b < 127)

# ========== Initialization code ==========

#@project.hook(0x4007fd, length=0)
#def hook_merge(state):
#    print(colored(" Filtering states", "cyan"))
#    simgr.active = [simgr.active[-1]]

# ========== Initialization code ==========

debugger_commands = [
            ("dc", debugger.debug_continue),
            ("dcu", debugger.debug_continue_until),
            ("dco", debugger.debug_continue_output),
            ("ds", debugger.debug_step),
            ("dw", debugger.debug_watch),
            ("dcb", debugger.debug_continue_until_branch),
            ("deu", debugger.debug_explore_until),
            ("deul", debugger.debug_explore_until_loop),
            ("del", debugger.debug_explore_loop),
            ("deud", debugger.debug_explore_until_dfs),
            ("deo", debugger.debug_explore_stdout),
            ("dr", debugger.debug_registers),
            ("doo", debugger.debug_initialize)]

disassembler_commands = [
            ("pd", disassembler.disassemble)]

stash_commands = [
            ("sl", stash.list),
            ("sk", stash.kill),
            ("sko", stash.kill_stdout),
            ("ska", stash.kill_all),
            ("sr", stash.revive),
            ("sro", stash.revive_stdout),
            ("sra", stash.revive_all),
            ("sn", stash.name),
            ("si", stash.stdin),
            ("sia", stash.stdin_all),
            ("so", stash.stdout),
            ("soa", stash.stdout_all)]

print_commands = [
            ("pa", printer.args),
            ("paa", printer.args_all),
            ("po", printer.stdout),
            ("poa", printer.stdout_all),
            ("pi", printer.stdin),
            ("pia", printer.stdin_all)]

util_commands = [
            ("c", clear),
            ("q", exit)]


def command_line():
    global simgr
    global debugger
    global project
    global argv
    global hooks

    while True:
        print(colored("[" + get_addr() + "|", "yellow") + colored(str(len(simgr.deadended)), "red") + colored("]> ", "yellow"), end='')
        command = input().strip().split(" ")

        for cmd, function in debugger_commands:
            if cmd == command[0]:
                debugger.project = project
                debugger.simgr = simgr
                debugger.command = command
                debugger.filename = filename
                debugger.angr = angr
                debugger.loop_entry_addrs = hooks.loop_entry_addrs
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
        for cmd, function in print_commands:
            if cmd == command[0]:
                printer.command = command
                printer.argv1 = argv
                printer.simgr = simgr
                printer.stdin = stdin
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

if __name__ == "__main__":
    command_line()
