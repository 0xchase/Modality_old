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
from project import *
from hooks import *

# Change projects to be a file in master directory, not a class

print("Imported libraries")

argc = len(sys.argv)
if(argc == 2):
    project = Project(sys.argv[1])
else:
    project = Project(sys.argv[1], int(sys.argv[2]))


disassembler = Disassembler(project.filename)
debugger = Debugger(disassembler.functions)

debugger_commands = [
            ("dc", debugger.debug_continue),
            ("dcu", debugger.debug_continue_until),
            ("ds", debugger.debug_step),
            ("dcub", debugger.debug_continue_until_branch),
            ("deu", debugger.debug_explore_until),
            ("deuo", debugger.debug_explore_until_stdout),
            ("dr", debugger.debug_registers),
            ("doo", debugger.debug_initialize),
            ("pd", disassembler.disassemble)]

stash_commands = [
            ("sl", stash.list),
            ("sk", stash.kill),
            ("sr", stash.revive),
            ("sn", stash.name),
            ("si", stash.stdin),
            ("sia", stash.stdin_all),
            ("so", stash.stdout),
            ("soa", stash.stdout_all)]

util_commands = [
            ("q", exit)]


def eval_sym(command, project):
    num = int(command[1])
    for i in project.simgr.deadended:
        result = i.solver.eval(project.argv[num], cast_to=bytes)
        print(result)


extra = [
            ("eval", eval_sym)
        ]

def main():
    global project

    while True:
        print("[" + get_addr() + "|" + str(len(project.simgr.deadended)) + "]> ", end='')
        command = input().strip().split(" ")

        for cmd, function in debugger_commands:
            if cmd == command[0]:
                function(lambda: null, command, project.simgr)
        for cmd, function in stash_commands:
            if cmd == command[0]:
                function(lambda: null, command, project.simgr)
        for cmd, function in util_commands:
            if cmd == command[0]:
                function()
        for cmd, function in extra:
            if cmd == command[0]:
                eval_sym(command, project)
                #function(lambda: command, project)


def get_addr():
    ret = ""
    if len(project.simgr.active) < 4:
        for s in project.simgr.active:
            ret += str(hex(s.addr)) + " "
        ret = ret[0:-1]
    else:
        ret += str(len(project.simgr.active))
    return ret

main()

