#!/usr/bin/python3

import angr
import claripy
from termcolor import colored
import os

os.system("clear")
# Automatically hook after malloc, stating return buffer
# Use Pypy for speedup

def run_until_branch(simgr):
    simgr.run(until=lambda sm: len(sm.active) > 1)

def main():
    proj = angr.Project("hashmenot", auto_load_libs=False) 

    class my_scanf(angr.SimProcedure):
        def run(self, fmt, ptr):
            print(colored("Hooked scanf", "yellow"))
            return 1
    class ret_zero(angr.SimProcedure):
        def run(self, fmt, ptr):
            print(colored("Hooked a call... returning zero", "yellow"))
            return 0
    class my_printf(angr.SimProcedure):
        def run(self, s):
            print(colored("Hooked printf()", "yellow"))
            print(str(self.state.memory.load(s)))
            return 0
    class my_strlen(angr.SimProcedure):
        def run(self, s):
            print(colored("Hooked strlen()", "yellow"))
            return 11
    class my_strncat(angr.SimProcedure):
        def run(self, dst, src, n):
            print(colored("Hooked strncat()", "yellow"))
            strlen = n
            strncpy = angr.SIM_PROCEDURES['libc']['strncpy']
            src_len = self.inline_call(strlen, src).ret_expr
            dst_len = self.inline_call(strlen, dst).ret_expr
            self.inline_call(strncpy, dst + dst_len, src, src_len+1, src_len=src_len)
            return dst
    class my_fgets(angr.SimProcedure):
        def run(self, s, size, stream):
            print(colored("Hooked fgets()", "yellow"))
            self.state.memory.store(s, "testdata12\n".encode())
            return s
    class my_sprintf(angr.SimProcedure):
        def run(self, s, f):
            print("Hooked sprintf()")
    class my_strncat(angr.SimProcedure):
        def run(self, s1, s2, n):
            print("Hooked strncat()")
    

    #proj.hook_symbol('__isoc99_scanf', my_scanf(), replace=True)
    #proj.hook_symbol('sprintf', my_sprintf(), replace=True)
    proj.hook_symbol('strlen', my_strlen(), replace=True)
    proj.hook_symbol('strncat', my_strncat(), replace=True)
    proj.hook_symbol('fflush', ret_zero(), replace=True)
    proj.hook_symbol('printf', my_printf(), replace=True)
    #proj.hook_symbol('strncat', my_strncat(), replace=True)
    #proj.hook_symbol('fgets', my_fgets(), replace=True)

    @proj.hook(0x4008d6, length=0)
    def my_main(state):
        #print("Running main with argc=%s and argv=%s" % (argc, argv))
        print(colored("Running main()", "yellow"))
    @proj.hook(0x400923, length=0)
    def after_fgets(state):
        #print("Running main with argc=%s and argv=%s" % (argc, argv))
        print(colored("Hooked after fgets()", "yellow"))
    @proj.hook(0x400948, length=0)
    def after_strlen(state):
        #print("Running main with argc=%s and argv=%s" % (argc, argv))
        print(colored("Hooked after strlen()", "yellow"))
        print(colored(str(state.regs.rax),"yellow"))
    @proj.hook(0x4009e9, length=0)
    def make_it_here(state):
        #print("Running main with argc=%s and argv=%s" % (argc, argv))
        #print(colored("Looped the hash", "yellow"))
        pass

    flag1 = claripy.BVS("flag1", 8*11)
    state = proj.factory.entry_state(stdin=flag1, add_options={angr.options.LAZY_SOLVES, angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY})
    #state = proj.factory.entry_state(stdin=flag1, add_options={angr.options.LAZY_SOLVES})

    for byte in flag1.chop(8):
        state.add_constraints(byte >= '\x20') # ' '
        state.add_constraints(byte <= '\x7e') # '~' \x7e

    simgr = proj.factory.simgr(state)
    #simgr.run()

    #sm.one_active.options.add(angr.options.LAZY_SOLVES)
    #sm.one_active.globals['scanf_count'] = 0

    simgr.explore(find=0x400a2b, avoid=[0x40095c, 0x400928, 0x400a06])
    if simgr.found:
        print(colored(str(simgr.found[0].posix.dumps(0).decode()), "green"))
    else:
        print("No solution found")


main()
