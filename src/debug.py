import sys
import claripy
from termcolor import colored

class Debugger():
    def __init__(self, f):
        self.functions = f
        self.watchpoints = {}
    
    def initialize(self, main, f):
        global functions
        functions = f

    def debug_continue(self):
        self.simgr.run()

    def debug_step(self):
        if len(self.command) == 1:
            self.simgr.step()
        else:
            num = int(self.command[1])
            for i in range(0, num):
                self.simgr.step()

    def debug_explore_until(self):
        command = self.command
        simgr = self.simgr
        
        old_active = []
        old_deadended = []

        for state in simgr.active:
            old_active.append(state)

        for state in simgr.deadended:
            old_deadended.append(state)

        if "0x" in command[1]:
            addr = int(command[1], 16)
        else:
            addr = int(self.symbol_to_address(command[1]), 16)

        print("Debug explore until " + hex(addr))
        old_state = state
        simgr.explore(find=addr).unstash(from_stash="found", to_stash="active")

        if simgr.active:
            print(colored("Found " + str(len(simgr.active)) + " solutions", "green"))
        else:
            print(colored("Exploration failed", "red"))

            print("Reverting state (currently a bit buggy)")

            simgr.active = []
            simgr.deadended = []

            for state in old_active:
                simgr.active.append(state)
            for state in old_deadended:
                simgr.deadended.append(state)

    def hook_watchpoint(self, state):
        addr = state.solver.eval(state.regs.rip)
        hit_count, message = self.watchpoints[addr]
        self.watchpoints[addr] = (hit_count + 1, message)
        
        if message == "":    
            print(colored(" [" + str(len(self.simgr.active)) + "|" + colored(str(len(self.simgr.deadended)), "red") + colored("]", "yellow"), "yellow"), colored("{" + str(hit_count) + "}", "cyan"), " Reached watchpoint at " + hex(addr))
        else:
            print(colored(" [" + str(len(self.simgr.active)) + "|" + colored(str(len(self.simgr.deadended)), "red") + colored("]", "yellow"), "yellow"), colored("{" + str(hit_count) + "}", "cyan"), " " + message)

    def debug_watch(self):
        addr = int(self.command[1], 16)
        print("Adding watchpoint at " + hex(addr))
        self.project.hook(addr, self.hook_watchpoint, length=0)

        if len(self.command) >= 3:
            self.watchpoints[addr] = (0, " ".join(self.command[2:]))
        else:
            self.watchpoints[addr] = (0, "")

    def find(self, state):
        return self.find_string in state.posix.dumps(1)

    def avoid(self, state):
        return self.avoid_string in state.posix.dumps(1)

    def debug_explore_until_stdout(self):
        command = self.command
        simgr = self.simgr
        self.find_string = command[1].encode()
        self.avoid_string = command[2].encode()
        simgr.explore(find=self.find, avoid=self.avoid)

        if simgr.active:
            print("Found " + str(len(simgr.active)) + " solutions")
        else:
            print("Exploration failed")
        
        
    
    def debug_continue_until(self):
        print("Debug continue until self, main")
        state.inspect.b("call")
        #simgr.run(until=lambda sm: sm.active[0].addr == 0x400815)
        self.simgr.run()

    def debug_continue_until_call(self):
        print("Debug continue until self, main")
        state.inspect.b("call")
        #simgr.run(until=lambda sm: sm.active[0].addr == 0x400815)
        self.simgr.run()

    def debug_continue_until_branch(self):
        while len(self.simgr.active) == 1:
            self.simgr.step()

    def debug_continue_until_ret(self):
        print("Debug continue until ret")
        self.simgr.run()

    def debug_continue_until_call(self):
        print("Debug continue until call")
        self.simgr.run()


    def debug_registers(self):
        simgr = self.simgr
        state = simgr.active[0] # Temporary hack
        print("rax = " + str(state.regs.rax))
        print("rbx = " + str(state.regs.rbx))
        print("rcx = " + str(state.regs.rcx))
        print("rdx = " + str(state.regs.rdx))
        print("rsi = " + str(state.regs.rsi))
        print("rdi = " + str(state.regs.rdi))
        print("rsp = " + str(state.regs.rsp))
        print("rbp = " + str(state.regs.rbp))
        print("rip = " + str(state.regs.rip))


    def debug_initialize():
        command = self.command
        simgr = self.simgr
        if len(command) == 1:
            print("Initializing at entry state")
            state = project.factory.entry_state()
            simgr = project.factory.simgr(state)
        else:
            print("Initializing blank state at " + command[1])
            state = project.factory.blank_state(addr=int(command[1],16))
            simgr = project.factory.simgr(state)

    def symbol_to_address(self, s):
        for addr, name in self.functions:
            if name == s:
                return addr

