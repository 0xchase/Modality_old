import sys

class Debugger():
    def __init__(self, f):
        self.functions = f
    
    def initialize(self, main, f):
        global functions
        functions = f

    def debug_continue(self, main, command, simgr):
        simgr.run()

    def debug_step(self, main, command, simgr):
        num = int(command[1])
        for i in range(0, num):
            simgr.step()

    def debug_explore_until(self, main, command, simgr):
        state = simgr.active[0]

        if "0x" in command[1]:
            addr = int(command[1], 16)
        else:
            addr = int(self.symbol_to_address(command[1]), 16)

        print("Debug explore until " + hex(addr))
        old_state = state
        simgr.explore(find=addr).unstash(from_stash="found", to_stash="active")

        if simgr.active:
            print("Found " + str(len(simgr.active)) + " solutions")
        else:
            print("Exploration failed")
            state = old_state
            simgr = project.factory.simgr(state)

    def debug_continue_until(self, main, command, simgr):
        print("Debug continue until self, main")
        state.inspect.b("call")
        #simgr.run(until=lambda sm: sm.active[0].addr == 0x400815)
        simgr.run()

    def debug_continue_until_call(self, main, command, simgr):
        print("Debug continue until self, main")
        state.inspect.b("call")
        #simgr.run(until=lambda sm: sm.active[0].addr == 0x400815)
        simgr.run()

    def debug_continue_until_branch(self, main, command, simgr):
        while len(simgr.active) == 1:
            simgr.step()

    def debug_continue_until_ret(self, main, command, simgr):
        print("Debug continue until ret")
        simgr.run()

    def debug_continue_until_call(self, main, command, simgr):
        print("Debug continue until call")
        simgr.run()


    def debug_registers(self, main, command, simgr):
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


    def debug_initialize(self, main, command, simgr):
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

