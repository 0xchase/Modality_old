import claripy

class Printer():
    def __init__(self):
        pass

    def args(self):
        for s in self.simgr.active:
            for i in range(1, len(self.argv1)):
                print(str(self.argv1[i]) + ": ", end='')
                result = s.solver.eval(self.argv1[i], cast_to=bytes)
                self.print_decode(result)

    def args_all(self):
        for s in self.simgr.active + self.simgr.deadended:
            for i in range(1, len(self.argv1)):
                result = s.solver.eval(self.argv1[i], cast_to=bytes)
                self.print_decode(result)

    def stdout(self):
        if len(self.command) == 1:
            for state in self.simgr.active:
                self.print_decode(state.posix.dumps(1))

    def stdin(self):
        if len(self.command) == 1:
            for state in self.simgr.active:
                self.print_decode(state.posix.dumps(0))
        else:
            self.print_decode(self.simgr.active[int(command[1])].posix.dumps(0))

    def stdout_all(self):
        if len(self.command) == 1:
            for state in self.simgr.active + self.simgr.deadended:
                self.print_decode(state.posix.dumps(1))

    def stdin_all(self):
        if len(self.command) == 1:
            for state in self.simgr.active + self.simgr.deadended:
                self.print_decode(state.posix.dumps(0))
        else:
            self.print_decode(self.simgr.active[int(command[1])].posix.dumps(0))

    def print_decode(self, s):
        try:
            print(s.decode())
        except:
            print(str(s))
