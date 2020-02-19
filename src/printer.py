import claripy

class Printer():
    def __init__(self):
        pass

    def args(self):
        for s in self.simgr.active:
            for i in range(1, len(self.args)):
                result = s.solver.eval(self.args[i], cast_to=bytes)
                try:
                    print(result.decode())
                except:
                    print(str(result))
