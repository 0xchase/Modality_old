import angr
import claripy

class Project():
    def __init__(self, filename, arg_num=0):
        self.filename = filename

        argv = []
        argv.append(filename)
        sym_arg_size = 40
        for i in range(0, arg_num):
            sym_arg = claripy.BVS('sym_arg', 8*sym_arg_size)
            argv.append(sym_arg)

        self.argv = argv
        self.project = angr.Project(self.filename)
        #self.state = self.project.factory.entry_state(add_options=angr.options.unicorn)
        self.state = self.project.factory.entry_state(args=argv)
        self.simgr = self.project.factory.simgr(self.state)
