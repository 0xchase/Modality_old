
#project.hook(0x8048d7b, angr.SIM_PROCEDURES["libc"]["strcmp"]())
#project.hook(0x8048d3b, angr.SIM_PROCEDURES["libc"]["strlen"]())

#state.inspect.b("call", hit_call)
#state.inspect.b("return", hit_return)

class Analysis():
    
    def a(self):
        print("Function call analysis")

    def aa(self):
        print("Function call and loops analysis")

    def aaa(self):
        print("Function call, loops, and memory r/w analysis")

        for state in self.simgr.active:
            print("Adding read hooks to state")
            state.inspect.b("mem_read", when=self.angr.BP_AFTER, action=self.hook_read)

    def hook_read(self, state):
        print("Hooked READ at " + str(state.inspect.mem_read_expr) + " from " + str(state.inspect.mem_read_address))
        

