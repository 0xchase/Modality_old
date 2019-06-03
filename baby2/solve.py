#!/usr/bin/python3
import angr
import IPython
import claripy

proj = angr.Project("baby2")
s = proj.factory.entry_state(args=[claripy.BVS('arg_1',50*8)])

simgr = proj.factory.simgr(s)
print(simgr.explore(find=lambda s: b"Correct" in s.posix.dumps(1)))

#print(simgr.deadended[0].posix.dumps(0))
#print(simgr.deadended[0].posix.dumps(1))
IPython.embed()

