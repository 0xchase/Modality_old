#!/usr/bin/python3

import angr
import claripy

project = angr.Project("challenges/hashmenot")
state = project.factory.entry_state()
simgr = project.factory.simgr(state)

simgr.explore(find=0x4009ad)


