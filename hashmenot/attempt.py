#!/usr/bin/python3
import angr

project = angr.Project("hashmenot", auto_load_libs=False)

@project.hook(0x400a2b)
def print_flag(state):
    print("FLAG SHOULD BE:", state.posix.dumps(0))
    project.terminate_execution()

project.execute()
