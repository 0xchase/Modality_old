#!/usr/bin/python3

import angr
import claripy

def main():
	proj = angr.Project('hashmenot', auto_load_libs=False)
	
	flag_chars = [claripy.BVS('%d' % i, 32) for i in range(32)]
	
	class my_scanf(angr.SimProcedure):
		def run(self, fmt, ptr):
			self.state.mem[ptr].dword = flag_chars[self.state.globals['scanf_count']]
			self.state.globals['scanf_count'] += 1

	proj.hook_symbol('__isoc99_scanf', my_scanf(), replace=True)

	sm = proj.factory.simulation_manager()
	sm.one_active.options.add(angr.options.LAZY_SOLVES)
	sm.one_active.globals['scanf_count'] = 0

	sm.explore(find=0x400a2b)

	flag = ''.join(chr(sm.one_found.solver.eval(c)) for c in flag_chars)

	print("Flag: " + flag)

main()
