# Modality Debugger

This project is in it's early stages and will only work on some binaries.

## Example
```
terminal:~# ./tool.py challenges/lockpicksim
Imported libraries
r_config_set: variable 'asm.cmtright' not found
[0x400600|0]> deu main
Debug explore until 0x4006f6
Found 1 solutions
[0x4006f6|0]> dcub
WARNING | 2020-02-16 17:55:19,360 | angr.state_plugins.symbolic_memory | The program is accessing memory or registers with an unspecified value. This could indicate unwanted behavior.
WARNING | 2020-02-16 17:55:19,360 | angr.state_plugins.symbolic_memory | angr will cope with this by generating an unconstrained symbolic variable and continuing. You can resolve this by:
WARNING | 2020-02-16 17:55:19,360 | angr.state_plugins.symbolic_memory | 1) setting a value to the initial state
WARNING | 2020-02-16 17:55:19,360 | angr.state_plugins.symbolic_memory | 2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to make unknown regions hold null
WARNING | 2020-02-16 17:55:19,360 | angr.state_plugins.symbolic_memory | 3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY_REGISTERS}, to suppress these messages.
WARNING | 2020-02-16 17:55:19,361 | angr.state_plugins.symbolic_memory | Filling memory at 0x7ffffffffff0000 with 64 unconstrained bytes referenced from 0x10a27e0 (strlen+0x0 in libc.so.6 (0xa27e0))
WARNING | 2020-02-16 17:55:19,362 | angr.state_plugins.symbolic_memory | Filling memory at 0x7fffffffffeff70 with 8 unconstrained bytes referenced from 0x10a27e0 (strlen+0x0 in libc.so.6 (0xa27e0))
[0x4008a0 0x4008ca|0]> pd
-----------------------------------------------------------  -----------------------------
cmp dword [var_2ch], 1                                       mov edi, str.Wrong
jne 0x4008ca                                                 call sym.imp.puts
lea rax, [var_20h]                                           mov eax, 1
mov rdi, rax                                                 mov rsi, qword [var_8h]
call sym.imp.atoi                                            xor rsi, qword fs:[0x28]
mov esi, eax                                                 je 0x4008ed
mov edi, str.Correct__Flag:_UMDCTF__you_p1cked__d_correctly  call sym.imp.__stack_chk_fail
mov eax, 0                                                   leave
call sym.imp.printf                                          ret
mov eax, 0                                                   nop
-----------------------------------------------------------  -----------------------------
[0x4008a0 0x4008ca|0]> sk 1
[0x4008a0|1]> dc
[|3]> pia
[|3]> sia
b'\xf5\xf5\xf5\xf4\x00'
04800
4801>
[|3]> 
```
# Design ideas

## Pre-built hooks
 - Check for string equality

## Pre-built inspect calls
 - Print on function call with args

## Pre-built constraints
 - Constrain on strlen()

## Other goals
 - Scripting ability. Works like normal angr script, but can enter debug mode
 - Eventually turn into r2 plugin, with commands to control execution

# Commands
## Debug commands
 - d: Print debug help menu
 - di: Debugger info
 - ds: Debugger step
 - dso: Debugger step over
 - dr: Print registers
 - dc: Continue
 - dcu: Continue until address
 - de: Explore
 - dei: Explore info (find addresses, avoid addresses)
 - de+: Add avoid address
 - de-: Remove avoid address
 - de--: Remove all avoid addresses

## Stash commands
 - s: Print stash help menu
 - sk: Kill state in stash
 - sr: Revive state in stash
 - sp: Print details about items in stash

## Constraint commands
 - ca: Constrain avoids list
 - ca+: Constrain add avoid
 - ca-: Constrain remove avoids
 - ca--: Constrain remove all avoids

## Dissassembly commands
 - pd: Disassemble n bytes
 - pdf: Disassemble function

## Other notes
 Hook memory writes, returns, etc with breakpoints to print what is happening
 Manager for moving and storing different simgr states
 When hit calls like strlen(), choose to simulate or constrain
 in state, add_options=angr.options.unicorn
 Command to generate angr script from command history
 Backwards slicing and backtracing for stash
 Print stdout as it executes
 Replace radare2 calls with capstone


