# Modality Debugger

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
 - 

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

