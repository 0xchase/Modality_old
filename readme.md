# Modality Debugger

This project is in it's early stages and will only work on some binaries.
---
# Todo
## Debugger
 - Add avoid commands
 - PEDA like view for debugging. Commands to print regs and stack

## Hooks
 - When hooking function calls, print args
 - When hit calls like strlen(), choose to simulate or constrain

## State
 - Track history for each state (currently not working)

## Dissassembler
 - Replace radare2 calls with capstone

## Other
 - Get working as scripting engine
 - Clean up code

## Pre-built hooks
 - Check for string equality

## Pre-built constraints
 - Constrain on strlen()

## Other goals
 - Scripting ability. Works like normal angr script, but can enter debug mode
 - Eventually turn into r2 plugin, with commands to control execution
 - Hook memory writes, returns, etc

