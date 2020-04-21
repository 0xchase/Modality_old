#! /usr/bin/env python3
# Copyright (C) 2017 Chase Kanipe

"""
r2-angr
"""

from __future__ import print_function

import r2lang
import r2pipe
import angr

# Add command to access old mounting commands

r = r2pipe.open()


def r2angr(_):
    """Build the plugin"""

    binary = r.cmdj("ij")["core"]["file"]

    def process(command):
        """Process commands here"""

        if not command.startswith("m"):
            return 0

        if "?" in command:


        # Parse arguments
        tmp = command.split(" ")
        print(str(tmp))

    return {"name": "r2-angr",
            "licence": "GPLv3",
            "desc": "Integrates angr with radare2",
            "call": process}


# Register the plugin
if not r2lang.plugin("core", r2angr):
    print("An error occurred while registering r2angr")

