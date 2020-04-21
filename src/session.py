#!/usr/bin/python3

import angr
import claripy

from debug import *
from disass import *
from printer import *
from hooks import *
from util import *
from analysis import *

class Session():

    def __init__(self, binary):
        print("Initialized r2-angr")
        self.binary = binary
        self.project = angr.Project(binary)
        self.simgr = self.project.factory.simgr()

    def run(self, command):
        print("Running command: " + command)
