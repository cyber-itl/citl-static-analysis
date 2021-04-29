#!/usr/bin/env python3

import magic
import os
import sys
import json
import subprocess
import copy
from argparse import ArgumentParser

analyzer = ["citl-static-analysis", "-nopretty_print", "-nolog_prefix", "-all_analyzers", "-logtostderr", "-binfile", ""]

parser = ArgumentParser(prog='Process a directory of binaries with the citl-static-analysis tool')

parser.add_argument('-d', '--dir',
    type=str,
    default=None,
    required=True,
    help='Input directory')
parser.add_argument('-o', '--data-output',
    type=str,
    default=None,
    required=True,
    help='Data output file (text file, one json blob per line)')
parser.add_argument('-e', '--err-output',
    type=str,
    default=None,
    required=False,
    help='Stderr output file')


args = parser.parse_args()

stdout_path = args.data_output
if args.err_output:
    stderr_path = args.err_output
else:
    stderr_path = "/dev/null"

if args.err_output and os.path.exists(stderr_path):
    os.remove(stderr_path)

if os.path.exists(stdout_path):
    os.remove(stdout_path)

stderr_fd = open(stderr_path, "a")
stdout_fd = open(stdout_path, "a")

for root, dirs, walkfiles in os.walk(args.dir):
    for name in walkfiles:
        target_file = os.path.join(root, name)

        try:
            mime = magic.from_file(target_file, mime=True)
        except:
            print(f"Failed to open: {target_file}")
            continue

        cur_analyzer = copy.copy(analyzer)
        cur_analyzer[-1] = target_file

        if mime == "application/x-executable" or mime == "application/x-sharedlib" or mime == "application/x-mach-binary" or mime == "application/x-dosexec":
            stderr_fd.write(f"target: {target_file}\n")
            stderr_fd.flush()
            print(f"target: {target_file}")
            p = subprocess.Popen(cur_analyzer, stdout=stdout_fd, stderr=stderr_fd)

            p.wait()

            if p.returncode != 0:
                print(f"File {target_file} failed with retcode: {p.returncode}")

        else:
            stderr_fd.write(f"Unknown mime: {mime}\n")
            stderr_fd.flush()
            continue

stderr_fd.close()
stdout_fd.close()
