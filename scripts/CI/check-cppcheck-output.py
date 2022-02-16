#!/usr/bin/env python3

import os
import sys


# Checks the output of cppcheck if a problem is emitted and fails the CI job in case of detection.
def main():
    count_problems = 0
    cppcheck_checks = [
        "warning",
        "style",
        "performance",
        "portability",
        "information",
        "unusedFunction",
    ]
    with open("log.txt", "r") as cppcheck_out:
        for line in cppcheck_out.readlines():
            for check in cppcheck_checks:
                if check in line:
                    count_problems += 1

    exit_code = 0
    if count_problems != 0:
        print(f"Number of cppcheck problems to fix = {count_problems}")
        exit_code = 1

    os.remove("log.txt")
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
