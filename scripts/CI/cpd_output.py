#!/usr/bin/env python3

import os
import sys
import argparse


class colors:
    RED = "\033[31m"
    ENDC = "\033[m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    PURPLE = "\033[35m"
    LIGHT_BLUE = "\033[36m"


def change_color(color):
    if color == colors.RED:
        color = colors.YELLOW
    elif color == colors.YELLOW:
        color = colors.BLUE
    elif color == colors.BLUE:
        color = colors.PURPLE
    elif color == colors.PURPLE:
        color = colors.LIGHT_BLUE
    elif color == colors.LIGHT_BLUE:
        color = colors.RED

    return color


def format_output(output):

    color = colors.RED

    for line in output:
        # standard output substring for duplicate info line
        if "duplication in the following files:" in line:
            print(colors.RED + line.rstrip("\n") + colors.ENDC)

        # standard output substring for the files contating the duplication
        elif "Starting at line" in line:
            print(color + line.rstrip("\n") + colors.ENDC)
            color = change_color(color)

        # seperating line of duplicates. reset
        elif "========" in line:
            print("\n")
            color = colors.RED
            continue
        # code lines
        else:
            print(colors.GREEN + line.rstrip("\n") + colors.GREEN)


# find how many duplicates there are, can be 0
def calculate_number_of_duplicates(output):
    num_of_duplicates = 0
    for line in output:
        if "duplication in the following files:" in line:
            num_of_duplicates += 1

    return num_of_duplicates


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Execute cpd with aprropriate parameters"
    )
    parser.add_argument("tokens", type=int, help="describes duplicates' minimum length")
    parser.add_argument(
        "files",
        type=str,
        nargs="+",
        help="directories where cpd will execute on, could be more that one",
    )
    parser.add_argument(
        "language", type=str, help="defines the language of the source code"
    )
    return parser.parse_args()


def check_for_duplicate_code(args):
    cpd_bin = "pmd-cpd"
    minimum_tokens_param = str(args.tokens)
    files_param = ""

    for file in args.files:

        files_param += "--dir " + file + " "

    language_param = args.language

    cpd_command = f"{cpd_bin} --minimum-tokens {minimum_tokens_param} {
        files_param} --language {language_param}"
    cpd_command = f"{
        cpd_command} --exclude ./lib/btree/dynamic_leaf.c --exclude ./lib/btree/index_node.c"
    stream = os.popen(cpd_command)
    output = stream.readlines()

    format_output(output)
    return calculate_number_of_duplicates(output), output


# Return codes
# 0 -> 0 duplicates good exit
# 1 -> cpd command failed (bad argument etc.)
# 4 -> found duplicates
def main():

    args = parse_arguments()

    return_value, output = check_for_duplicate_code(args)

    if return_value == 0:
        # if the output-list is empty then we have 0 duplicates
        if len(output) == 0:
            sys.exit(0)
        # else output contains error code while parsing command, cpd command failed
        else:
            sys.exit(1)

    sys.exit(4)


if __name__ == "__main__":
    main()
