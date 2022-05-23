#!/usr/bin/env python3
import sys

remove_lines = {}
add_lines = {}
iwyu_file_lines = []


class bcolors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"

    def disable(self):
        self.HEADER = ""
        self.OKBLUE = ""
        self.OKGREEN = ""
        self.WARNING = ""
        self.FAIL = ""
        self.ENDC = ""


def read_file(filename):
    with open(filename, "r") as iwyu_output:
        iwyu_file_lines = iwyu_output.readlines()
        return iwyu_file_lines


def clear_input(file_lines):
    strip_lines = []

    for line in file_lines:
        strip_lines.append(line.strip("\n"))

    return strip_lines


def get_headers(file_lines, add_or_remove, data_dict):
    last_file = ""
    check_next_line = False

    for line in file_lines:

        if check_next_line == True:
            if line == "":
                check_next_line = False
                continue

            hashtag_pos = line.find("#")
            greater_pos = line.find(">")
            doubleq_pos = line.rfind('"')
            struct_pos = line.find("struct")

            # The header can be included using <>
            if greater_pos != -1:
                data_dict[last_file].append(line[hashtag_pos : greater_pos + 1])

            # The header can be included using ""
            if doubleq_pos != -1:
                data_dict[last_file].append(line[hashtag_pos : doubleq_pos + 1])

            if struct_pos != -1:
                data_dict[last_file].append(line)

        if add_or_remove in line:
            check_next_line = True
            last_file = line.split(" ")[0]
            data_dict[last_file] = []


def pretty_print_files(remove_lines, add_lines):

    report_error = False
    for file, headers in remove_lines.items():
        if headers == []:
            continue

        report_error = True
        print(bcolors.OKBLUE + f"Remove these headers from {file}" + bcolors.ENDC)

        for header in headers:
            print(bcolors.FAIL + header + bcolors.ENDC)

    for file, headers in add_lines.items():
        if headers == []:
            continue

        report_error = True
        print(bcolors.OKBLUE + f"Add these headers in {file}" + bcolors.ENDC)

        for header in headers:
            print(bcolors.OKGREEN + header + bcolors.ENDC)

    return report_error


iwyu_file_lines = read_file("iwyu_output.txt")
iwyu_file_lines = clear_input(iwyu_file_lines)
get_headers(iwyu_file_lines, "remove", remove_lines)
get_headers(iwyu_file_lines, "add", add_lines)

if pretty_print_files(remove_lines, add_lines) == True:
    print("Please fix the errors reported in red or green!")
    sys.exit(1)

sys.exit(0)
