import argparse
import enum
import sys


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


class Op(enum.Enum):
    PUT = 1
    GET = 2
    NONE = 3


# create an argparser for the checker
# checker required a 'file' argument
def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Execute tracer with appropriate parameters"
    )
    parser.add_argument("file", type=str, help="tracefile to be parsed")
    return parser.parse_args()


# return the operation based on the current line
def get_op(line_list):
    if line_list[0] == "PUT":
        return Op.PUT
    elif line_list[0] == "GET":
        return Op.GET
    else:
        return Op.NONE


# Validate that the get operation follows the GET KEY_SIZE KEY format
# if not throw an error and exit
def validate_get_op_format(line_list):
    key_size = int(line_list[1])
    key = line_list[2]
    if key_size != len(key):
        print(colors.RED + "key " + key + " is not valid" + colors.ENDC)
        print("Exiting..")
        sys.exit(1)


# Validate that the put operation follows the PUT KEY_SIZE KEY VALUE_SIZE
# if not throw an error and exti
def validate_put_op_format(line_list):
    key_size = int(line_list[1])
    key = line_list[2]
    value_size = int(line_list[3])

    if key_size != len(key):
        print(colors.RED + "key " + key + " is not valid" + colors.ENDC)
        print("Exiting..")
        sys.exit(1)


# validate that the line follows a certain pattern
# pattern is:
# OP = PUT -> PUT KEY_SIZE KEY VALUE_SIZE VALUE
# OP = GET -> GET KEY_SIZE KEY
def validate_line(line):
    str_line_list = line.split()
    op = get_op(str_line_list)
    if op == Op.PUT:
        validate_put_op_format(str_line_list)
    elif op == Op.GET:
        validate_get_op_format(str_line_list)
    else:
        print(
            colors.RED
            + "Invalid operation: "
            + str_line_list[0]
            + " in tracefile"
            + colors.ENDC
        )
        print("Exiting..")
        sys.exit(1)


# return the number of lines in the file, located in filename
def count_lines(filename):
    tracefile = open(filename, "r")
    line = tracefile.readline()
    count = 1
    while line:
        count += 1
        line = tracefile.readline()
    tracefile.close()
    return count


# process each line of the file and validate that all the lines are following
# the operation appropirate's format,
def validate_tracefile(args):
    filename = args.file
    number_of_lines = count_lines(filename)

    tracefile = open(filename, "r")
    line = tracefile.readline()
    line_count = 1
    while line:
        # last line may be incomplete if this is a tracefile from a bug
        if line_count != number_of_lines - 1:
            validate_line(line)
        line = tracefile.readline()
        line_count += 1

    tracefile.close()


def main():
    args = parse_arguments()
    validate_tracefile(args)
    print(colors.GREEN + "tracefile is valid!" + colors.ENDC)


if __name__ == "__main__":
    main()
