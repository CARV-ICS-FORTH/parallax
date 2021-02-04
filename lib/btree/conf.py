#!/usr/bin/python3
import os


def options(flag, confh):
    tosearch = [
        "#define LEVEL0_TOTAL_SIZE",
        "#define INSERT_TO_INDEX ",
        "#define NUMBER_OF_DATABASES ",
        "#define ZERO_LEVEL_MEMORY_SPILL_THREASHOLD",
    ]

    tobereplaced = [
        "#define LEVEL0_TOTAL_SIZE GB(2)\n",
        "#define INSERT_TO_INDEX 1\n",
        "#define NUMBER_OF_DATABASES (4)\n",
        "#define ZERO_LEVEL_MEMORY_SPILL_THREASHOLD (0.1 * ZERO_LEVEL_MEMORY_UPPER_BOUND)\n",
    ]

    for i in range(len(tosearch)):
        if tosearch[i] in flag:
            confh.write(tobereplaced[i])
            return

    confh.write(flag)


def main():

    confh = open(
        "conf.h", "r+"
    )  # Initial conf.h that will be changed to meet the tests requirements
    confh2 = open("conf2.h", "w")  # The final file with the configuration for the tests

    for line in confh:
        options(line, confh2)

    os.system("mv conf2.h conf.h")


main()
