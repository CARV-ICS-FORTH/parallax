#!/bin/python3
import argparse
import os
import sys

from colorama import Fore, Style
from scanf import scanf


def getArgs():
    """Creates the command line arguments to be used. """

    parser = argparse.ArgumentParser(
        description="Performs inserts,deletes,find,updates based on cmdline arguments."
    )

    parser.add_argument(
        "--insert", type=int, dest="insert", help="Number of keys to insert."
    )
    parser.add_argument(
        "--delete", type=int, dest="delete", help="Number of keys to delete."
    )
    parser.add_argument(
        "--deletekey",
        type=int,
        dest="deletekey",
        help="Deletes the key passed as argument.",
    )
    parser.add_argument(
        "--find", type=int, dest="find", help="Number of keys to search."
    )
    parser.add_argument(
        "--findkey",
        type=int,
        dest="findkey",
        help="Searches the key passed as argument.",
    )
    parser.add_argument(
        "--update", type=int, dest="update", help="Number of keys to update."
    )
    parser.add_argument(
        "--no-sbdu",
        dest="sbdu",
        action="store_false",
        default=True,
        help="Do not search all keys before performing deletes or updates.",
    )

    return parser.parse_args()


def sanitize(args):
    """Checks command line arguments for invalid inputs. """

    if (
        args.insert
        is args.find
        is args.update
        is args.delete
        is args.deletekey
        is args.findkey
        is None
    ):
        print("You must perform at least one operation insert, find, update or delete.")
        print("Exiting...")
        sys.exit()

    if args.insert is not None and args.insert < 1:
        print("Error give a positive number for inserts")
        sys.exit()

    if args.delete is not None and args.delete < 1:
        print("Error give a positive number for deletes")
        sys.exit()

    if args.find is not None and args.find < 1:
        print("Error give a positive number for finds")
        sys.exit()

    if args.update is not None and args.update < 1:
        print("Error give a positive number for updates")
        sys.exit()


def parseKeys():
    """Returns a list with all the key-value pairs
    insert microbenchmark performed. """
    keyValues = []
    file = open("keys.txt", "r")
    for line in file:
        if "Parse" in line:
            break

    for line in file:
        if "Parse" not in line:
            keyValues.append(line)
        else:
            break

    file.close()

    return keyValues


def extractKeyValuePairs(kv):
    """Returns a dictionary with key value pairs only. """

    keyValues = dict()

    for line in kv:
        kv = scanf("%*s %*s [%s] [%s]", line)
        keyValues[kv[0]] = kv[1]

    kv = None
    return keyValues


def insert(args):
    """Execute insert to load the region."""

    command = "./inserts " + str(args.insert) + " > keys.txt"

    if os.system(command) != 0:
        print("insert exited abnormally exiting...")
        sys.exit()


def searchAllKeys(keyValues, lost=[]):
    """Validates insert operation if a key is not found,
    there is a bug in insert path."""
    command = "./find "

    # os.system("rm find.txt")
    # os.system("rm find.sh")

    for k in keyValues:
        if k in lost:
            continue
        command = command + k + " "

    f = open("find.sh", "w")
    f.write("#!/bin/bash\n")
    f.write(command + " > find.txt")
    f.close()
    os.system("sh find.sh")

    count = 0
    f = open("find.txt", "r")
    for line in f:
        if "NOT FOUND" in line:
            count = count + 1
            # sys.exit()
    if count > 0:
        print(
            Fore.RED
            + "The number of keys that were not found "
            + str(count)
            + Style.RESET_ALL
        )
    else:
        print("All keys found!")

    f.close()


def update(args, keyValues):
    """Execute update to change values to a number of keys."""

    command = "./updates "
    if args.sbdu is True:
        searchAllKeys(keyValues)

    if args.update > len(keyValues):
        size = len(keyValues)
    else:
        size = args.update

    os.system("rm updates.txt")

    i = 0
    for k in keyValues:
        if i >= (size - 1):
            break
        if os.system(command + k + " >> updates.txt") != 0:
            print("Error in update")
        i += 1

    if args.sbdu is True:
        searchAllKeys(keyValues)


def find(args, keyValues):
    """Search for keys in a region."""
    command = "./find "

    if args.find > len(keyValues):
        size = len(keyValues)
    else:
        size = args.find

    os.system("rm find.txt")
    i = 0
    for k in keyValues:
        if i >= (size - 1):
            break
        os.system(command + k + " >> find.txt")
        i += 1

    f = open("find.txt", "r")
    for line in f:
        if "NOT FOUND" in line:
            print("Error could not find key")


def delete(args, keyValues):
    """Delete keys in a region."""
    command = "./deletes "
    flag = 0

    if args.delete > len(keyValues):
        size = len(keyValues)
    else:
        size = args.delete

    os.system("rm delete.txt")
    i = 0
    for k in keyValues:
        if i >= (size - 1):
            break
        os.system(command + k + " >> delete.txt")
        i = i + 1

    f = open("delete.txt", "r")
    for line in f:
        if "NOT DELETED" in line:
            print("Error could not delete key")
            flag = 1
    f.close()

    if args.sbdu is True:
        searchAllKeys(keyValues)

    # i = 0
    # if flag == 0:
    #     for i in range(0, size):
    #         for k in keyValues:
    #             del keyValues[k]
    #             break


def deleteKey(args, keyValues):
    command = "./deletes " + str(args.deletekey) + " > lost.txt"
    lost = []
    os.system(command)

    if os.path.isfile("lost.txt"):
        f = open("lost.txt", "r")

        for line in f:
            if "KEYSLOSE" in line:
                break

        for line in f:
            if "KEYSLOST" not in line:
                lost.append(line.rstrip())
            else:
                break
        # print(lost)

    searchAllKeys(keyValues, lost)


def findKey(args, keyValues):
    command = "./find " + str(args.findkey)
    os.system(command)


def makeAppropriateCalls(args):
    if args.insert is not None:
        insert(args)

    keyValuestoParse = parseKeys()
    keyValues = extractKeyValuePairs(keyValuestoParse)

    if args.update is not None:
        update(args, keyValues)

    if args.find is not None:
        find(args, keyValues)

    if args.delete is not None:
        delete(args, keyValues)

    if args.deletekey is not None:
        deleteKey(args, keyValues)

    if args.findkey is not None:
        findKey(args, keyValues)


def main():
    args = getArgs()
    sanitize(args)

    if not os.path.isfile("/tmp/kreon.dat"):
        # Don't use less than 3GB because allocator will smash the stack.
        print(Fore.RED + "kreon.dat has not been created" + Style.RESET_ALL)
        # os.system("fallocate -l 3G /tmp/kreon.dat")

    makeAppropriateCalls(args)


main()
