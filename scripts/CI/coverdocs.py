#!/usr/bin/env python3

"""
This script checks the documentation of the master branch and compares it with the documentation of the current branch,
if the documentation ratio is less than the master branch ration then the script will fail.
"""
import os
import sys


def generate_doxygen_report(branch_name, src_dir):
    """
    Given a branch name and the source directory of the project this function generates a doxygen summary for documented code.
    """

    doc_summary_file = f"doc-summary-{branch_name}.info"
    # Produce coverxygen report to produce the coverage report using lcov
    coverxygen_cmd = f"python3 -m coverxygen --xml-dir {src_dir}/docs/xml --src-dir {src_dir} --output doc-coverage-{branch_name}.info --scope all --kind all"
    os.system(coverxygen_cmd)

    # Produce coverxygen report to produce the summary report
    coverxygen_cmd = f"python3 -m coverxygen --xml-dir {src_dir}/docs/xml --src-dir {src_dir} --output {doc_summary_file} --scope all --kind all --format summary"
    os.system(coverxygen_cmd)

    curr_branch_doc_ratio = 0.0
    summary_last_line_tokens = []

    # Read last summary line and extract the numbers from the fraction
    with open(doc_summary_file, "r") as summary_file:
        read_last_line = summary_file.readlines()[-1]
        summary_last_line_tokens = (
            read_last_line.rstrip().split(" ")[-1][1:-1].split("/")
        )

    curr_branch_doc_ratio = float(summary_last_line_tokens[0]) / float(
        summary_last_line_tokens[1]
    )
    print(f"Branch {branch_name} ratio {curr_branch_doc_ratio}")
    return curr_branch_doc_ratio


def main():

    """
    Compares the doxygen coverage between two branches.
    Returns 0 if the current branch contains >= coverage compared to the second branch.
    Returns 1 if the current branch contains < coverage compared to the second branch.
    """
    if len(sys.argv) < 5:
        print("To execute this script run:")
        print(
            "coverxygen.py current_branch_name current_branch_src_dir default_branch_name default_branch_src_dir"
        )
        sys.exit(1)

    current_branch_ratio = generate_doxygen_report(sys.argv[1], sys.argv[2])

    if sys.argv[1] == sys.argv[3]:
        print("We are on master branch we do not need to calculate the ratio!")
        sys.exit(0)

    master_branch_ratio = generate_doxygen_report(sys.argv[3], sys.argv[4])

    if current_branch_ratio < master_branch_ratio:
        print("The new code in the current branch is not documented!")
        sys.exit(1)

    print("The new code in the current branch is documented.")
    sys.exit(0)


if __name__ == "__main__":
    main()
