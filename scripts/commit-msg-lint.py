#!/bin/python3
import base64
import gitlab
import os
import sys

host = "https://carvgit.ics.forth.gr"
token = str(base64.b32decode(os.environ["CID_TOKEN"]).decode("utf-8"))
project = os.environ["CI_PROJECT_PATH"]
branch = os.environ["CI_BUILD_REF_NAME"]


with gitlab.Gitlab(host, private_token=token) as gl:
    parallax = gl.projects.get(project)
    commits = parallax.commits.list(ref_name=branch)
    new_commits = []
    dest_branch_commits = parallax.commits.list(
        ref_name=os.environ["CI_MERGE_REQUEST_TARGET_BRANCH_NAME"]
    )

    for c in commits:
        if c not in dest_branch_commits:
            new_commits.append(c)

    path = os.getcwd()
    command = "gitlint --msg-filename " + path + "/msg"

    for c in new_commits:
        with open("msg", "w") as f:
            f.write(c.message)

        if os.system(command) != 0:
            sys.exit(-1)

        os.remove("msg")
