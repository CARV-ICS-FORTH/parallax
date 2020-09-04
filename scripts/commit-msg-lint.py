#!/bin/python3
import base64
import gitlab
import os
import sys

host = "https://carvgit.ics.forth.gr"
token = base64.b32decode(os.environ["CID_TOKEN"])
project = os.environ["CI_PROJECT_PATH"]
branch = os.environ["CI_BUILD_REF_NAME"]
commit_sha = os.environ["CI_COMMIT_SHA"]
proj_url = os.environ["CI_PROJECT_URL"]
user_email = os.environ["GITLAB_USER_EMAIL"]
pipeline_id = os.environ["CI_PIPELINE_ID"]

with gitlab.Gitlab(host, private_token=token) as gl:
    kreon = gl.projects.get(project)
    commits = kreon.commits.list(ref_name=branch)
    master_commits = kreon.commits.list(ref_name="master")
    new_commits = []

    for c in commits:
        if c not in master_commits:
            new_commits.append(c)

    path = os.getcwd()
    command = "gitlint --msg-filename " + path + "/msg"

    for c in new_commits:
        f = open("msg", "w")
        f.write(c.message)
        f.close()
        if os.system(command) != 0:
            sys.exit(-1)
        os.remove("msg")
