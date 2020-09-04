"""Defines rules for special sections of a commit message"""
import re
from gitlint.rules import CommitRule, RuleViolation


class FooterRule(object):
    """ Common parent class for all Footer rules """

    def validate(self, commit):
        # Extract footer from commit message body
        footer = commit.message.body[-2:]
        if len(footer) < 2:
            return ""
        # If the last line does not contain the word Closes or # then we only have a body
        if "Closes" not in footer[1] and "#" not in footer:
            return ""

        if footer[0] != "":
            return "Footer is not separated from body with newline"

        if "Closes" not in footer[1]:
            return "First word of footer should be 'Closes'"

        matches = re.finditer(r"Closes (\#\d*)|(\,\#\d*)", footer[1], re.MULTILINE)
        matches_len = 0
        for _, match in enumerate(matches, start=1):
            matches_len = matches_len + len(match.group(0))

        if matches_len != len(footer[1]):
            return "Multiple issues should be comma separated"

        return ""


# Extend MyCustomRule from both CommitRule (so gitlint will find it)
# and FooterRule (to implement common footer logic)
class MyCustomRule(CommitRule, FooterRule):
    """"""

    name = "Footer Section"
    id = "UC1"

    def validate(self, commit):
        # call validate method from FooterRule to easily extract footer
        message = super(MyCustomRule, self).validate(commit)
        if message == "":
            return

        return [
            RuleViolation(self.id, message, line_nr=len(commit.message.body))
        ]  # content=self.footer[1]
