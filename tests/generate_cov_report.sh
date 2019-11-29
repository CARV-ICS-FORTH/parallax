#!/bin/sh
/usr/local/bin/gcovr -v -p -r .. -e '3rdparty' --html --html-details -o report.html
