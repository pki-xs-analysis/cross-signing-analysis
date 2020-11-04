#!/bin/bash

# git clone https://github.com/robstradling/authroot.stl.git

cd authroot.stl && git fetch; for commit in $(git log origin/master | grep commit | awk '{print $2}'); do git checkout $commit && export TARGETDIR=../stl_$(git log -n1 | grep "Produced at " | awk '{print $7}') && mkdir -p $TARGETDIR && cp authroot*.* $TARGETDIR/ && cp -r crt $TARGETDIR/; done; git checkout master;

