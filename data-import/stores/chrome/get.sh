#!/bin/bash

TARGETDIR=$(date +%F)_src.git-master-net-data-ssl
TARGETFILE=$(date +%F)_src.git-master-net-data-ssl.tar.gz

mkdir $TARGETDIR
wget -O $TARGETFILE https://chromium.googlesource.com/chromium/src.git/+archive/refs/heads/master/net/data/ssl.tar.gz
tar -C $TARGETDIR -xzf $TARGETFILE

