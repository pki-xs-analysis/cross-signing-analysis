#!/usr/bin/env bash

# We do not need this at SYD
pg_ctl stop -D postgres -m fast
sleep 2
rm -r postgres
rm serverlog
rm -f testdata/*.statistics
