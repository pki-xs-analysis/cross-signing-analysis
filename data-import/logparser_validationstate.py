#!/usr/bin/env python

import argparse
import re

description ="Find out up to which certificate validation was completed before crash to resume accordingly (or simply to check the current running state). Hint: Copy the full buffer of a screen session with ctrl+a ':hardcopy -h <path>'"

parser = argparse.ArgumentParser(description=description)
parser.add_argument("-f", "--logfile", type=str, required=True, help="Logfile for analysis")
args = parser.parse_args()

pattern = re.compile("Worker (?P<workerid>\d+): Finished certs (?P<certs_start>\d+) - (?P<certs_end>\d+) ... Found (?P<newpaths_cnt>\d+) new and (?P<knownpaths_cnt>\d+) known paths")

data = {}

for line in open(args.logfile, "ro"):
    m = pattern.match(line)
    if m:
        workerid = int(m.group('workerid'))
        certs_end = int(m.group('certs_end'))
        
        data.setdefault(workerid, 0)
        data[workerid] = max(data[workerid], certs_end)
    else:
        print "WARNING Cannot match line \"{}\"".format(line.rstrip('\n'))

for workerid in sorted(data):
    print workerid, data[workerid]

print "\n##### RESULT #####"
workerid_min = min(data.keys())
workerid_max = max(data.keys())
worker_cnt = len(data.keys())
print "Gathered data from workers {} - {} (count: {})".format(workerid_min, workerid_max, worker_cnt)
print "\tINFO Doublecheck that worker count equals the number of used workers"
for w_id in xrange(workerid_min, workerid_max+1):
    if w_id not in data.keys():
        print "\tWARNING Missing data for worker {}: Result below does not incorporate state of this worker; Apply safety margin when resuming!".format(w_id)
certid_for_resuming = min([data[w_id] for w_id in data]) + 1
print "All certificates with ids smaller than {} have been checked.".format(certid_for_resuming)
print "Resume with --start_with_certid {}".format(certid_for_resuming)
