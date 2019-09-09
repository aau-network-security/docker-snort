#!/bin/bash

find /data/in -iname '*.pcap' | \
    while read f; do
	echo Running snort on $f
        OUT="/data/out/$(basename $f)"
	snort -u snort -g snort -A console -c /etc/snort/snort.conf -r $f > $OUT.out 2>$OUT.err
    done
