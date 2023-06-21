#!/usr/bin/bash
set -e
trap2json -generate /etc/trap2json/snmptrapd.conf
shopt -s lastpipe
snmptrapd -M +/etc/trap2json/mibs -m ALL -Lo -OnUx -f -C -c /etc/trap2json/snmptrapd.conf | exec trap2json