#!/usr/bin/bash
set -e
trap2json -generate /etc/trap2json/snmptrapd.conf
shopt -s lastpipe
if [[ -z "${SNMPTRAPD_DEBUG}" ]]; then
  snmptrapd -M +/etc/trap2json/mibs -m ALL -Lo -OnUx -f -C -c /etc/trap2json/snmptrapd.conf | exec trap2json
else
  snmptrapd -M +/etc/trap2json/mibs -m ALL -Lo -Lf /var/log/trap2json/trap2json.log -OnUx -f -C -c /etc/trap2json/snmptrapd.conf | exec trap2json
fi