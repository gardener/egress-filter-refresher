#!/bin/bash -e
# SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

IPV4_IPSET_NAME=egress-filter-set-v4
IPV6_IPSET_NAME=egress-filter-set-v6
IPV4_EGRESS_FILTER_LIST=/lists/ipv4-list
IPV6_EGRESS_FILTER_LIST=/lists/ipv6-list
IPSET_SCRIPT=/tmp/ipset_script

function update {
  local IPSET_NAME=`mktemp -u`
  echo "Creating temporary ipset with name \"${IPSET_NAME}\"..."
  ipset create ${IPSET_NAME} hash:net family inet$1 maxelem 65536
  echo "Temporary ipset with name \"${IPSET_NAME}\" created successfully."

  cat $3 | grep -v '\[\]' | awk '{print $2}' | sed "s%^%-A ${IPSET_NAME} %" > ${IPSET_SCRIPT}

  local ENTRIES=`wc -l < ${IPSET_SCRIPT}`
  echo "Adding ${ENTRIES} entries into temporary ipset..."
  echo "quit" >> ${IPSET_SCRIPT}
  ipset - < ${IPSET_SCRIPT}
  echo ""
  echo "Added ${ENTRIES} entries into temporary ipset successfully."

  set +e
  ipset -quiet -name list $2
  if [ $? -ne 0 ]; then
    set -e
    echo "Initially creating ipset with name \"$2\"..."
    ipset create $2 hash:net family inet$1 maxelem 65536
    echo "Ipset \"$2\" initially created successfully."
    local DEFAULT_NET_DEVICE=`ip route | grep default | awk '{print $5}'`
    echo "Initially creating ip${1}tables rule for device \"${DEFAULT_NET_DEVICE}\" referencing ipset..."
    ip${1}tables -t mangle -A POSTROUTING -o ${DEFAULT_NET_DEVICE} -m set --match-set $2 dst -j DROP
    echo "Initial ip${1}tables rule for device \"${DEFAULT_NET_DEVICE}\" created successfully."
  else
    set -e
  fi

  echo "Swapping new ipset \"${IPSET_NAME}\" against old one \"$2\"..."
  ipset swap ${IPSET_NAME} $2
  echo "Swapped contents of ipsets \"${IPSET_NAME}\" and \"$2\" successfully."

  echo "Cleaning up temporary ipset..."
  ipset destroy ${IPSET_NAME}
  rm ${IPSET_SCRIPT}
  echo "Cleanup finished successfully."
}

while true; do
  date
  update "" ${IPV4_IPSET_NAME} ${IPV4_EGRESS_FILTER_LIST}
  update "6" ${IPV6_IPSET_NAME} ${IPV6_EGRESS_FILTER_LIST}
  date

  echo "Going to sleep for 1h..."
  sleep 1h
done
