#!/bin/bash
# SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

IPV4_EGRESS_FILTER_LIST=/lists/ipv4-list
IPV6_EGRESS_FILTER_LIST=/lists/ipv6-list
DIFF_FILE=/tmp/diff
ADDED_FILE=/tmp/added
REMOVED_FILE=/tmp/removed

function check_and_update {
  echo "Checking ipv$1 egress filter list with `wc -l < $2` entries against current settings..."
  diff <(ip -$1 r | grep blackhole | grep -v "proto bird" | awk '{print $2}' | sort) <(cat $2 | grep -v '\[\]' | awk '{print $2}' | sed s%/32%% | sort) > ${DIFF_FILE}
  cat ${DIFF_FILE} | grep ^\> | awk '{print $2}' > ${ADDED_FILE}
  cat ${DIFF_FILE} | grep ^\< | awk '{print $2}' > ${REMOVED_FILE}

  echo "Difference calculated. `wc -l < ${ADDED_FILE}` entries added. `wc -l < ${REMOVED_FILE}` entries removed."

  sed -i 's%^%route add blackhole %' ${ADDED_FILE}
  sed -i 's%^%route del blackhole %' ${REMOVED_FILE}

  if [ -s "${ADDED_FILE}" ]; then
    echo "Adding new entries..."
    ip -$1 -batch ${ADDED_FILE}
    if [ $? -eq 0 ]; then
      echo "Adding `wc -l < ${ADDED_FILE}` entries succeeded."
    else
      echo "Adding `wc -l < ${ADDED_FILE}` entries failed."
    fi
  fi

  if [ -s "${REMOVED_FILE}" ]; then
    echo "Removing old entries..."
    ip -$1 -batch ${REMOVED_FILE}
    if [ $? -eq 0 ]; then
      echo "Removing `wc -l < ${REMOVED_FILE}` entries succeeded."
    else
      echo "Removing `wc -l < ${REMOVED_FILE}` entries failed."
    fi
  fi
  rm ${DIFF_FILE} ${ADDED_FILE} ${REMOVED_FILE}
}

while true; do
  date
  check_and_update "4" ${IPV4_EGRESS_FILTER_LIST}
  check_and_update "6" ${IPV6_EGRESS_FILTER_LIST}
  date

  echo "Going to sleep for 1h..."
  sleep 1h
done
