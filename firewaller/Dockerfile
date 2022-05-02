# SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

FROM alpine:3.15.4

ADD firewaller/update-firewall.sh /update-firewall.sh
RUN chmod +x /update-firewall.sh; \
    apk update; \
    apk add bash; \
    apk add ipset; \
    apk add ip6tables; \
    apk add iproute2

CMD [ "bash","-c", "/update-firewall.sh"]
