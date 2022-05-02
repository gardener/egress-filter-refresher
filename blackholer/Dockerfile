# SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

FROM alpine:3.15.4

ADD blackholer/update-blackholes.sh /update-blackholes.sh
RUN chmod +x /update-blackholes.sh; \
    apk update; \
    apk add bash; \
    apk add diffutils; \
    apk add iproute2

CMD [ "bash","-c", "/update-blackholes.sh"]
