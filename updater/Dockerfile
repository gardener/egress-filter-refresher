# SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

FROM alpine:3.14.2

ADD updater/update-filter-list.sh /update-filter-list.sh
RUN chmod +x /update-filter-list.sh; \
    apk update; \
    apk add curl; \
    apk add jq

CMD [ "sh","-c", "/update-filter-list.sh"]
