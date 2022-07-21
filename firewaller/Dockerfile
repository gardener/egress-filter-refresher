# SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

FROM alpine:3.15.4 as builder

WORKDIR /volume

ADD firewaller/update-firewall.sh ./update-firewall.sh
RUN chmod +x ./update-firewall.sh; \
    apk update; \
    apk add bash; \
    apk add ipset; \
    apk add ip6tables; \
    apk add iproute2

RUN mkdir -p ./bin ./sbin ./lib ./usr/bin ./usr/sbin ./usr/lib ./usr/lib/xtables ./tmp ./run \
    && cp -d /lib/ld-musl-* ./lib \
    && cp -d /lib/libc.musl-* ./lib \
    && cp -d /lib/libz.so.* ./lib \
    && cp -d /usr/lib/libelf* ./usr/lib \
    && cp -d /usr/lib/libip4* ./usr/lib \
    && cp -d /usr/lib/libip6* ./usr/lib \
    && cp -d /usr/lib/libmnl* ./usr/lib \
    && cp -d /usr/lib/libncursesw.so.* ./usr/lib \
    && cp -d /usr/lib/libnftnl* ./usr/lib \
    && cp -d /usr/lib/libreadline.so.* ./usr/lib \
    && cp -d /usr/lib/libxtables* ./usr/lib \
    && cp -d /usr/lib/xtables/* ./usr/lib/xtables \
    && cp -d /bin/bash ./bin \
    && cp -d /bin/busybox ./bin \
    && cp -d /bin/cat ./bin \
    && cp -d /bin/date ./bin \
    && cp -d /bin/echo ./bin \
    && cp -d /bin/grep ./bin \
    && cp -d /bin/mktemp ./bin \
    && cp -d /bin/rm ./bin \
    && cp -d /bin/sed ./bin \
    && cp -d /bin/sleep ./bin \
    && cp -d /sbin/ip ./sbin \
    && cp -d /sbin/iptables* ./sbin \
    && cp -d /sbin/ip6tables* ./sbin \
    && cp -d /sbin/xtables* ./sbin \
    && cp -d /usr/bin/awk ./usr/bin \
    && cp -d /usr/bin/wc ./usr/bin \
    && cp -d /usr/sbin/ipset ./usr/sbin

FROM scratch

COPY --from=builder /volume /

CMD [ "bash","-c", "/update-firewall.sh"]
