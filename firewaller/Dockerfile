# SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

FROM alpine:3.16.3 as builder

WORKDIR /volume

ADD firewaller/update-firewall.sh ./update-firewall.sh
RUN chmod +x ./update-firewall.sh; \
    apk update; \
    apk add bash; \
    apk add ipset; \
    apk add ip6tables; \
    apk add iproute2-minimal

RUN mkdir -p ./bin ./sbin ./lib ./usr/bin ./usr/sbin ./usr/lib ./usr/lib/xtables ./usr/lib/bash ./tmp ./run ./etc/bash ./etc/openvpn ./usr/lib/openvpn/plugins ./etc/iproute2 ./etc/terminfo ./etc/logrotate.d ./etc/network/if-up.d ./usr/share/udhcpc \
    && cp -d /lib/ld-musl-* ./lib                                           && echo "package musl" \
    && cp -d /lib/libc.musl-* ./lib                                         && echo "package musl" \
    && cp -d /bin/busybox ./bin                                             && echo "package busybox" \
    && cp -d /bin/sh ./bin                                                  && echo "package busybox" \
    && cp -d /etc/logrotate.d/acpid ./etc/logrotate.d                       && echo "package busybox" \
    && cp -d /etc/network/if-up.d/dad ./etc/network/if-up.d                 && echo "package busybox" \
    && cp -d /etc/securetty ./etc                                           && echo "package busybox" \
    && cp -d /etc/udhcpd.conf ./etc                                         && echo "package busybox" \
    && cp -d /usr/share/udhcpc/default.script ./usr/share/udhcpc            && echo "package busybox" \
    && cp -d -r /etc/terminfo/* ./etc/terminfo                              && echo "package ncurses-terminfo-base" \
    && cp -d /usr/lib/libformw.so.* ./usr/lib                               && echo "package ncurses-libs" \
    && cp -d /usr/lib/libmenuw.so.* ./usr/lib                               && echo "package ncurses-libs" \
    && cp -d /usr/lib/libncursesw.so.* ./usr/lib                            && echo "package ncurses-libs" \
    && cp -d /usr/lib/libpanelw.so.* ./usr/lib                              && echo "package ncurses-libs" \
    && cp -d /etc/inputrc ./etc                                             && echo "package readline" \
    && cp -d /usr/lib/libreadline.so.* ./usr/lib                            && echo "package readline" \
    && cp -d /bin/bash ./bin                                                && echo "package bash" \
    && cp -d /etc/bash/bashrc ./etc/bash                                    && echo "package bash" \
    && cp -d /usr/lib/bash/* ./usr/lib/bash                                 && echo "package bash" \
    && cp -d /usr/lib/libcap.* ./usr/lib                                    && echo "package libcap" \
    && cp -d /usr/lib/libpsx.* ./usr/lib                                    && echo "package libcap" \
    && cp -d /usr/lib/libbz2* ./usr/lib                                     && echo "package libbz2" \
    && cp -d /usr/lib/libfts* ./usr/lib                                     && echo "package fts" \
    && cp -d /usr/lib/liblzma* ./usr/lib                                    && echo "package xz-libs" \
    && cp -d /lib/libz.* ./lib                                              && echo "package zlib" \
    && cp -d /usr/lib/libasm* ./usr/lib                                     && echo "package libelf" \
    && cp -d /usr/lib/libdw* ./usr/lib                                      && echo "package libelf" \
    && cp -d /usr/lib/libelf* ./usr/lib                                     && echo "package libelf" \
    && cp -d /usr/lib/libmnl.* ./usr/lib                                    && echo "package libmnl" \
    && cp -d /sbin/ip ./sbin                                                && echo "package iproute2-minimal" \
    && cp -d /etc/iproute2/* ./etc/iproute2                                 && echo "package iproute2-minimal" \
    && cp -d /usr/lib/libipset* ./usr/lib                                   && echo "package ipset" \
    && cp -d /usr/sbin/ipset* ./usr/sbin                                    && echo "package ipset" \
    && cp -d /usr/lib/libnftnl* ./usr/lib                                   && echo "package libnftnl" \
    && cp -d /etc/ethertypes ./etc                                          && echo "package iptables" \
    && cp -d /sbin/iptables* ./sbin                                         && echo "package iptables" \
    && cp -d /sbin/xtables* ./sbin                                          && echo "package iptables" \
    && cp -d /usr/lib/libip4* ./usr/lib                                     && echo "package iptables" \
    && cp -d /usr/lib/libip6* ./usr/lib                                     && echo "package iptables" \
    && cp -d /usr/lib/libipq* ./usr/lib                                     && echo "package iptables" \
    && cp -d /usr/lib/libxtables* ./usr/lib                                 && echo "package iptables" \
    && cp -d /usr/lib/xtables/* ./usr/lib/xtables                           && echo "package iptables" \
    && cp -d /sbin/ip6tables* ./sbin                                        && echo "package ip6tables" \
    && cp -d /bin/cat ./bin                                                 && echo "package coreutils" \
    && cp -d /bin/date ./bin                                                && echo "package coreutils" \
    && cp -d /bin/echo ./bin                                                && echo "package coreutils" \
    && cp -d /bin/mktemp ./bin                                              && echo "package coreutils" \
    && cp -d /bin/rm ./bin                                                  && echo "package coreutils" \
    && cp -d /bin/sleep ./bin                                               && echo "package coreutils" \
    && cp -d /usr/bin/wc ./usr/bin                                          && echo "package coreutils" \
    && cp -d /bin/sed ./bin                                                 && echo "package sed" \
    && cp -d /bin/grep ./bin                                                && echo "package <not-clear>" \
    && cp -d /usr/bin/awk ./usr/bin                                         && echo "package <not-clear>"

FROM scratch

COPY --from=builder /volume /

CMD [ "bash","-c", "/update-firewall.sh"]
