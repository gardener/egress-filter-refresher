# SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

############# gobuilder
FROM golang:1.25.5 AS gobuilder

WORKDIR /build
COPY ./VERSION ./VERSION
COPY ./.git ./.git
COPY . .
ARG TARGETARCH
RUN make build-filter-updater GOARCH=$TARGETARCH

FROM alpine:3.23.3 AS builder

WORKDIR /volume

COPY --from=gobuilder /build/filter-updater ./filter-updater

RUN apk update; \
    apk add ipset; \
    apk add ip6tables; \
    apk add iptables-legacy; \
    apk add iproute2-minimal

RUN mkdir -p ./bin ./sbin ./lib ./usr/bin ./usr/sbin ./usr/lib ./usr/lib/xtables ./tmp ./run ./etc/iproute2\
    && cp -d /lib/ld-musl-* ./lib                                           && echo "package musl" \
    && cp -d /lib/libc.musl-* ./lib                                         && echo "package musl" \
    && cp -d /usr/lib/libcap.* ./usr/lib                                    && echo "package libcap" \
    && cp -d /usr/lib/libpsx.* ./usr/lib                                    && echo "package libcap" \
    && cp -d /usr/lib/libz.* ./lib                                              && echo "package zlib" \
    && cp -d /usr/lib/libzstd.* ./usr/lib                                   && echo "package libzstd" \
    && cp -d /usr/lib/libelf* ./usr/lib                                     && echo "package libelf" \
    && cp -d /usr/lib/libmnl.* ./usr/lib                                    && echo "package libmnl" \
    && cp -d /sbin/ip ./sbin                                                && echo "package iproute2-minimal" \
    && cp -d /usr/lib/libipset* ./usr/lib                                   && echo "package ipset" \
    && cp -d /usr/sbin/ipset* ./usr/sbin                                    && echo "package ipset" \
    && cp -d /usr/lib/libnftnl* ./usr/lib                                   && echo "package libnftnl" \
    && cp -d /etc/ethertypes ./etc                                          && echo "package iptables" \
    && cp -d /usr/sbin/iptables* ./sbin                                         && echo "package iptables" \
    && cp -d /usr/sbin/xtables* ./sbin                                          && echo "package iptables" \
    && cp -d /usr/lib/libip4* ./usr/lib                                     && echo "package iptables" \
    && cp -d /usr/lib/libip6* ./usr/lib                                     && echo "package iptables" \
    && cp -d /usr/lib/libxtables* ./usr/lib                                 && echo "package iptables" \
    && cp -d /usr/lib/xtables/* ./usr/lib/xtables                           && echo "package iptables" \
    && cp -d /usr/sbin/ip6tables* ./sbin                                        && echo "package ip6tables"

FROM scratch

COPY --from=builder /volume /

CMD ["/filter-updater"]
