FROM alpine:3.14.2

ADD update-filter-list.sh /update-filter-list.sh
RUN chmod +x /update-filter-list.sh; \
    apk update; \
    apk add curl; \
    apk add jq

CMD [ "sh","-c", "/update-filter-list.sh"]
