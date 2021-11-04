#!/bin/sh -e

/downloader/download.sh

if [ ! -f ${LISTFILE} ]; then
    echo "${LISTFILE} does not exist, exiting..."
    exit 1
fi
ls -l ${LISTFILE}

echo -n "{\"apiVersion\": \"v1\", \"kind\": \"Secret\", \"metadata\": { \"name\": \"egress-filter-list\"}, \"type\": \"Opaque\", \"data\": {\"list\": \"" > ${LISTFILE}.tmp
base64 -w0 ${LISTFILE} >> ${LISTFILE}.tmp
echo "\"}}" >> ${LISTFILE}.tmp
mv ${LISTFILE}.tmp ${LISTFILE}

status=$(curl -X GET -H "Content-Type: application/json" -H "Accept: application/json" -H "Authorization: Bearer `cat /var/run/secrets/kubernetes.io/serviceaccount/token`" --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt -o /dev/null -w '%{http_code}\n' -s https://kubernetes.default.svc.cluster.local/api/v1/namespaces/${NAMESPACE}/secrets/egress-filter-list)

if [ $status = "200" ]; then
    echo "Secret found, updating..."
    curl -X PUT -H "Content-Type: application/json" -H "Accept: application/json" -H "Authorization: Bearer `cat /var/run/secrets/kubernetes.io/serviceaccount/token`" --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt -o /dev/null -w '%{http_code}\n' -s https://kubernetes.default.svc.cluster.local/api/v1/namespaces/${NAMESPACE}/secrets/egress-filter-list -d @${LISTFILE}
else 
    echo "Secret not found, creating..."
    curl -X POST -H "Content-Type: application/json" -H "Accept: application/json" -H "Authorization: Bearer `cat /var/run/secrets/kubernetes.io/serviceaccount/token`" --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt -o /dev/null -w '%{http_code}\n' -s https://kubernetes.default.svc.cluster.local/api/v1/namespaces/${NAMESPACE}/secrets -d @${LISTFILE}
fi

rm ${LISTFILE}
