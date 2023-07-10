FROM golang:1.20 AS buildStage
COPY go.mod go.sum /source_code/
WORKDIR /source_code
RUN go mod download
COPY . .
RUN go build -o /trap2json github.com/bangunindo/trap2json
RUN chmod +x /trap2json

FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC
RUN apt-get update && \
    apt-get install -y snmptrapd snmp-mibs-downloader tzdata ca-certificates snmp
RUN mkdir /etc/trap2json /etc/trap2json/mibs /var/run/snmptrapd /var/log/trap2json
COPY --from=buildStage /trap2json /usr/local/bin/trap2json
COPY entrypoint.sh .
COPY config-minimal.yml /etc/trap2json/config.yml
RUN chmod +x entrypoint.sh
# snmp trap
EXPOSE 10162/udp
# prometheus
EXPOSE 9285
ENTRYPOINT ["/entrypoint.sh"]