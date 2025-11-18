FROM golang:1.25.4 AS buildStage
COPY go.mod go.sum /source_code/
WORKDIR /source_code
RUN go mod download
COPY . .
RUN GOEXPERIMENT=greenteagc go build -o /trap2json github.com/bangunindo/trap2json
RUN chmod +x /trap2json

FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC
RUN apt-get update && \
    apt-get install -y \
    snmptrapd=5.9.4+* \
    snmp=5.9.4+* \
    snmp-mibs-downloader=1.6 \
    pv \
    tzdata ca-certificates
RUN mkdir /etc/trap2json /etc/trap2json/mibs /var/run/snmptrapd /var/log/trap2json
COPY --from=buildStage /trap2json /usr/local/bin/trap2json
COPY entrypoint.sh .
COPY config-minimal.yml /etc/trap2json/config.yml
RUN chmod +x entrypoint.sh
# snmp trap
EXPOSE 10162/udp
# prometheus
EXPOSE 9285
ENV T2J_BUFFERSIZE=32M
ENTRYPOINT ["/entrypoint.sh"]
