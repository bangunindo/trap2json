# Trap2JSON
Listens to SNMP Trap, converts it to json, and forwards it to zabbix, kafka, mqtt broker, or proxy it to other trap receiver.
Internally it uses snmptrapd to listen to incoming trap message, output it
to stdout and parse the messages. If you're familiar with how snmptrapd works,
you can add any configuration supported by snmptrapd.conf. Prior knowledge
for snmptrapd is not required as trap2json can handle common snmptrapd setup.

While this tool can forward snmptrap to many destinations, we treat zabbix
as the first class citizen and the main purpose for creating this tool. You
can use this as a solution for your distributed zabbix setup.

## Features
- Parse snmp trap messages to JSON and send to many forwarders
- Supported forwarders
  - File/stdout
  - Kafka
  - MQTT Broker
  - SNMP Trap (like a proxy)
  - Zabbix
- Message filter for each forwarder
  - Decide which messages to drop
- Choose your own JSON schema
- Prometheus exporter
- Queued forwarder
  - If the queue is full for a forwarder, the message is dropped
  - Supports unbounded queue
- Forwarder auto retry with exponential backoff delay
- Supports trap/inform with version 1/2c/3 in a single endpoint

## Installation
The supported way of running Trap2JSON is to use docker. Docker image is available
on [dockerhub](https://hub.docker.com/r/bangunindo/trap2json).
You can see sample config and its explanations at [config.yml](config.yml)
```shell
docker run -v ./config.yml:/etc/trap2json/config.yml -p 162:10162/udp bangunindo/trap2json:latest
```
The docker image has default MIBs retrieved via snmp-mibs-downloader.
If you have your own MIBs, place it under `/etc/trap2json/mibs`
```shell
docker run -v /path/to/mibs:/etc/trap2json/mibs -v ./config.yml:/etc/trap2json/config.yml -p 162:10162/udp bangunindo/trap2json:latest
```
You might also want to adjust the timezone for better data readability
```shell
docker run -e TZ=Asia/Jakarta -v ./config.yml:/etc/trap2json/config.yml -p 162:10162/udp bangunindo/trap2json:latest
```
Or if you want to pass extra arguments to snmptrapd
```shell
docker run -v ./config.yml:/etc/trap2json/config.yml -p 162:10162/udp bangunindo/trap2json:latest -Lf /var/log/trap2json/snmptrapd.log -Dusm
```
The buffer size for snmptrapd can be customized by setting `T2J_BUFFERSIZE` environment variable.
By default, it's set to 32M to accommodate trap2json startup time.
```shell
docker run -e T2J_BUFFERSIZE=128M -v ./config.yml:/etc/trap2json/config.yml -p 162:10162/udp bangunindo/trap2json:latest
```

## Zabbix Forwarder
For zabbix forwarder to work, you need to create an item with Zabbix Trapper type and text/log data type. If you need
to map the agent address to host's interface, consider using the `advanced` section of `zabbix_trapper` config in [config.yml](config.yml).

Zabbix limits its text/log type to 65536 characters/bytes (depending on backend). In most cases you probably will
not meet this limitation. But when it does, you might want to create a smaller json schema with only the data
you want.
