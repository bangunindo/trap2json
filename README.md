# Trap2JSON
Listens to SNMP Trap, converts it to json, and forwards it to other system.
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
- Supports trap/inform with version 1/2c/3 in a single endpoint

## Installation
The supported way of running Trap2JSON is to use docker.
You can see sample config and its explanations at [config.yml](config.yml)
```shell
docker run -v config.yml:/etc/trap2json/config.yml -p 162:10162/udp bangunindo/trap2json:latest
```
The docker image has default MIBs retrieved via snmp-mibs-downloader.
If you have your own MIBs, place it under `/etc/trap2json/mibs`
```shell
docker run -v /path/to/mibs:/etc/trap2json/mibs -v config.yml:/etc/trap2json/config.yml -p 162:10162/udp bangunindo/trap2json:latest
```
You might also want to adjust the timezone for better data readability
```shell
docker run -e TZ=Asia/Jakarta -v config.yml:/etc/trap2json/config.yml -p 162:10162/udp bangunindo/trap2json:latest
```

## Zabbix Forwarder
For zabbix forwarder to work, you need to create an item with Zabbix Trapper type and text/log data type. If you need
to map the agent address to host's interface, consider using the `advanced` section of `zabbix_trapper` config in [config.yml](config.yml)