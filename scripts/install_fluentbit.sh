#!/bin/bash

curl https://raw.githubusercontent.com/fluent/fluent-bit/master/install.sh | sh

[SERVICE]
    flush        5
    daemon       Off
    log_level    info
    parsers_file parsers.conf
    plugins_file plugins.conf
    http_server  Off
    http_listen  0.0.0.0
    http_port    2020
    storage.metrics on
    storage.path /var/log/flb-storage/
    storage.sync normal
    storage.checksum off
    storage.backlog.mem_limit 5M
    Log_File /var/log/td-agent-bit.log
[INPUT]
    Name  tail
    Path  /srv/uptime-kuma/webhook.log
    Tag   uptime-kuma
    Parser json
    Read_from_Head Off
    Storage.Type filesystem
    Mem_Buf_Limit 128MB
[OUTPUT]
    Name  tcp
    Host  Monitoring-SIEM
    Port  1515
    net.keepalive off
    Match uptime-kuma
    Format  json_lines
    json_date_key true