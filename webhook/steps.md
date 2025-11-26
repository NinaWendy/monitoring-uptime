
# Steps to setup webhook

1. Create  `main.go`

2. Create  `rsyslog-uptime-kuma.conf` add contents of `webhook-app.conf`

    Edit `50-default.conf`

3. Create `install-production.sh`

4. Create `uptime-kuma-webhook.service`

5. Create `monitor-webhook.sh`

6. Create `load-test.sh`

7. Run `chmod +x install-production.sh monitor-webhook.sh`

    chmown syslog:adm /srv/uptime-kuma/webhook.log

    chmod 777 /srv/uptime-kuma/webhook.log

8. Run:

    ```sh
    sudo bash
    export PATH=$PATH:/usr/local/go/bin
    go mod init uptimewebhook
    go mod tidy
    ./install-production.sh
    ```
