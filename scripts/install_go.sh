#!/bin/bash

rm -rf /usr/local/go

wget https://go.dev/dl/go1.25.3.linux-amd64.tar.gz

sudo tar -C /usr/local -xzf go1.25.3.linux-amd64.tar.gz

export PATH=$PATH:/usr/local/go/bin

go version

#On Ubuntu, run:

sudo apt update

sudo apt install golang-go build-essential -y

#Or, for the latest official version, you can use:

wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz

sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz

echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.profile

source ~/.profile

# If go is still not found

sudo bash
export PATH=$PATH:/usr/local/go/bin