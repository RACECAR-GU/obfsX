#!/usr/bin/env bash

# NOTE: Targets Bionic Beaver LTS
# This script targets testing servers - I would not use it to spin up servers that are meant to be used in the wild.
# TODO: Make command line option for OBFS4

apt update && apt upgrade -y

cd /pt/obfs

git pull origin main
go build -o bin ./obfs4proxy

systemctl restart tor
