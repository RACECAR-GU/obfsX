#!/usr/bin/env bash

# NOTE: Targets Bionic Beaver LTS

apt install apt-transport-https
cat "deb https://deb.torproject.org/torproject.org bionic main
   deb-src https://deb.torproject.org/torproject.org bionic main" > /etc/apt/sources.list.d/tor_sources.list

wget -qO- https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc | gpg --import
gpg --export A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89 | apt-key add -

apt update
apt install tor deb.torproject.org-keyring

apt install git

cat "-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIBzwn5AYtJ5unwLZUAG5rC9hnbhd4nftcmi59bDEKGrnIna9X/oeHK
MSdCXbkYVLMu944OT8HL+PRShvok9zIsWyegBwYFK4EEACOhgYkDgYYABAHaF2hN
Mg+OBhNtjeoM35sEuDb6hgE06OTyhnXYFXlh5xArNpXr7Wnn4LHG0KVy8J1T3QeQ
X5pODyWPHoox/8rhXwHbLcnj3SCFJsIZkVRxY3ztlX/xtgbewU+AQ8t+4EP2pcuI
75HSZQyb6xLyaHWXPsdfJSMKof8nHGaop90LTHm9sw==
-----END EC PRIVATE KEY-----" > ~/.ssh/racecar_bot

cat "host github.com
 HostName github.com
 IdentityFile ~/.ssh/racecar_bot
 User git" > ~/.ssh/config

git clone git@github.com:RACECAR-GU/obfsX.git ~/obfsx

go build -o /usr/bin/obfs4proxy ~/obfsx/obfs4proxy

rm /etc/tor/torrc

cat "BridgeRelay 1

PublishServerDescriptor 0
DataDirectory /tor/obfs5_bridge_data

# This port must be externally reachable.
# Avoid port 9001 because it's commonly associated with Tor and censors may be scanning the Internet for this port.
ORPort 9999

ServerTransportPlugin obfs4 exec /usr/bin/obfs4proxy

# This port must be externally reachable and must be different from the one specified for ORPort.
# Avoid port 9001 because it's commonly associated with Tor and censors may be scanning the Internet for this port.
ServerTransportListenAddr obfs4 0.0.0.0:6666

# Local communication port between Tor and obfs4.  Always set this to "auto".
# "Ext" means "extended", not "external".  Don't try to set a specific port number, nor listen on 0.0.0.0.
ExtORPort auto

ContactInfo <st1038@georgetown.edu>

# Pick a nickname that you like for your bridge.  This is optional.
Nickname OBFS5Test" > /etc/tor/torrc

systemctl restart tor