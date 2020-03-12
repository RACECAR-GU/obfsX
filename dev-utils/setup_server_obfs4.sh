#!/usr/bin/env bash

# NOTE: Targets Bionic Beaver LTS
# This script targets testing servers - I would not use it to spin up servers that are meant to be used in the wild.

apt update

apt install apt-transport-https software-properties-common
echo "deb https://deb.torproject.org/torproject.org bionic main
deb-src https://deb.torproject.org/torproject.org bionic main" | tee /etc/apt/sources.list.d/tor_sources.list

wget -qO- https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc | gpg --import
gpg --export A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89 | apt-key add -

add-apt-repository ppa:longsleep/golang-backports

apt update
apt install tor deb.torproject.org-keyring obfs4proxy

rm /etc/tor/torrc

mkdir /tor/
chown -R debian-tor /tor/
chmod -R 755 /tor

echo "BridgeRelay 1

PublishServerDescriptor 0

# This port must be externally reachable.
# Avoid port 9001 because it's commonly associated with Tor and censors may be scanning the Internet for this port.
ORPort 9999

ServerTransportPlugin obfs4 exec /usr/bin/obfs4proxy

# This port must be externally reachable and must be different from the one specified for ORPort.
# Avoid port 9001 because it's commonly associated with Tor and censors may be scanning the Internet for this port.
ServerTransportListenAddr obfs4 0.0.0.0:6666

# Local communication port between Tor and obfs4.  Always set this to \"auto\".
# \"Ext\" means \"extended\", not \"external\".  Don't try to set a specific port number, nor listen on 0.0.0.0.
ExtORPort auto

ContactInfo <st1038@georgetown.edu>

# Pick a nickname that you like for your bridge.  This is optional.
Nickname OBFS5Test" | sudo tee /etc/tor/torrc

ln -s /etc/apparmor.d/system_tor /etc/apparmor.d/disable/
sudo apparmor_parser -R /etc/apparmor.d/system_tor

systemctl restart tor

cat /var/log/syslog | grep "Your Tor server's identity key fingerprint is" -i
tail /var/lib/tor/pt_state/obfs4_bridgeline.txt
