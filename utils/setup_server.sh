#!/usr/bin/env bash

# NOTE: Targets Ubuntu 20.04 LTS
# This script targets testing servers - I would not use it to spin up servers that are meant to be used in the wild.
# TODO: Make command line option for OBFS4

if [ "$1" == "" ]; then
	echo "You must pass an IP as the first parameter"
	exit 1
fi

IP=$1
PORT='6666'
PTDIR='/pt'
OBFSDIR="$PTDIR/obfs"
BRIDGELINE="$OBFSDIR/bridgeline.txt"
LOG='false'
LOGLEVEL='DEBUG'
CONTACT='st1038@georgetown.edu'

apt update

apt install apt-transport-https software-properties-common -y
echo "deb https://deb.torproject.org/torproject.org focal main
deb-src https://deb.torproject.org/torproject.org focal main" | tee /etc/apt/sources.list.d/tor_sources.list

wget -qO- https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc | gpg --import
gpg --export A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89 | apt-key add -

add-apt-repository ppa:longsleep/golang-backports -y

apt update
apt install tor deb.torproject.org-keyring git golang-go -y

mkdir -p $OBFSDIR
git clone https://github.com/RACECAR-GU/obfsX.git $OBFSDIR

cd $OBFSDIR

go build -o bin ./obfs4proxy

rm /etc/tor/torrc

echo "BridgeRelay 1

PublishServerDescriptor 0

# This port must be externally reachable.
# Avoid port 9001 because it's commonly associated with Tor and censors may be scanning the Internet for this port.
ORPort 9999

ServerTransportPlugin obfs4,obfs5 exec $OBFSDIR/bin -enableLogging=$LOG -logLevel $LOGLEVEL

# This port must be externally reachable and must be different from the one specified for ORPort.
# Avoid port 9001 because it's commonly associated with Tor and censors may be scanning the Internet for this port.
ServerTransportListenAddr obfs5 0.0.0.0:$PORT

# Local communication port between Tor and obfs4.  Always set this to \"auto\".
# \"Ext\" means \"extended\", not \"external\".  Don't try to set a specific port number, nor listen on 0.0.0.0.
ExtORPort auto

ContactInfo <$CONTACT>

# Pick a nickname that you like for your bridge.  This is optional.
Nickname OBFS5Test" | sudo tee /etc/tor/torrc

ln -s /etc/apparmor.d/system_tor /etc/apparmor.d/disable/
sudo apparmor_parser -R /etc/apparmor.d/system_tor

systemctl restart tor

# Tor takes time to start, our bridgeline needs to cook...
sleep 2m

FINGERPRINT=$(cat /var/log/syslog | grep "Your Tor server's identity key  fingerprint is" |\
	sed -n 1p | cut -d "'" -f3 | cut -d " " -f2)
tail -n 1 /var/lib/tor/pt_state/obfs4_bridgeline.txt > $BRIDGELINE

sed -i "s/<PORT>/$PORT/g" $BRIDGELINE
sed -i "s/obfs4/obfs5/g" $BRIDGELINE
sed -i "s/<FINGERPRINT>/$FINGERPRINT/g" $BRIDGELINE
sed -i "s/<IP>/$IP/g" $BRIDGELINE
