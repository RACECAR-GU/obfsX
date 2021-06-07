cd ~/projects/racecar/channel_obfuscation/obfsX
go build -o obfs4proxy/obfs4proxy ./obfs4proxy
sudo rm /home/framework/tor-browser-linux64-9.0.4_en-US/tor-browser_en-US/Browser/TorBrowser/Tor/PluggableTransports/obfs4proxy
sudo cp ~/projects/racecar/channel_obfuscation/obfsX/obfs4proxy/obfs4proxy /home/framework/tor-browser-linux64-9.0.4_en-US/tor-browser_en-US/Browser/TorBrowser/Tor/PluggableTransports/obfs4proxy
sudo rm /usr/bin/obfs4proxy
sudo cp ~/projects/racecar/channel_obfuscation/obfsX/obfs4proxy/obfs4proxy /usr/bin/obfs4proxy
sudo systemctl restart tor
