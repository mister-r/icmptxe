killall icmptxe && sleep 3
./icmptxe -s &
sleep 2
ifconfig tun0 10.0.3.1 netmask 255.255.255.0
ifconfig tun0 mtu 512

