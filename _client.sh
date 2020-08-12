killall icmptxe && sleep 3
./icmptxe -c $1 &
sleep 2
ifconfig tun0 10.0.3.2 netmask 255.255.255.0
ifconfig tun0 mtu 512
