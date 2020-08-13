# icmptxe
## ICMPTXE - extended/encrypted version, based on ICMPTX

ICMPTXE is a program that allows a user with root privledges to create a
virtual network link between two computers, encapsulating data inside of
ICMP packets.
By comparing to ICMPTX it has some issues fixed and extra ability to hide
fact of tunneling by simple XOR-based encryption, to help bypass filtering.

## -- license --

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this ICMPTX.  If not, see <http://www.gnu.org/licenses/>.

## -- basic usage instructions --

First, make sure you have the tun module from your 2.6 kernel loaded up
or compiled into your kernel on both ends of your tunnel.

Second, compile the code on both the client machine and the server you
wish to tunnel your traffic between.

Third, on the server side, do something like

./icmpxe -s &

sleep 1

ifconfig tun0 10.0.3.1 netmask 255.255.255.0


Fourth, on the client side, do something like

./icmptxe -c 1.2.3.4 &

sleep 1

ifconfig tun0 10.0.3.2 netmask 255.255.255.0


OR: There're helper scripts _server.sh and _client.sh. Run first on server
another on client, givin server IP as argument, they will do the job.

Replace 1.2.3.4 with your internet-accessible IP on the server. At this
point you should have a simple link between the client and server. On
the client, you should be able to ping 10.0.3.1 and get a response. Note
that there are several levels of irony involved in receiving the responses.
SSH tunneling can be used at this point for secure communication over the
channel. Note that there is no encryption capability provided directly by
ICMPTX.

Once you've confirmed that the tunnel does in fact work, routing should be
easily accomplished. The tun interfaces are just like any other ethernet
devices on your system and can be used as such, for example:

route add -net 192.168.0.0/24 gw 10.0.3.1

executed on the client could add a route to your server's DMZ segment.
Access to systems on the 192.168.0.0/24 subnet from the client would
then be transparently tunneled through the ICMPTX connection.

## Multiple clients support

Multiple simultaneous clients are supported, however this requires to have
tunnel subnet not wider than /24, cuz last octet of client's address is used as
clients table key index, so it should be unique across all connected clients.

## -- who's to blame for all this? --

ICMPTXE has an interesting lineage. The code for the ICMP handling was
originally included from the itunnel program. Tun interface handling
was included from the VTun project, originally authored by Maxim
Krasnyansky. The two were brought together by edi / teso. From there,
Siim Põder cleaned up the code and wrote a short article about it,
possibly still available at http://www.linuxexposed.com/content/view/153/52/ .
That seems to be where Thomer Gil found it, after which he further cleaned
it up and presented it at http://thomer.com/icmptx/, which is where I,
John Plaxco, came across it. Further and newer information may be
available at the project's homepage at http://github.com/jakkarth/icmptx.
Then somebody extended it by adding obfuscation of encapsulated traffic,
implementing support for multiple clients and fixing several issues that
were preventing working through NATs.