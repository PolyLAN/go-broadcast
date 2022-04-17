go-broadcast is a small go utilities for repeating UDP broadcast packet accross linux interfaces.

It will take a configuration file containing the list of port which broadcast should be mirrored. 
This configuration is contained in games.csv. It will also take a list of the interfaces on which 
it should listen for broadcast packet and mirror the packet.

# Runing it

Edit the list of game to your liking contained in games.csv. This list contains a name used for 
documentation purpose and a port number used for selecting the udp broadcast packet that should be
mirrored. Finally, define the set of interfaces used to receive udp broadcast. This set will also be 
used as destination copy for the udp broadcast packet.
For example, if eth0, eth1 and eth2 are the interface used to receive and mirror broadcast, then using:

```
docker build -t proxy . && docker run --net=host proxy eth1 eth1 eth2
```
Will listen and mirror the broadcast received on any of the interface on all other interfaces.

# Broadcast storm

The naive approach of replicating packet would be to simply take any broadcast packet and copy it 
on all but the interface it originated from. This would be a problem if two proxy would be active 
on the same set of interface. One proxy would take the mirrored packet and mirror them again. This would
create a broadcast storm. We use instead the TTL field of the UDP broadcast packet to mark a packet as 
mirrored. Upon receiving a packet with this TTL, we will ignore it and not mirror it again.
