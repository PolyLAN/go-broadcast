package main

import (
	"bufio"
	"fmt"
    "net"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
    commentPrefix        byte          = '#'
    rangeSeparator       string        = "-"
	retransmitBufferSize int32         = 1024
	snapshot_len         int32         = 2048
	promiscuous          bool          = false
	timeout              time.Duration = 500 * time.Millisecond
)

type Interface struct {
	pcap.Interface
	SendBuffer chan gopacket.Packet
}

func InterfaceFromName(name string) (Interface, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return Interface{}, err
	}
	for _, device := range devices {
		if device.Name != name {
            continue
		}

        v4addresses := []pcap.InterfaceAddress{}
        for _, address := range device.Addresses {
            if address.Broadaddr != nil {
                v4addresses = append(v4addresses, address)
            }
        }
        device.Addresses = v4addresses
        return Interface{device, make(chan gopacket.Packet, retransmitBufferSize)}, nil
	}
    return Interface{}, fmt.Errorf("Cannot find interface %s", name)
}
func portInPorts(port uint16, ports []uint16) bool {
	for _, p := range ports {
		if p == port {
			return true
		}
	}
	return false
}

func bufferRetransmit(packet gopacket.Packet, destinationDevices []Interface, ports *[]uint16) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if (ipLayer != nil) && (udpLayer != nil) {
		ipPacket, _ := ipLayer.(*layers.IPv4)
		udpPacket, _ := udpLayer.(*layers.UDP)

		//if ipPacket.TTL != proxyTTL && portInPorts(uint16(udpPacket.DstPort), *ports) {

		if portInPorts(uint16(udpPacket.DstPort), *ports) {
	log.Printf("Forwarding %s:%d -> %s:%d\n", ipPacket.SrcIP, udpPacket.SrcPort, ipPacket.DstIP, udpPacket.DstPort)
			for _, destinationDevice := range destinationDevices {
                if ipPacket.DstIP != nil {
				    destinationDevice.SendBuffer <- packet
                } else {
				    log.Printf("Didn't sent (no Dest IP) to %s\n", destinationDevice.Name)
                }
			}
		}
	}
}

func getRealBroadcastAddresses(device Interface) []net.IP{
    brdAddrs := []net.IP{}
    for _, address := range device.Addresses {
                    if address.Broadaddr.Equal(address.IP) {
                        //TODO: pcap lib seems to return invalid broadcast address 
                        // if the underlying interface defines more than one ip address.
                        // In those case, the Broadcast address will be equal to the ip address.
                        continue
                    }
        brdAddrs = append(brdAddrs, address.Broadaddr)
    }
    return brdAddrs
}


func interfaceWorker(device Interface, destinationDevices []Interface, ports *[]uint16) error {
	// Open device
	handle, err := pcap.OpenLive(device.Name, snapshot_len, promiscuous, timeout)
	if err != nil {
		return err
	}
	defer handle.Close()

	bpfFilter := "udp and (dst host 255.255.255.255"
	for _, address := range getRealBroadcastAddresses(device) {
        bpfFilter += " or dst host " + address.String()
	}
	bpfFilter += ")"
	handle.SetBPFFilter(bpfFilter)
    deviceNames:= []string{}
    for _, d := range destinationDevices {
        deviceNames = append(deviceNames, d.Name)
    }


    log.Printf("Using filter '%s' for interface %s -> %v with %v addresses\n", bpfFilter, device.Name, deviceNames, device.Addresses)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		case incomingPacket := <-packetSource.Packets():
			bufferRetransmit(incomingPacket, destinationDevices, ports)

		case outgoingPacket := <-device.SendBuffer:
			//send Packet and rewrite the destAddr
			ipLayer := outgoingPacket.Layer(layers.LayerTypeIPv4)
			udpLayer := outgoingPacket.Layer(layers.LayerTypeUDP)

			if ipLayer != nil && udpLayer != nil {
				ipPacket, _ := ipLayer.(*layers.IPv4)
				udpPacket, _ := udpLayer.(*layers.UDP)

				for _, address := range getRealBroadcastAddresses(device) {

					ipPacket.DstIP = address
					ipPacket.TTL -= 1
					options := gopacket.SerializeOptions{
						ComputeChecksums: true,
						FixLengths:       true,
					}
					udpPacket.SetNetworkLayerForChecksum(ipPacket)

                    newBuffer := gopacket.NewSerializeBuffer()
				log.Printf("Sending %s:%d on %s", ipPacket.DstIP, udpPacket.SrcPort, device.Name)
                    err := gopacket.SerializePacket(newBuffer, options, outgoingPacket)
                    if err != nil {
                        log.Println(err)
                        continue
                    }
                    outgoingPacket := newBuffer.Bytes()
                    handle.WritePacketData(outgoingPacket)
				}
			}
		}
	}
	return nil
}

func readPortList(confFile string) ([]uint16, error) {
	csvFile, err := os.Open(confFile)
	if err != nil {
		return nil, err
	}
    ports := []uint16{}
	lineReader := bufio.NewReader(csvFile)
    if lineReader == nil {
        log.Fatal(err)
    }

	for {
		line, _, err := lineReader.ReadLine()
		if err != nil {
			if err == io.EOF {
				break
			} else {
				return ports, err
			}

		}
		lineStr := string(line)

        // Skip empty line and comment (#)
		if len(lineStr) > 0 && lineStr[0] == commentPrefix {
            log.Println(lineStr)
			continue
		}

		columns := strings.SplitN(lineStr, ",", 2)
        log.Println(lineStr)
        log.Println(columns[0])
        s := strings.Split(columns[0], rangeSeparator)
        if len(s) == 1 {
            s = append(s, s[0])
        }

		start, err := strconv.ParseUint(s[0], 10, 16)
		if err != nil {
            return nil, err
		}
		end, err := strconv.ParseUint(s[1], 10, 16)
		if err != nil {
            return nil, err
		}

        for i := start; i <= end; i++ {
            ports = append(ports, uint16(i))
        }

	}
	return ports, nil
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "-h" {
		log.Println("Usage: ", os.Args[0], "[INTERFACE] ...")
		return
	}
	ports, err := readPortList("games.csv")
    log.Printf("Ports founds %v\n", ports)
	if err != nil {
		log.Fatal(err)
	}
	devices := []Interface{}
	for _, deviceName := range os.Args[1:] {
		device, err := InterfaceFromName(deviceName)

        if err != nil {
            log.Fatal(err)
        }

		devices = append(devices, device)
	}

	for i, v := range devices {
		otherDevices := make([]Interface, len(devices)-1, len(devices)-1)
		for otherDeviceIndex := 0; otherDeviceIndex < len(devices); otherDeviceIndex++ {
			if otherDeviceIndex != i {
				if otherDeviceIndex > i {
					otherDevices[otherDeviceIndex-1] = devices[otherDeviceIndex]
				} else {
					otherDevices[otherDeviceIndex] = devices[otherDeviceIndex]
				}
			}
		}
		log.Println("starting worker on", v.Name)
		if i == len(devices)-1 {
			interfaceWorker(v, otherDevices, &ports)
		} else {
			go interfaceWorker(v, otherDevices, &ports)
		}
	}
}
