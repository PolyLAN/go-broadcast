package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type Interface struct {
	pcap.Interface
	SendBuffer chan gopacket.Packet
}

var (
	retransmitBufferSize int32         = 1024
	snapshot_len         int32         = 2048
	promiscuous          bool          = false
	timeout              time.Duration = 500 * time.Millisecond
	proxyTTL             uint8         = 64
)

func InterfaceFromName(name string) (Interface, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return Interface{}, err
	}
	for _, device := range devices {
		if device.Name == name {
			return Interface{device, make(chan gopacket.Packet, retransmitBufferSize)}, nil
		}
	}
	return Interface{}, nil
}
func portInPorts(port uint16, ports []uint16) bool {
	for _, p := range ports {
		if p == port {
			return true
		}
	}
	return false
}

func lastAddr(n *net.IPNet) (net.IP, error) { // works when the n is a prefix, otherwise...
	if n.IP.To4() == nil {
		return net.IP{}, errors.New("Does not support IPv6 addresses.")
	}
	ip := make(net.IP, len(n.IP.To4()))
	binary.BigEndian.PutUint32(ip, binary.BigEndian.Uint32(n.IP.To4())|^binary.BigEndian.Uint32(net.IP(n.Mask).To4()))
	return ip, nil
}

func bufferRetransmit(packet gopacket.Packet, destinationDevices []Interface, ports *[]uint16) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if (ipLayer != nil) && (udpLayer != nil) {
		ipPacket, _ := ipLayer.(*layers.IPv4)
		udpPacket, _ := udpLayer.(*layers.UDP)
		if ipPacket.TTL != proxyTTL && portInPorts(uint16(udpPacket.DstPort), *ports) {
			for _, destinationDevice := range destinationDevices {
				fmt.Printf("%s:%d -> %s:%d\n", ipPacket.SrcIP, udpPacket.SrcPort, ipPacket.DstIP, udpPacket.DstPort)
				fmt.Println("sending to ", destinationDevice.Name)
				destinationDevice.SendBuffer <- packet
			}
		}
	}
}

func interfaceWorker(device Interface, destinationDevices []Interface, ports *[]uint16) error {
	// Open device
	handle, err := pcap.OpenLive(device.Name, snapshot_len, promiscuous, timeout)
	if err != nil {
		return err
	}
	defer handle.Close()
	bpfFilter := "udp and (dst host 255.255.255.255"
	for _, address := range device.Addresses {
		fmt.Println(address.Broadaddr)
		bpfFilter = bpfFilter + " or dst host " + address.Broadaddr.String()
	}
	bpfFilter = bpfFilter + ")"
	handle.SetBPFFilter(bpfFilter)
	fmt.Println("using filter '", bpfFilter, "'")
	fmt.Println("for interface", device, "->", destinationDevices)
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
				for _, address := range device.Addresses {
					ipPacket.DstIP = address.Broadaddr
					ipPacket.TTL = proxyTTL
					options := gopacket.SerializeOptions{
						ComputeChecksums: true,
						FixLengths:       true,
					}
					udpPacket.SetNetworkLayerForChecksum(ipPacket)
					newBuffer := gopacket.NewSerializeBuffer()
					err := gopacket.SerializePacket(newBuffer, options, outgoingPacket)
					if err != nil {
						return err
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
	ports := make([]uint16, 0)
	lineReader := bufio.NewReader(csvFile)
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
		if len(lineStr) > 0 && lineStr[0] == '#' {
			continue
		}
		columns := strings.SplitN(lineStr, ",", 2)
		port, err := strconv.ParseUint(columns[0], 10, 16)
		if err != nil {
			log.Println(err)
			continue
		}
		ports = append(ports, uint16(port))
	}
	return ports, nil
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "-h" {
		fmt.Println("Usage: ", os.Args[0], "[INTERFACE] ...")
		return
	}
	ports, err := readPortList("games.csv")
	if err != nil {
		log.Fatal(err)
	}
	devices := []Interface{}
	for _, deviceName := range os.Args[1:] {
		device, _ := InterfaceFromName(deviceName)
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
		fmt.Println("starting worker on", v.Name)
		if i == len(devices)-1 {
			interfaceWorker(v, otherDevices, &ports)
		} else {
			go interfaceWorker(v, otherDevices, &ports)
		}
	}
}
