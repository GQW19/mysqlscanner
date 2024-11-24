/*
Copyright 2024 Grant Williams

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
// Some parts of this code is modified from:
// LZR: https://github.com/stanford-esrg/lzr
// Scanv6: https://github.com/IPv6-Security/scanv6

package mysqlscanner

import (
	"bytes"
	"fmt"
	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	log "github.com/sirupsen/logrus"
)

func handlePacket(packet gopacket.Packet) MySQlInformation {
	// Get IP address
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		ipLayer = packet.Layer(layers.LayerTypeIPv6)
	}

	ipString := ""
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		if ip == nil {
			ip, _ := ipLayer.(*layers.IPv6)
			ipString = ip.SrcIP.String()
		} else {
			ipString = ip.SrcIP.String()
		}
	}

	// Get Port
	tcpLayer := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	srcPort := strconv.Itoa(int(tcpLayer.SrcPort))

	// Get Application Layer
	applicationLayer := packet.ApplicationLayer()

	if applicationLayer != nil {
		applicationPayload := applicationLayer.Payload()
		// Based on LZR MySQL identification criteria
		if bytes.Equal([]byte(applicationPayload[3:4]), []byte{0x00}) && bytes.Equal([]byte(applicationPayload[4:5]), []byte{0x0a}) {
			mysqlFields := ParseMySQL(applicationPayload)
			mysqlFields.IPAddress = ipString
			mysqlFields.DstPort = srcPort
			return mysqlFields
		} else if bytes.Equal([]byte(applicationPayload[3:4]), []byte{0x00}) && bytes.Equal([]byte(applicationPayload[4:5]), []byte{0xff}) {
			mysqlFields := ParseMySQLError(applicationPayload)
			mysqlFields.IPAddress = ipString
			mysqlFields.DstPort = srcPort
			return mysqlFields
		}
		return MySQlInformation{Issql: false}
	}
	return MySQlInformation{Issql: false}
}

func ListenForPCAP(config Config, pcapChannel chan MySQlInformation, setupChannel chan string, validIP4 bool, validIP6 bool) {
	PcapFilterIPv6 := ""
	PcapFilterIPv4 := ""
	PcapFilter := ""

	// BPF Filters adapted from LZR (github.com/stanford-esrg/lzr) and scanv6 (github.com/IPv6-Security/scanv6)
	if validIP6 == true {
		PcapFilterIPv6 = fmt.Sprintf("((ip6 proto 6 && (ip6[53] & 8 != 0)) && ip6 dst %s)", config.SourceAddr6)
	}
	if validIP4 == true {
		PcapFilterIPv4 = fmt.Sprintf("((ip proto 6 && (tcp[tcpflags] & tcp-push != 0)) && ip dst %s )", config.SourceAddr4)
	}

	if validIP4 && validIP6 {
		PcapFilter = "(" + PcapFilterIPv6 + "||" + PcapFilterIPv4 + ")"
	} else if validIP4 {
		PcapFilter = PcapFilterIPv4
	} else if validIP6 {
		PcapFilter = PcapFilterIPv6
	}
    
	// Create Filters and Listen for Packets
	if handle, err := pcap.OpenLive(config.Interface, 1600, true, pcap.BlockForever); err != nil {
		log.Fatal("OpenLive: ", err)
	} else if err := handle.SetBPFFilter(PcapFilter); err != nil {
		log.Fatal("Set BPF Filter: ", err, PcapFilter)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		setupChannel <- "setup"
		for packet := range packetSource.Packets() {
			parsedPacket := handlePacket(packet)
			pcapChannel <- parsedPacket
		}
	}
}
