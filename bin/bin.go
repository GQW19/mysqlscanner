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

package bin

import (
	"bufio"
	"encoding/json"
	"io"
	"mysqlscanner"
	"net"
	"os"
	"time"

	flags "github.com/jessevdk/go-flags"
	log "github.com/sirupsen/logrus"
)

func check(e error) {
	if e != nil {
		log.Fatalln(e)
	}
}

func connectTCP(address string, timeout int, networkString string, localAddress string) (net.Conn, error) {

	localAddr := &net.TCPAddr{IP: net.ParseIP(localAddress)}
	tcpdialer := net.Dialer{Timeout: time.Duration(1000000000 * timeout), LocalAddr: localAddr}

	conn, err := tcpdialer.Dial(networkString, address)

	if err != nil {
		//fmt.Println("Error connecting:", err)
		return conn, err
	}
	return conn, nil
}

func MySQLScannerMain() {

	// Load Flags
	_, config, err := mysqlscanner.ParseCommandLine(os.Args[1:])

	if err != nil {
		flagsErr, ok := err.(*flags.Error)
		if ok && flagsErr.Type == flags.ErrHelp {
			return
		}
		check(err)
	}

	// Check Config Inputs
	validIP4, validIP6 := mysqlscanner.ValidateConfig(config)

	// Create PCAP Listener
	pcapChannel := make(chan mysqlscanner.MySQlInformation, 100000)
	setupChannel := make(chan string, 100000)
	go func() {
		mysqlscanner.ListenForPCAP(config, pcapChannel, setupChannel, validIP4, validIP6)
	}()

	setupConfirmed := <-setupChannel
	if setupConfirmed == "setup" {
		log.Info("Setup PCAP Listener")
		if validIP4 {
			log.Info("Listening on IPv4 Address")
		}
		if validIP6 {
			log.Info("Listening on IPv6 Address")
		}
	} else {
		log.Fatal("Error Setting Up PCAP Listener")
		return
	}

	// Load STDIN File:
	inputFile := os.Stdin
	inputBuffer := bufio.NewReader(inputFile)

	// Read From STDIN and send TCP Handshake
	connections := make(map[string]net.Conn)

	log.Info("Commencing Sending")
	for {
		line, err := inputBuffer.ReadString('\n')
		if err == io.EOF {
			if line == "" {
				break
			}
		} else if err != nil {
			break
		}

		ipaddressString, port, networkString, inputLocalAddress := mysqlscanner.ParseNetStringAndIP(config, line, validIP4, validIP6)
		if ipaddressString == "" {
			continue
		}

		conn, err := connectTCP(ipaddressString+":"+port, config.Timeout, networkString, inputLocalAddress)

		if err != nil {
			objectToWrite := mysqlscanner.TCPErrorStruct{IPAddress: ipaddressString[1 : len(ipaddressString)-1], Issql: false, DstPort: port, Errormessage: err.Error()}
			jsonData, err0 := json.Marshal(objectToWrite)
			check(err0)
			_, err1 := os.Stdout.Write(jsonData)
			check(err1)
			_, err2 := os.Stdout.Write([]byte{'\n'})
			check(err2)
		} else {
			connections[ipaddressString+":"+port] = conn
		}
	}

	// Return Responses
	for loop := true; loop; {
		if len(connections) == 0 {
			break
		}
		select {
		case ipStr := <-pcapChannel:
			if ipStr.Issql == true {
				ipaddress := net.ParseIP(ipStr.IPAddress)
				ipParsingString := ""
				if ipaddress.To4() != nil {
					ipParsingString = ipaddress.String() + ":" + ipStr.DstPort
				} else {
					ipParsingString = "[" + ipaddress.String() + "]" + ":" + ipStr.DstPort
				}
				ipErrorObject := mysqlscanner.MySQLError{}
				var jsonData []byte
				if ipStr.Sqlerror == true {
					ipErrorObject.IPAddress = ipStr.IPAddress
					ipErrorObject.DstPort = ipStr.DstPort
					ipErrorObject.Issql = ipStr.Issql
					ipErrorObject.Sqlerror = ipStr.Sqlerror
					ipErrorObject.Errorcode = ipStr.Errorcode
					ipErrorObject.Errormessage = ipStr.Errormessage
					jsonData, err = json.Marshal(ipErrorObject)
					check(err)
				} else {
					jsonData, err = json.Marshal(ipStr)
					check(err)
				}
				connections[ipParsingString].Close()
				delete(connections, ipParsingString)

				_, err = os.Stdout.Write(jsonData)
				check(err)
				_, err2 := os.Stdout.Write([]byte{'\n'})
				check(err2)
			}

		case <-time.After(time.Duration(config.Cooldown) * 1000 * time.Millisecond):
			// Wait cooldown seconds after the last MySQL packet is recieved
			loop = false
		}
	}

	// Close Any Outstanding Connections
	log.Info("Closing Connections")
	for _, conn := range connections {
		conn.Close()
	}

}
