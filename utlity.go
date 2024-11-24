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
// https://github.com/zmap/zgrab2/blob/178d984996c518848e8c1133b6ce52ffaa621579/config.go

package mysqlscanner

import (
	"net"
	"strings"

	flags "github.com/jessevdk/go-flags"
	log "github.com/sirupsen/logrus"
)

var parser *flags.Parser

func init() {
	parser = flags.NewParser(&config, flags.Default)
}

func ParseCommandLine(args []string) ([]string, Config, error) {
	posArgs, err := parser.ParseArgs(args)
	return posArgs, config, err
}

func ParseNetStringAndIP(config Config, ipstring string, validIP4 bool, validIP6 bool) (string, string, string, string) {
	// Split string
	parts := strings.Split(ipstring, ",")

	if len(parts) < 2 {
		log.Errorf("Not a Valid IP/Port pair: %s", ipstring)
		return "", "", "", ""
	}

	// Create formatted string
	ipaddress := net.ParseIP(parts[0])
	if ipaddress == nil {
		log.Errorf("Not a Valid IP/Port pair: %s", ipstring)
		return "", "", "", ""
	}

	// Check IPv4 vs. IPv6 format.
	var ipaddressString string
	var networkString string
	if ipaddress.To4() != nil && validIP4 == true {
		ipaddressString = ipaddress.String() //+ ":" + strings.TrimRight(parts[1], "\n")
		networkString = "tcp4"
	} else if ipaddress.To4() == nil && validIP6 == true {
		ipaddressString = "[" + ipaddress.String() + "]" //+ ":" + strings.TrimRight(parts[1], "\n")
		networkString = "tcp6"
	} else {
		log.Error("Correct Interface not specified.")
		return "", "", "", ""

	}

	// Get formatted string and port for ConnectTCP
	inputLocalAddress := ""
	if networkString == "tcp4" {
		inputLocalAddress = config.SourceAddr4
	} else {
		inputLocalAddress = config.SourceAddr6
	}

	port := strings.TrimRight(parts[1], "\n")

	return ipaddressString, port, networkString, inputLocalAddress
}
