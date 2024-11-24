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

package mysqlscanner

import (
	"net"

	log "github.com/sirupsen/logrus"
)

// Config is the high level framework options that will be parsed
// from the command line
type Config struct {
	Timeout     int    `short:"t" long:"timeout" default:"10" description:"Timeout for TCP connection in seconds."`
	Cooldown    int    `short:"c" long:"cooldown" default:"2" description:"Time to Wait after last MySQL packet is recieved to close remaining connections."`
	SourceAddr4 string `short:"4" long:"source-address-ip4" default:"" description:"IPv6 Address of Interface"`
	SourceAddr6 string `short:"6" long:"source-address-ip6" default:"" description:"IPv4 Address of Interface"`
	Interface   string `short:"i" long:"interface" default:"" description:"Interface"`
}

var config Config

func ValidateConfig(config Config) (bool, bool) {
	validIP4 := false
	validIP6 := false

	// Check IPv4 Address
	if config.SourceAddr4 != "" {
		ipaddress := net.ParseIP(config.SourceAddr4)
		if ipaddress == nil {
			log.Fatal("Not a Valid IPv4 Address: %s", config.SourceAddr4)
		} else if ipaddress.To4() != nil {
			validIP4 = true
		} else {
			log.Fatal("Not a Valid IPv4 Address: %s", config.SourceAddr4)
		}
	} else {
		log.Warn("No IPv4 Address Provided")
	}

	// Check IPv6 Address
	if config.SourceAddr6 != "" {
		ipaddress := net.ParseIP(config.SourceAddr6)
		if ipaddress == nil {
			log.Fatal("Not a Valid IPv6 Address: %s", config.SourceAddr6)
		} else if ipaddress.To4() == nil {
			validIP6 = true
		} else {
			log.Fatal("Not a Valid IPv6 Address: %s", config.SourceAddr6)
		}
	} else {
		log.Warn("No IPv6 Address Provided")
	}

	if validIP4 == false && validIP6 == false {
		log.Fatal("No Valid Interface Address Provided")
	}

	// Check Interface
	if config.Interface == "" {
		log.Fatal("No Interface Provided")
	}

	return validIP4, validIP6
}
