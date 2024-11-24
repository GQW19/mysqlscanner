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
	"bytes"
	"encoding/binary"
	"reflect"
)

type ServerCapabilities struct {
	LONGPASSWORD                             bool
	FOUNDROWS                                bool
	LONGCOLUMNFLAGS                          bool
	CONNECTWITHDATABASE                      bool
	DONTALLOWDATABASETABLECOLUMN             bool
	CANUSECOMPRESSION                        bool
	ODBCCLIENT                               bool
	LOADDATALOCAL                            bool
	IGNORESPACESBEFOREPARENTHESIS            bool
	SPEAKS41NEW                              bool
	INTERACTIVECLIENT                        bool
	SWITCHTOSSLAFTERHANDSHAKE                bool
	IGNORESIGPIPES                           bool
	KNOWSABOUTTRANSACTIONS                   bool
	SPEAKS41OLD                              bool
	CANDO41AUTH                              bool
	MULITPLESTATEMENTS                       bool
	MULTIPLERESULTS                          bool
	PSMULTIPLERESULTS                        bool
	PLUGINAUTH                               bool
	CONNECTATTRS                             bool
	PLUGINAUTHLENENC                         bool
	CLIENTCANHANDLEEXPIREDPASSWORDS          bool
	SESSIONVARIABLETRACKING                  bool
	DEPRECATEEOF                             bool
	CLIENTCANHANDLEOPTIONALRESULTSETMETADATA bool
	ZSTDCOMPRESSIONALGORITHM                 bool
	QUERYATTRIBUTES                          bool
	MULTIFACTORAUTHENTICATION                bool
	CAPABILITYEXTENSION                      bool
}

type ServerStatus struct {
	INTRANSACTION       bool
	AUTOCOMMIT          bool
	MULTIQUERY          bool
	MORERESULTS         bool
	BADINDEXUSED        bool
	NOINDEXUSED         bool
	CURSOREXISTS        bool
	LASTROWSENT         bool
	DATABASEDROPPED     bool
	NOBACKSLASHESCAPES  bool
	METADATACHANGED     bool
	QUERYWASSLOW        bool
	PSOUTPARAMS         bool
	INTRANSREADONLY     bool
	SESSIONSTATECHANGED bool
}

type MySQlInformation struct {
	IPAddress            string
	DstPort              string
	Issql                bool
	Sqlerror             bool
	Version              int
	VersionString        string
	ThreadID             uint32
	Salt1                string
	ServerCapabilities   ServerCapabilities
	ServerLanguage       string
	ServerStatus         ServerStatus
	Salt2                string
	AuthenticationPlugin string
	Errorcode            uint16
	Errormessage         string
}

type MySQLError struct {
	IPAddress    string
	DstPort      string
	Issql        bool
	Sqlerror     bool
	Errorcode    uint16
	Errormessage string
}

type TCPErrorStruct struct {
	IPAddress    string
	DstPort      string
	Issql        bool
	Errormessage string
}

func parseLanguage(languagebit []byte) string {

	if bytes.Equal(languagebit, []byte{0x01}) {
		return "big5_chinese_ci"
	} else if bytes.Equal(languagebit, []byte{0x02}) {
		return "latin2_czech_cs"
	} else if bytes.Equal(languagebit, []byte{0x03}) {
		return "dec8_swedish_ci"
	} else if bytes.Equal(languagebit, []byte{0x04}) {
		return "cp850_general_ci"
	} else if bytes.Equal(languagebit, []byte{0x05}) {
		return "latin1_german1_ci"
	} else if bytes.Equal(languagebit, []byte{0x06}) {
		return "hp8_english_ci"
	} else if bytes.Equal(languagebit, []byte{0x07}) {
		return "koi8r_general_ci"
	} else if bytes.Equal(languagebit, []byte{0x08}) {
		return "latin1_swedish_ci"
	} else if bytes.Equal(languagebit, []byte{0x09}) {
		return "latin2_general_ci"
	} else if bytes.Equal(languagebit, []byte{0x0a}) {
		return "swe7_swedish_ci"
	} else if bytes.Equal(languagebit, []byte{0x21}) {
		return "utf8mb3_general_ci "
	} else if bytes.Equal(languagebit, []byte{0x3f}) {
		return "binary"
	} else {
		return "other"
	}

}

func ParseBit(bit byte) bool {
	if bit > 0 {
		return true
	} else {
		return false
	}
}

func ParseCapabilities(capabilities []byte, capabilities_ext []byte) ServerCapabilities {
	serverCapabilitiesObject := ServerCapabilities{}
	attrNames := []string{"LOADDATALOCAL", "ODBCCLIENT", "CANUSECOMPRESSION", "DONTALLOWDATABASETABLECOLUMN", "CONNECTWITHDATABASE",
		"LONGCOLUMNFLAGS", "FOUNDROWS", "LONGPASSWORD",
		"CANDO41AUTH", "SPEAKS41OLD", "KNOWSABOUTTRANSACTIONS",
		"IGNORESIGPIPES", "SWITCHTOSSLAFTERHANDSHAKE", "INTERACTIVECLIENT", "SPEAKS41NEW", "IGNORESPACESBEFOREPARENTHESIS"}
	attrNamesExtended := []string{"SESSIONVARIABLETRACKING", "CLIENTCANHANDLEEXPIREDPASSWORDS", "PLUGINAUTHLENENC", "CONNECTATTRS", "PLUGINAUTH",
		"PSMULTIPLERESULTS", "MULTIPLERESULTS", "MULITPLESTATEMENTS",
		"", "", "CAPABILITYEXTENSION", "MULTIFACTORAUTHENTICATION", "QUERYATTRIBUTES", "ZSTDCOMPRESSIONALGORITHM",
		"CLIENTCANHANDLEOPTIONALRESULTSETMETADATA", "DEPRECATEEOF"}

	// Parse Capabilities
	for i := 0; i < len(capabilities)*8; i++ {
		bit := capabilities[i/8] & (1 << uint(7-i%8))
		bool_value := ParseBit(bit)
		value := reflect.ValueOf(&serverCapabilitiesObject).Elem().FieldByName(attrNames[i])
		if value.CanSet() {
			value.Set(reflect.ValueOf(bool_value))
		}
	}

	// Parse Extended Capabilities
	for i := 0; i < len(capabilities_ext)*8; i++ {
		if attrNamesExtended[i] != "" {
			bit := capabilities_ext[i/8] & (1 << uint(7-i%8))
			bool_value := ParseBit(bit)
			value := reflect.ValueOf(&serverCapabilitiesObject).Elem().FieldByName(attrNamesExtended[i])
			if value.CanSet() {
				value.Set(reflect.ValueOf(bool_value))
			}
		}
	}

	return serverCapabilitiesObject
}

func parseServerStatus(serverstatus []byte) ServerStatus {
	serverStatusObject := ServerStatus{}

	attrNames := []string{"LASTROWSENT", "CURSOREXISTS", "NOINDEXUSED", "BADINDEXUSED ", "MORERESULTS", "MULTIQUERY", "AUTOCOMMIT", "INTRANSACTION",
		"", "SESSIONSTATECHANGED", "INTRANSREADONLY", "PSOUTPARAMS", "QUERYWASSLOW", "METADATACHANGED", "NOBACKSLASHESCAPES", "DATABASEDROPPED"}

	for i := 0; i < len(serverstatus)*8; i++ {
		if attrNames[i] != "" {
			bit := serverstatus[i/8] & (1 << uint(7-i%8))
			bool_value := ParseBit(bit)
			value := reflect.ValueOf(&serverStatusObject).Elem().FieldByName(attrNames[i])
			if value.CanSet() {
				value.Set(reflect.ValueOf(bool_value))
			}
		}
	}
	return serverStatusObject
}

func ParseMySQL(applicationPayload []byte) MySQlInformation {

	mysqlinformation := MySQlInformation{Issql: true}
	mysqlinformation.Version = int(applicationPayload[4])

	end := 5 + 1
	for i := end; i < len(applicationPayload); i++ {
		if applicationPayload[i] == 0 {
			end = i
			break
		}
	}

	// Add Version String
	mysqlinformation.VersionString = string(applicationPayload[5:end])

	// Add ThreadID
	mysqlinformation.ThreadID = binary.LittleEndian.Uint32(applicationPayload[end+1 : end+5])
	end = end + 5

	// Add Salt 1
	mysqlinformation.Salt1 = string(applicationPayload[end : end+8])
	end = end + 9

	// Add Capabilities
	mysqlinformation.ServerCapabilities = ParseCapabilities(applicationPayload[end:end+2], applicationPayload[end+5:end+7])
	end = end + 2

	//  Add Language
	mysqlinformation.ServerLanguage = parseLanguage(applicationPayload[end : end+1])
	end = end + 1

	// Add Server Status
	mysqlinformation.ServerStatus = parseServerStatus(applicationPayload[end : end+2])
	end = end + 4

	// Add Auth Plugin
	salt_end := len(applicationPayload)
	if bytes.Equal(applicationPayload[end:end+1], []byte{0x00}) {
	} else {
		length := int(applicationPayload[end : end+1][0])
		mysqlinformation.AuthenticationPlugin = string(applicationPayload[len(applicationPayload)-length-1 : len(applicationPayload)])
		salt_end = len(applicationPayload) - length - 1
	}

	// Add Second Salt
	end = end + 1
	salt_begin := 0
	for i := end; i < len(applicationPayload); i++ {
		if applicationPayload[i] != 0 {
			salt_begin = i
			break
		}
	}
	mysqlinformation.Salt2 = string(applicationPayload[salt_begin:salt_end])
	return mysqlinformation
}

func ParseMySQLError(applicationPayload []byte) MySQlInformation {
	mysqlinformation := MySQlInformation{Issql: true, Sqlerror: true}

	// Add Error Code
	mysqlinformation.Errorcode = binary.LittleEndian.Uint16(applicationPayload[5:7])

	// Add Text Error
	mysqlinformation.Errormessage = string(applicationPayload[7:len(applicationPayload)])
	return mysqlinformation

}
