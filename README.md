# MySQLScanner

The MySQLScanner is a tool for scanning SQL servers and extracting banner information. It follows a two step process:
1. It first initiates a TCP connection with input IP/host pairs. 
2. It listens for (and records packet information from) incoming SQL Server Hello packets. 

MySQLScanner is compatible with both IPv4 and IPv6, and can be run on an interface supporting both (with mixed IPv4 and IPv6 input). 

## Installation

### Dependencies
`mysqlscanner` uses go version `1.21+` and `gopacket` library which requires libpcap header files to be present. The header files and libpcap can be installed as follows:
```
$> sudo apt-get install git libpcap-dev
```

### Compiling
In order to compile the scanner, you can use the Makefile as:
```
$> make
```

If you also would like to update all other modules, and recompile them, run the following:
```
$> make update
```
This will clean the cache and update/recompile all packages along with `mysqlscanner`.

It is suggested to run this, when you update your Go version.

## Usage

The program can be run as follows:
```
cat input_file.txt | mysqlscanner -4 <ipv4 source address> -6 <ipv6 source address> -i <interface> -t <TCP timeout (optional)> -c <cooldown (optional)>  > output_file.txt
```
Please ensure the input IPv4 and/or IPv6 source addresses match the source addresses connected to the interface in question. 

Input format for input file:
```
ip,port
ip,port
```
IP addresses can be formatted as either IPv4 or IPv6 addresses. 

Outputs are formatted in JSON output. All IPv6 addresses will be in compressed format in the output JSON. 

## Testing
A list of test cases (requiring responsive IPv4 and/or IPv6 host/port pairs running MySQL) are provided in TESTCASES.md. 


## Limitations:
There are currently a handful of limitations of this SQL scanner, detailed below:
1. TCP connections are made in sequence. This means, if all host/port pairs are down, the program may take up to timeout*(number of host/port pairs) to complete. This could be solved by either directly creating the SYN connection packets via gopacket (and sending TCP connection packets independently), or by creating multiple goroutines for connecting via Dial. 
2. This program only supports SQL server discovery for SQL servers using Handshake version 10 (meaning SQL version 4.1+). While Handshake version 10 is most common, it may miss some servers. 
3. Currently this program does not support TLS connections to collect certificate data. 
4. Currently there is no packet validation on incoming TCP packets to ensure they are in fact sent in response to scans. 
