# Test Cases for MySQL Scanner

Because this is an active scanning tool, full testing of features requires addresses responsive on the MySQL protocol. Specifically:
1. 1-2 responsive IPv4 address/port pairs running MySQL. 
2. 1-2 repsonsive IPv6 address/port pairs running MySQL. 
3. 1 IPv4 address/port pair running MySQL but returning an authentication error. 
4. 1 IPv6 address/port pair running MySQL but returning an authentication error. 
5. 1 IPv4 address/port pair open on TCP but not running MySQL.  
6. 1 IPv6 address/port pair open on TCP but not running MySQL. 
7. 1 unresponsive IPv4 address/port pair. 
8. 1 unresponsive IPv6 address/port pair. 

IPv4 addresses can be found through Censys's search (https://search.censys.io/). For responsive IPv6 addresses we suggest starting with hitlist services (like the IPv6 hitlist: https://ipv6hitlist.github.io/). 

THe following is a list of test cases. IPv4 and IPv6 network interfaces are needed where specified. 

## Input
1. SourceAddress4 and SourceAddress6 not supplied -> error
2. Only supplying SourceAddress4 -> error for input IPv6 addresses, proper operation for input IPv4 addresses
3. Only supplying SourceAddress6 -> error for input IPv4 addresses, proper operation for input IPv6 addresses
4. Supply both SourceAddress4 and SourceAddress6 -> Proper operation for both IPv4 and IPv6
5. SourceAddress4 not an IP address -> Error
6. SourceAddress6 not an IP address -> Error
4. Network Interface not supplied. -> error
5. Network Interface doesn't exist. -> error in pcap listener.

## IPv4 only (interface with IPv4 address required)
1. Single Host/port with MySQL running on port. 
3. Single Host/port with MySQL running but returns authentication error. 
3. Single Host/port with TCP open but not running MySQL.
4. Single Host/port not open. 
5. Multiple Hosts with MySQL running on port. 
6. Single host on multple ports. 

## IPv6 only (interface with IPv6 address required)
1. Single Host/port with MySQL running on port. 
3. Single Host/port with MySQL running but returns authentication error. 
3. Single Host/port with TCP open but not running MySQL.
4. Single Host/port not open. 
5. Multiple Hosts with MySQL running on port. 
6. Single host on multple ports. 

## IPv4 and IPv6 (interface with both IPv4 and IPv6 addresses required)
1. Single IPv4 Host/port with MySQL running on port. 
3. Single IPv4 Host/port with MySQL running but returns authentication error. 
3. Single IPv4 Host/port with TCP open but not running MySQL.
4. Single IPv4 Host/port not open. 
5. Multiple IPv4 Hosts with MySQL running on port. 
6. Single IPv4 host on multple ports. 

7. Single IPv6 Host/port with MySQL running on port. 
8. Single IPv6 Host/port with MySQL running but returns authentication error. 
9. Single IPv6 Host/port with TCP open but not running MySQL.
10. Single IPv6 Host/port not open. 
11. Multiple IPv6 Hosts with MySQL running on port. 
12. Single IPv6 host on multple ports. 

13. Single IPv4 host/port and Single IPv6 host/port with mysql running. 
14. Single IPv4 host/port and Single IPv6 host/port with MySQL running but returns authentication error. 
15. Single IPv4 host/port and Single IPv6 host/port with TCP open but not running MySQL.
16. Single IPv4 host/port and Single IPv6 host/port with TCP not open. 
17. Multiple IPv4 and IPv6 host/port pairs. 


