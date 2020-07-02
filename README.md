# goportscan

This Go Script is used to run port scans via nmap, and identify particular 
protocols running on open ports through a custom signatures file

## Examples

### To discover open ports
To discover the TCP ports for targets listed in file `targets.txt`, run the command:

```
$ cat targets.txt
www.google.com
www.hotmail.com

$ cat targets | sudo go run goportscan.go
[tcp] http://www.google.com:80
[tcp] https://www.google.com:443
[tcp] unknown://www.hotmail.com:100
[tcp] smb://www.hotmail.com:139
[tcp] https://www.hotmail.com:443
[tcp] smb://www.hotmail.com:445
```

To scan for all TCP 65536 ports, select `-p all`. By default, UDP scan will only be run on the top `25` ports. 

### Run version scan and store results
To run a version scan and aggressive scan (which includes OS Scanning via `-A` nmap flag)  on a target `www.google.com` and store the results in an 
output folder `out-nmap-www.google.com`

```
$ echo -e "www.google.com" | sudo go run goportscan.go -skipUDP -runVersionScan -osScan -o out-nmap
[tcp] http://www.google.com:80
[tcp] https://www.google.com:443

$ cat out-nmap-www.google.com/out-grep-tcp.txt
Host: 172.217.167.68 (syd15s06-in-f4.1e100.net) Status: Up
Host: 172.217.167.68 (syd15s06-in-f4.1e100.net) Ports: 80/open/tcp//http//gws/, 443/open/tcp//ssl|https//gws/      Ignored State: filtered (998)
# Nmap done at Sun Jun 14 11:17:27 2020 -- 1 IP address (1 host up) scanned in 81.49 seconds
```

### Verbose mode and skip UDP scan
To show commands as they are executed when running on `www.google.com`, select `-v` flag and `-runUDP` to run UDP scanning

```
$ echo -e "www.google.com" | sudo go run goportscan.go -runUDP -v

2020/06/14 11:46:19 [v] Executing cmd: sudo nmap --open --top-ports 1000 -sS -Pn www.google.com
2020/06/14 11:46:49 [v] Output of cmd 'sudo nmap --open --top-ports 1000 -sS -Pn www.google.com':
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-14 11:46 AEST
Nmap scan report for www.google.com (172.217.167.68)
Host is up (0.061s latency).
rDNS record for 172.217.167.68: syd15s06-in-f4.1e100.net
Not shown: 998 filtered ports
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT    STATE SERVICE
80/tcp  open  http
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 25.10 seconds

[tcp] http://www.google.com:80
[tcp] https://www.google.com:443
```
