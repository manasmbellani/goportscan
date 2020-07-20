package main

// Script is used to run a portscan via nmap (assumed accessible via $PATH var),
// and identify different protocols on host/ip addresses listing

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strings"
	"sync"

	"gopkg.in/yaml.v2"
)

// TopUDPPortsToScan - Top UDP ports to scan
const TopUDPPortsToScan = "25"

// CommonPorts - TCP Common Ports to use only when looking for a host that is alive. Skip UDP scan.
const CommonPorts = "21,22,25,53,80,110,139,143,389,443,445,465,587,636,3306,3389,8080,8443,9080,9443"

// OpenPortLineSig - Regex for identifying line containing an open port in Nmap Output
const OpenPortLineSig = "[0-9]+/(tcp|udp).*open[\\s]+"

// Execute a command to get the output, error
func execCmd(cmdToExec string, verbose bool) string {

	if verbose {
		log.Printf("[v] Executing cmd: %s\n", cmdToExec)
	}

	args := strings.Fields(cmdToExec)
	cmd := exec.Command(args[0], args[1:]...)
	out, err := cmd.CombinedOutput()
	var outStr, errStr string
	if out == nil {
		outStr = ""
	} else {
		//log.Printf("Command Output:%s\n", out)
		outStr = string(out)
	}

	if err == nil {
		errStr = ""
	} else {
		errStr = string(err.Error())
		//log.Printf("Command Error: %s\n", err)
	}

	totalOut := (outStr + "\n" + errStr)
	if verbose {
		log.Printf("[v] Output of cmd '%s':\n%s\n", cmdToExec, totalOut)
	}

	return totalOut
}

type yamlSignatureConfig struct {
	Signatures []struct {
		Protocol string `yaml:"protocol"`
		Regex    string `yaml:"regex"`
	} `yaml:"signatures"`
}

func main() {
	numThreadsPtr := flag.Int("t", 20, "Number of goroutines for port scanning")
	portStrPtr := flag.String("p", "top1000", "TCP ports to scan for - "+
		"can specify individual ports separated with comma (,). Options are: common, top1000, all, or comma-sep custom ports list")
	outprefixfolderPtr := flag.String("o", "",
		"Output folder's prefix to write nmap results. Contains 'hostname'"+
			"too as suffix")
	runVersionScansPtr := flag.Bool("versionScan", false,
		"Include version scans for TCP traffic")
	runOSScanPtr := flag.Bool("osScan", false,
		"Includes TCP OS Scan, version scans via the aggressive scan (-A) option")
	verbosePtr := flag.Bool("v", false, "Show detailed info as cmds exec")
	runUDPPtr := flag.Bool("u", false, "Run UDP scanning of host")
	signaturesFilePtr := flag.String("sigFile", "/opt/goportscan/signatures.yaml",
		"Signatures file to identify protocol signatures")
	flag.Parse()

	numThreads := *numThreadsPtr
	portsStr := *portStrPtr
	verbose := *verbosePtr
	sigFile := *signaturesFilePtr
	runUDP := *runUDPPtr
	outprefixfolder := *outprefixfolderPtr
	runVersionScans := *runVersionScansPtr
	runOSScan := *runOSScanPtr

	// Verbose logging required?
	if !verbose {
		log.SetFlags(0)
		log.SetOutput(ioutil.Discard)
	}

	// Get the ports to scan
	portsArg := ""
	if portsStr == "all" {
		portsArg = "--top-ports 65536"
	} else if portsStr == "top1000" {
		portsArg = "--top-ports 1000"
	} else if portsStr == "common" {
		portsArg = "-p " + CommonPorts
	} else {
		portsArg = "-p " + portsStr
	}

	// Parse the signatures file and get the signatures
	var c yamlSignatureConfig

	// Check if signature file exists
	_, err := os.Stat(sigFile)
	if os.IsNotExist(err) {
		fmt.Printf("[-] Signature file: %s not found\n", sigFile)
		log.Fatalf("[-] Signature file: %s not found\n", sigFile)
	}

	// Read the signature file
	yamlFile, err := ioutil.ReadFile(sigFile)
	if err != nil {
		fmt.Printf("[-] yamlFile.Get err   #%v\n", err)
		log.Fatalf("[-] yamlFile.Get err   #%v\n", err)

	}
	err = yaml.Unmarshal(yamlFile, &c)
	if err != nil {
		fmt.Printf("[-] Unmarshal Error: %v\n", err)
		log.Fatalf("[-] Unmarshal Error: %v\n", err)
	}
	signatures := c.Signatures

	var wg sync.WaitGroup

	// Hosts to port scan
	hosts := make(chan string)

	for i := 0; i < numThreads; i++ {
		wg.Add(1)

		// Go subroutine to perform the port scan
		go func(hosts chan string, wg *sync.WaitGroup) {

			// Start listening on channel for hosts to process
			for host := range hosts {
				// Prepare outfiles to write nmap results in different formats for
				// TCP/UDP
				outfolder := ""
				outfileNormTCP := ""
				outfileGrepTCP := ""
				outfileXMLTCP := ""
				outfileNormUDP := ""
				outfileGrepUDP := ""
				outfileXMLUDP := ""
				if outprefixfolder != "" {
					outfolder = outprefixfolder + "-" + host

					// Make the output folder if it doesn't exist
					_ = os.Mkdir(outfolder, 0700)

					outfileNormTCP = path.Join(outfolder, "out-nmap-norm-tcp.txt")
					outfileGrepTCP = path.Join(outfolder, "out-nmap-grep-tcp.txt")
					outfileXMLTCP = path.Join(outfolder, "out-nmap-xml-tcp.txt")

					outfileNormUDP = path.Join(outfolder, "out-nmap-norm-udp.txt")
					outfileGrepUDP = path.Join(outfolder, "out-nmap-grep-udp.txt")
					outfileXMLUDP = path.Join(outfolder, "out-nmap-xml-udp.txt")
				}

				// Run TCP Port scan on host
				log.Printf("[*] Performing TCP scan on host: %s", host)
				cmd := ""
				cmd = "sudo nmap -T4 --open {portsArg} -sS -Pn {host}"
				if outfolder != "" {
					cmd += " -oN " + outfileNormTCP + " -oG " + outfileGrepTCP +
						" -oX " + outfileXMLTCP
				}
				if runVersionScans {
					cmd += " -sV"
				}
				if runOSScan {
					cmd += " -A"
				}
				cmd = strings.ReplaceAll(cmd, "{portsArg}", portsArg)
				cmd = strings.ReplaceAll(cmd, "{host}", host)
				outTCP := execCmd(cmd, verbose)

				// Run UDP Port scan
				outUDP := ""
				if runUDP {
					log.Printf("[*] Performing UDP scan on host: %s", host)
					cmd = "sudo nmap --open --top-ports {top_udp_ports} -sU -Pn {host}"
					if outfolder != "" {
						cmd += " -oN " + outfileNormUDP + " -oG " + outfileGrepUDP +
							" -oX " + outfileXMLUDP
					}
					cmd = strings.ReplaceAll(cmd, "{top_udp_ports}", TopUDPPortsToScan)
					cmd = strings.ReplaceAll(cmd, "{portsArg}", portsArg)
					cmd = strings.ReplaceAll(cmd, "{host}", host)
					outUDP = execCmd(cmd, verbose)
				} else {
					log.Printf("[*] Skipping UDP scanning of host: %s, as -runUDP flag not selected", host)
				}

				// Combine outputs
				out := outTCP + "\n" + outUDP

				// Parse output to look for lines with open ports
				outlines := strings.Split(out, "\n")
				for _, outline := range outlines {
					if outline != "" {

						// Find a line with open port
						openPortLineRegex := OpenPortLineSig
						found, _ := regexp.MatchString(openPortLineRegex, outline)
						if found {
							// Get the port
							port := strings.Split(outline, "/")[0]

							// Is port on TCP/UDP?
							transportProtocol := strings.Split(strings.Split(outline, "/")[1], " ")[0]

							// Track if signature found for port
							sigFound := false

							// Search for a signature within the output
							for _, signature := range signatures {

								// Check if relevant regex signature present in nmap
								// outline - if it is, then implement the block
								protocolRegex := signature.Regex
								protocol := signature.Protocol

								found, _ := regexp.MatchString(protocolRegex, outline)
								if found {
									fmt.Printf("[%s] %s://%s:%s\n", transportProtocol, protocol, host, port)
									sigFound = true
									break
								}
							}
							if !sigFound {
								fmt.Printf("[%s] unknown://%s:%s\n", transportProtocol, host, port)
							}
						}
					}
				}
			}
			wg.Done()
		}(hosts, &wg)
	}

	// Take list of hosts to scan from user via STDIN
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		host := sc.Text()

		// Add the host for processing
		hosts <- host
	}

	// No more hosts to process - all done.
	close(hosts)

	wg.Wait()
}
