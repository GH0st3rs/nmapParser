// nmapParser project nmapParser.go
package nmapParser

import (
	"encoding/xml"
	"io/ioutil"
	"regexp"
	"strings"
)

type SMBOSDiscovery struct {
	OS          string
	LanManager  string
	CPE         string
	NetBIOS     string
	FQDN        string
	NetworkName string
}

type Address struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
	Vendor   string `xml:"vendor,attr"`
}

type PortService struct {
	Name      string   `xml:"name,attr"`
	Product   string   `xml:"product,attr"`
	Ver       string   `xml:"version,attr"`
	OsType    string   `xml:"ostype,attr"`
	ExtraInfo string   `xml:"extrainfo,attr"`
	CPE       []string `xml:"cpe"`
}

type Script struct {
	ID     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
}

type Status struct {
	Value string `xml:"state,attr"`
}

type Port struct {
	PortID   int         `xml:"portid,attr"`
	Protocol string      `xml:"protocol,attr"`
	State    Status      `xml:"state"`
	Service  PortService `xml:"service"`
	Script   Script      `xml:"script"`
}

type OSClass struct {
	Type     string `xml:"type,attr"`
	Vendor   string `xml:"vendor,attr"`
	OSFamily string `xml:"osfamily,attr"`
	OSGen    string `xml:"osgen,attr"`
	CPE      string `xml:"cpe"`
}

type OSMatch struct {
	Name    string    `xml:"name,attr"`
	OSClass []OSClass `xml:"osclass"`
}

type Hop struct {
	IP  string `xml:"ipaddr,attr"`
	TTL uint8  `xml:"ttl,attr"`
}

type Hostname struct {
	Value string `xml:"name,attr"`
}

type Host struct {
	Status     Status    `xml:"status"`
	Address    []Address `xml:"address"`
	Hostname   Hostname  `xml:"hostnames>hostname"`
	Ports      []Port    `xml:"ports>port"`
	OS         []OSMatch `xml:"os>osmatch"`
	HostScript []Script  `xml:"hostscript>script"`
	TraceHop   []Hop     `xml:"trace>hop"`
}

type nmaprun struct {
	XMLName xml.Name `xml:"nmaprun"`
	Hosts   []Host   `xml:"host"`
}

//Parse xml file to GO structure
func Parse(REPORT_FILE *string) (*nmaprun, error) {
	REPORT := nmaprun{}
	xmlContent, _ := ioutil.ReadFile(*REPORT_FILE)
	err := xml.Unmarshal(xmlContent, &REPORT)
	if err != nil {
		return &nmaprun{}, err
	}
	return &REPORT, nil
}

//Parse output from smb-os-discovery script to GO structure
func SmbScriptParse(output *string) *SMBOSDiscovery {
	arr := strings.Split(*output, "\n  ")[1:]
	buf := SMBOSDiscovery{}
	for _, item := range arr {
		if match, _ := regexp.MatchString(`OS: ([a-zA-Z0-9]+) ([\(\)\a-zA-Z0-9\.]+)`, item); match {
			match, _ := regexp.Compile(`OS: ([a-zA-Z0-9]+) ([\(\)\a-zA-Z0-9\.]+)`)
			result := match.FindStringSubmatch(item)
			if len(result) == 3 {
				buf.OS = result[1]
				buf.LanManager = result[2]
			}
		} else if match, _ := regexp.MatchString(`Computer name: ([a-zA-Z0-9\.\-]+)`, item); match {
			match, _ := regexp.Compile(`Computer name: ([a-zA-Z0-9\.\-]+)`)
			result := match.FindStringSubmatch(item)
			if len(result) == 2 {
				buf.NetworkName = result[1]
			}
		} else if match, _ := regexp.MatchString(`NetBIOS computer name: ([a-zA-Z0-9\.\-]+)`, item); match {
			match, _ := regexp.Compile(`NetBIOS computer name: ([a-zA-Z0-9\.\-]+)`)
			result := match.FindStringSubmatch(item)
			if len(result) == 2 {
				buf.NetBIOS = result[1]
			}
		} else if match, _ := regexp.MatchString(`FQDN: ([a-zA-Z0-9\.\-]+)`, item); match {
			match, _ := regexp.Compile(`FQDN: ([a-zA-Z0-9\.\-]+)`)
			result := match.FindStringSubmatch(item)
			if len(result) == 2 {
				buf.FQDN = result[1]
			}
		} else if match, _ := regexp.MatchString(`OS CPE: ([a-zA-Z0-9\.\-\:\/]+)`, item); match {
			match, _ := regexp.Compile(`OS CPE: ([a-zA-Z0-9\.\-\:\/]+)`)
			result := match.FindStringSubmatch(item)
			if len(result) == 2 {
				buf.CPE = result[1]
			}
		}
	}
	return &buf
}
