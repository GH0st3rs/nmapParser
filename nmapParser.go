// nmapParser project nmapParser.go
package nmapParser

import (
	"encoding/xml"
	"io/ioutil"
	"strings"
)

type SMBOSDiscovery struct {
	OS          string
	LanManager  string
	DomainDNS   string
	ForestDNS   string
	CPE         string
	Workgroup   string
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

func Parse(REPORT_FILE *string) (*nmaprun, error) {
	REPORT := nmaprun{}
	xmlContent, _ := ioutil.ReadFile(*REPORT_FILE)
	err := xml.Unmarshal(xmlContent, &REPORT)
	if err != nil {
		return &nmaprun{}, err
	}
	return &REPORT, nil
}

func SmbScriptParse(output *string) *SMBOSDiscovery {
	arr := strings.Split(*output, "\n  ")[1:]
	buf := SMBOSDiscovery{}
	buf.CPE = arr[1][8:]
	buf.FQDN = arr[6][len("FQDN: "):]
	buf.NetBIOS = arr[3][len("NetBIOS computer name: "):]
	buf.OS = arr[0][len("OS: "):strings.Index(arr[0], " (")]
	buf.LanManager = arr[0][strings.Index(arr[0], " (")+2 : strings.LastIndex(arr[0], ")")]
	buf.DomainDNS = arr[4][len("Domain name: "):]
	buf.ForestDNS = arr[5][len("Forest name: "):]
	buf.NetworkName = arr[2][len("Computer name: "):]
	return &buf
}
