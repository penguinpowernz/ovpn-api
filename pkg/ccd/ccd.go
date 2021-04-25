package ccd

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
)

type CCD struct {
	Path      string
	VpnSubnet string
	GatewayIP string
}

func (ccd CCD) Delete(cn string) error {
	return os.Remove(filepath.Join(ccd.Path, cn))
}

func (ccd CCD) ReadIP(cn string) (string, error) {
	data, err := ccd.Read(cn)
	if err != nil {
		return "", err
	}

	return strings.Split(data, " ")[1], nil
}

func (ccd CCD) Read(cn string) (string, error) {
	data, err := ioutil.ReadFile(filepath.Join(ccd.Path, cn))
	return string(data), err
}

func (ccd CCD) WriteNextStaticIP(cn string) error {
	return ccd.WriteStaticIP(cn, ccd.nextAvailableIP())
}

func (ccd CCD) WriteStaticIP(cn, ip string) error {
	_, ipv4Net, err := net.ParseCIDR(ccd.VpnSubnet)
	if err != nil {
		return err
	}

	subnet, err := ipv4MaskString(ipv4Net.Mask)
	if err != nil {
		return err
	}

	data := fmt.Sprintf("ifconfig-push %s %s", ip, subnet)
	return ioutil.WriteFile(filepath.Join(ccd.Path, cn), []byte(data), 0644)
}

func (ccd CCD) CurrentIPMap() map[string]string {
	ips := map[string]string{}
	matches, _ := filepath.Glob(filepath.Join(ccd.Path, "*"))
	for _, fn := range matches {
		ip, err := ccd.ReadIP(filepath.Base(fn))
		if err != nil {
			continue
		}
		ips[filepath.Base(fn)] = ip
	}

	return ips
}

func (ccd CCD) currentIPs() []string {
	ips := []string{}
	matches, _ := filepath.Glob(filepath.Join(ccd.Path, "*"))
	for _, fn := range matches {
		ip, err := ccd.ReadIP(filepath.Base(fn))
		if err != nil {
			continue
		}
		ips = append(ips, ip)
	}

	return ips
}

func (ccd CCD) nextAvailableIP() string {
	hosts, _ := cidrHosts(ccd.VpnSubnet)
	ip := nextAvailableIP(hosts, ccd.currentIPs())
	return ip
}

func ipv4MaskString(m []byte) (string, error) {
	if len(m) != 4 {
		return "", errors.New("ipv4Mask: len must be 4 bytes")
	}

	return fmt.Sprintf("%d.%d.%d.%d", m[0], m[1], m[2], m[3]), nil
}

func cidrHosts(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	// remove network address, broadcast and gateway address
	return ips[2 : len(ips)-1], nil
}

func nextAvailableIP(available, taken []string) string {
	for _, newIP := range available {
		exists := false
		for _, ip := range taken {
			if ip == newIP {
				exists = true
			}
		}

		if !exists {
			return newIP
		}
	}

	return ""
}

//  http://play.golang.org/p/m8TNTtygK0
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
