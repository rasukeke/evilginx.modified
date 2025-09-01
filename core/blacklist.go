package core

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/kgretzky/evilginx2/log"
)

type BlockIP struct {
	ipv4 net.IP
	ipv6 net.IP
	mask *net.IPNet
}

type Blacklist struct {
	ips        map[string]*BlockIP
	masks      []*BlockIP
	configPath string
	verbose    bool
}

func NewBlacklist(path string) (*Blacklist, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDONLY, 0644)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	bl := &Blacklist{
		ips:        make(map[string]*BlockIP),
		configPath: path,
		verbose:    true,
	}

	fs := bufio.NewScanner(f)
	fs.Split(bufio.ScanLines)

	for fs.Scan() {
		l := fs.Text()
		// remove comments
		if n := strings.Index(l, ";"); n > -1 {
			l = l[:n]
		}
		l = strings.Trim(l, " ")

		if len(l) > 0 {
			if strings.Contains(l, "/") {
				ipv4, ipv6, mask, err := parseIPAndMask(l)
				if err == nil {
					bl.masks = append(bl.masks, &BlockIP{ipv4: ipv4, ipv6: ipv6, mask: mask})
				} else {
					log.Error("blacklist: invalid ip/mask address: %s", l)
				}
			} else {
				ipv4, ipv6 := parseIP(l)
				if ipv4 != nil || ipv6 != nil {
					bl.ips[l] = &BlockIP{ipv4: ipv4, ipv6: ipv6, mask: nil}
				} else {
					log.Error("blacklist: invalid ip address: %s", l)
				}
			}
		}
	}

	log.Info("blacklist: loaded %d ip addresses and %d ip masks", len(bl.ips), len(bl.masks))
	return bl, nil
}

func (bl *Blacklist) GetStats() (int, int) {
	return len(bl.ips), len(bl.masks)
}

func (bl *Blacklist) AddIP(ip string) error {
	if bl.IsBlacklisted(ip) {
		return nil
	}

	ipv4, ipv6 := parseIP(ip)
	if ipv4 != nil || ipv6 != nil {
		bl.ips[ip] = &BlockIP{ipv4: ipv4, ipv6: ipv6, mask: nil}
	} else {
		return fmt.Errorf("blacklist: invalid ip address: %s", ip)
	}

	// write to file
	f, err := os.OpenFile(bl.configPath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(ip + "\n")
	if err != nil {
		return err
	}

	return nil
}

func (bl *Blacklist) IsBlacklisted(ip string) bool {
	ipv4, ipv6 := parseIP(ip)
	if ipv4 != nil || ipv6 != nil {
		if _, ok := bl.ips[ip]; ok {
			return true
		}
		for _, m := range bl.masks {
			if m.mask != nil && (m.mask.Contains(ipv4) || m.mask.Contains(ipv6)) {
				return true
			}
		}
	}
	return false
}

func (bl *Blacklist) SetVerbose(verbose bool) {
	bl.verbose = verbose
}

func (bl *Blacklist) IsVerbose() bool {
	return bl.verbose
}

func parseIPAndMask(addr string) (ipv4, ipv6 net.IP, mask *net.IPNet, err error) {
	if strings.Contains(addr, "/") {
		ip, ipnet, err := net.ParseCIDR(addr)
		if err != nil {
			return nil, nil, nil, err
		}
		return ip.To4(), ip.To16(), ipnet, nil
	}

	ip := net.ParseIP(addr)
	return ip.To4(), ip.To16(), nil, nil
}

func parseIP(addr string) (ipv4, ipv6 net.IP) {
	ip := net.ParseIP(addr)
	return ip.To4(), ip.To16()
}
