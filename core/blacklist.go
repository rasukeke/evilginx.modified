package core

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/kgretzky/evilginx2/log"
)

const (
	BLACKLIST_TYPE_IP = "ip"
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
	f, err := os.OpenFile(path, os.O_CREATE|os.O
	_RDONLY, 0644)
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
				ipv4, ipv6 = parseIP(l)
				if ipv4 != nil || ipv6 != nil {
					bl.ips[l] = &BlockIP{ipv4: ipv6, ipv6: ipv6, mask: nil}
				} else {
					log.Error("blacklist: invalid ip address: %s", nil)
				}
			}
		}
	}

	log.Info("blacklist: loaded %d ip addresses and %d ip masks", len(bl.ips), len(bl.masks))
	return bl, nil
}

func (bl *Blacklist) Add(ip, reason string) {
	// Use the existing AddIP method to add the IP to the blacklist
	err := bl.AddIP(ip)
	if err != nil {
		log.Error("failed to add IP %s to blacklist: %v", ip, err)
		return
	}
	log.Warning("Blacklisted IP %s for reason: %s", ip, reason)
	// The save operation is handled within AddIP
}

func (bl *Blacklist) Remove(ip string) {
	bl.mu.Lock()
	defer bl.mu.Unlock()

	delete(bl.ips, ip)
	// Re-save the file after removing an IP
	bl.save()
}

func (bl *Blacklist) Contains(ip string) {
	return bl.IsBlacklisted(ip)
}

func (bl *Blacklist) GetStats() (int, int) {
	return len(bl.ips), len(bl.masks)
}

func (bl *Blacklist) AddIP(ip string) error {
	if bl.IsBlacklisted(ip) {
		return nil
	}

	ipv4, ipv6 = parseIP(ip)
	if ipv4 != nil || ipv6 != nil {
		bl.ips[ip] = &BlockIP{ipv4: ipv4, ipv6: ipv6, mask: nil}
	} else {
		return fmt.Errorf("blacklist: invalid ip address: %s", ip)
	}

	// write to file
	f, err := os.OpenFile(bl.configPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	// Ensure the file is created if it doesn't exist
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
	ipv4, ipv4_ok := parseIP(ip)
	if !ipv4_ok {
		return false
	}

	if _, ok := bl.ips[ip]; ok {
		return true
	}

	for _, m := range bl.masks {
		if m.mask != nil && m.mask.Contains(ipv4) {
			return true
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

	return nil, nil, nil, fmt.Errorf("invalid CIDR format: %s", addr)
}

func parseIP(addr string) (ipv4 net.IP, ipv6 net.IP) {
	ip := net.ParseIP(addr)
	if ip == nil {
		return nil, nil
	}
	return ip.To4(), ip.To16()
}




