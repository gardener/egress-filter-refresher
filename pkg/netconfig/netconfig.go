// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package netconfig

import (
	"fmt"
	"strings"
)

const (
	ipSetsMaxLen         = "65536"
	ipTablesLoggingChain = "POLICY_LOGGING"
	ipTablesLogPrefix    = "Policy-Filter-Dropped:"
	ipTablesLogLimit     = "10/min"
	ipTablesLogLevel     = "4"
	dummyDeviceName      = "dummy0"
	tmpIPSet             = "tmpIPSet"
)

type IPTablesAction string

const (
	IPTablesAppend IPTablesAction = "-A"
	IPTablesCheck  IPTablesAction = "-C"
	IPTablesDelete IPTablesAction = "-D"
)

var (
	DefaultNetUtilsCommandExecutor NetUtilsCommandExecutor = &OSNetUtilsCommandExecutor{}
)

func GetDefaultNetworkDevice(ipVersion string) (string, error) {
	output, err := DefaultNetUtilsCommandExecutor.ExecuteIPRouteCommand(ipVersion, "route", "show", "default")
	if err != nil {
		return "", err
	}

	fields := strings.Fields(output)
	for i, field := range fields {
		if field == "dev" {
			return fields[i+1], nil
		}
	}
	return "", fmt.Errorf("default network device not found")
}

func InitLoggingChain(ipVersion string) error {
	DefaultNetUtilsCommandExecutor.DetermineIPTablesBackend()
	err := DefaultNetUtilsCommandExecutor.ExecuteIPTablesCommand(ipVersion, "-t", "mangle", "-L", ipTablesLoggingChain)
	if err != nil {
		err := DefaultNetUtilsCommandExecutor.ExecuteIPTablesCommand(ipVersion, "-t", "mangle", "-N", ipTablesLoggingChain)
		if err != nil {
			return fmt.Errorf("error creating ip%stables logging chain: %v", ipVersion, err)
		}
	}

	if ipVersion == "6" {
		if err = DefaultNetUtilsCommandExecutor.ExecuteIPTablesCommand(ipVersion, "-t", "mangle", "-C", ipTablesLoggingChain, "-p", "icmpv6", "-j", "DROP"); err != nil {
			err = DefaultNetUtilsCommandExecutor.ExecuteIPTablesCommand(ipVersion, "-t", "mangle", "-A", ipTablesLoggingChain, "-p", "icmpv6", "-j", "DROP")
			if err != nil {
				return fmt.Errorf("error creating ip%stables drop icmp6 rule: %v", ipVersion, err)
			}
		}
	}

	if err = DefaultNetUtilsCommandExecutor.ExecuteIPTablesCommand(ipVersion, "-t", "mangle", "-C", ipTablesLoggingChain, "-m", "limit", "--limit", ipTablesLogLimit, "-j", "LOG", "--log-prefix", ipTablesLogPrefix, "--log-level", ipTablesLogLevel); err != nil {
		err = DefaultNetUtilsCommandExecutor.ExecuteIPTablesCommand(ipVersion, "-t", "mangle", "-A", ipTablesLoggingChain, "-m", "limit", "--limit", ipTablesLogLimit, "-j", "LOG", "--log-prefix", ipTablesLogPrefix, "--log-level", ipTablesLogLevel)
		if err != nil {
			return fmt.Errorf("error creating ip%stables logging rule: %v", ipVersion, err)
		}
	}

	if err = DefaultNetUtilsCommandExecutor.ExecuteIPTablesCommand(ipVersion, "-t", "mangle", "-C", ipTablesLoggingChain, "-j", "DROP"); err != nil {
		err = DefaultNetUtilsCommandExecutor.ExecuteIPTablesCommand(ipVersion, "-t", "mangle", "-A", ipTablesLoggingChain, "-j", "DROP")
		if err != nil {
			return fmt.Errorf("error creating ip%stables drop rule: %v", ipVersion, err)
		}
	}
	return nil
}

// firewaller

func IPTablesLoggingChainRule(ipVersion string, protocol string, ipSet string, device string, action IPTablesAction, blockIngress bool) error {
	a := string(action)

	ipTablesArgs := []string{
		"-t", "mangle",
		a, "POSTROUTING",
		"-o", device,
		"-p", protocol,
		"-m", "set",
		"--match-set", ipSet,
		"dst",
		"-j", ipTablesLoggingChain,
	}

	if protocol == "tcp" && !blockIngress {
		ipTablesArgs = append(ipTablesArgs[:8], append([]string{"--syn"}, ipTablesArgs[8:]...)...)
	}

	return DefaultNetUtilsCommandExecutor.ExecuteIPTablesCommand(ipVersion, ipTablesArgs...)
}

func AddIPTablesLoggingRules(ipVersion, ipSet, defaultNetworkDevice string, blockIngress bool) error {

	for _, proto := range []string{"tcp", "udp"} {
		if err := IPTablesLoggingChainRule(ipVersion, proto, ipSet, defaultNetworkDevice, IPTablesCheck, blockIngress); err != nil {
			err := IPTablesLoggingChainRule(ipVersion, proto, ipSet, defaultNetworkDevice, IPTablesAppend, blockIngress)
			if err != nil {
				return fmt.Errorf("error creating %s logging chain rules for %s, device %s %w", proto, ipSet, defaultNetworkDevice, err)
			}
		}
	}
	return nil
}

func RemoveIPTablesLoggingRules(ipVersion, ipSet, defaultNetworkDevice string) error {
	// we don't care if SYN filtering was enabled previously. delete both variants.
	for _, blockIngress := range []bool{true, false} {
		if err := IPTablesLoggingChainRule(ipVersion, "tcp", ipSet, defaultNetworkDevice, IPTablesCheck, blockIngress); err == nil {
			err := IPTablesLoggingChainRule(ipVersion, "tcp", ipSet, defaultNetworkDevice, IPTablesDelete, blockIngress)
			if err != nil {
				return fmt.Errorf("error deleting tcp logging chain rules for %s, device %s, blockIngress %t, %w", ipSet, defaultNetworkDevice, blockIngress, err)
			}
		}
	}
	// delete udp rules.
	if err := IPTablesLoggingChainRule(ipVersion, "udp", ipSet, defaultNetworkDevice, IPTablesCheck, false); err == nil {
		err := IPTablesLoggingChainRule(ipVersion, "udp", ipSet, defaultNetworkDevice, IPTablesDelete, false)
		if err != nil {
			return fmt.Errorf("error deleting udp logging chain rules for %s, device %s %w", ipSet, defaultNetworkDevice, err)
		}
	}
	fmt.Printf("Removed iptables v%s rules for ipset %s on device %s\n", ipVersion, ipSet, defaultNetworkDevice)
	return nil
}

func InitIPSet(ipVersion, ipSetName string) error {
	if ipVersion == "4" {
		ipVersion = ""
	}
	fmt.Printf("Initially creating ipset with name %s\n", ipSetName)
	if err := DefaultNetUtilsCommandExecutor.ExecuteIPSetCommand("list", ipSetName); err != nil {
		err := DefaultNetUtilsCommandExecutor.ExecuteIPSetCommand("create", ipSetName, "hash:net", "family", "inet"+ipVersion, "maxelem", ipSetsMaxLen)
		if err != nil {
			return fmt.Errorf("error creating IP set %s: %v", ipSetName, err)
		}
	}
	return nil
}

func prepareAddrs(content string, trimSuffix bool) []string {
	res := []string{}
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		if !strings.Contains(line, "[]") {
			if len(strings.Fields(line)) == 2 {
				addr := strings.Fields(line)[1]
				if trimSuffix {
					addr = strings.TrimSuffix(addr, "/32")
					addr = strings.TrimSuffix(addr, "/128")
				}
				res = append(res, addr)
			}
		}
	}
	return res
}

func AddIPListToIPSet(ipSetName string, content string) error {

	addrs := prepareAddrs(content, false)

	for i, addr := range addrs {
		addrs[i] = "-A " + ipSetName + " " + addr
	}
	addrs = append(addrs, "quit\n")

	err := DefaultNetUtilsCommandExecutor.ExecuteIPSetScript(strings.Join(addrs, "\n"))
	if err != nil {
		return fmt.Errorf("error adding addresses to ipset %w", err)
	}
	fmt.Printf("Added %d entries to ipset '%s'.\n", len(addrs)-1, ipSetName)
	return nil
}

func UpdateIPSet(ipVersion, ipSetName, egressFilterList, defaultNetworkDevice string, blockIngress bool) error {
	inetVersion := ""
	if ipVersion == "6" {
		inetVersion = "6"
	}

	defer func() {
		fmt.Println("Clean-up temporary ipset")
		err := DefaultNetUtilsCommandExecutor.ExecuteIPSetCommand("destroy", tmpIPSet)
		if err != nil {
			fmt.Printf("Error cleaning-up temporary ipsets %v\n", err)
		}
	}()

	fmt.Printf("Creating temporary ipset with name \"%s\"...\n", tmpIPSet)
	err := DefaultNetUtilsCommandExecutor.ExecuteIPSetCommand("create", tmpIPSet, "hash:net", "family", "inet"+inetVersion, "maxelem", ipSetsMaxLen)
	if err != nil {
		return fmt.Errorf("error creating temporary ipset: %w", err)
	}

	fmt.Printf("Temporary ipset with name \"%s\" created successfully.\n", tmpIPSet)

	err = AddIPListToIPSet(tmpIPSet, egressFilterList)
	if err != nil {
		return fmt.Errorf("error adding entries to temporary ipset: %w", err)
	}
	fmt.Println("Added entries into temporary ipset successfully.")

	err = AddIPTablesLoggingRules(ipVersion, ipSetName, defaultNetworkDevice, blockIngress)
	if err != nil {
		return fmt.Errorf("error adding iptables rules %w", err)
	}

	fmt.Printf("Swapping new ipset '%s' against old one '%s'\n", tmpIPSet, ipSetName)
	err = DefaultNetUtilsCommandExecutor.ExecuteIPSetCommand("swap", tmpIPSet, ipSetName)
	if err != nil {
		return fmt.Errorf("error swapping ipsets: %w", err)
	}

	return nil
}

func RemoveIPSet(ipSetName string) error {
	if err := DefaultNetUtilsCommandExecutor.ExecuteIPSetCommand("list", ipSetName); err == nil {
		err = DefaultNetUtilsCommandExecutor.ExecuteIPSetCommand("destroy", ipSetName)
		if err != nil {
			return fmt.Errorf("error cleaning-up ipset %s: %w\n", ipSetName, err)
		}
	}

	fmt.Printf("Removed ipset %s\n", ipSetName)
	return nil
}

// blackholer

func diff(new, old []string) (added, removed []string) {
	newSet := make(map[string]bool)
	oldSet := make(map[string]bool)

	for _, s := range new {
		newSet[s] = true
	}

	for _, s := range old {
		oldSet[s] = true
	}

	for s := range newSet {
		if !oldSet[s] {
			added = append(added, s)
		}
	}

	for s := range oldSet {
		if !newSet[s] {
			removed = append(removed, s)
		}
	}

	return
}

func InitDummyDevice() error {
	out, _ := DefaultNetUtilsCommandExecutor.ExecuteIPRouteCommand("4", "link", "show")
	if !strings.Contains(out, " "+dummyDeviceName+": ") {
		_, err := DefaultNetUtilsCommandExecutor.ExecuteIPRouteCommand("4", "link", "add", dummyDeviceName, "type", "dummy")
		if err != nil {
			return fmt.Errorf("error creating dummy device: %v", err)
		}
		_, err = DefaultNetUtilsCommandExecutor.ExecuteIPRouteCommand("4", "link", "set", dummyDeviceName, "up")
		if err != nil {
			return fmt.Errorf("error setting up dummy device: %v", err)
		}
		fmt.Println("Added dummy device.")
	}

	for _, ipv := range []string{"4", "6"} {
		if err := DefaultNetUtilsCommandExecutor.ExecuteIPTablesCommand(ipv, "-t", "mangle", "-C", "POSTROUTING", "-o", dummyDeviceName, "-j", ipTablesLoggingChain); err != nil {
			err = DefaultNetUtilsCommandExecutor.ExecuteIPTablesCommand(ipv, "-t", "mangle", "-A", "POSTROUTING", "-o", dummyDeviceName, "-j", ipTablesLoggingChain)
			if err != nil {
				return fmt.Errorf("error creating ip%stables rule for logging packets to dummy device: %v", "", err)
			}
		}
	}

	fmt.Println("Created iptables rules for logging packets to dummy device.")
	return nil
}

func RemoveDummyDevice() error {
	if err := DefaultNetUtilsCommandExecutor.ExecuteIPTablesCommand("4", "-t", "mangle", "-C", "POSTROUTING", "-o", dummyDeviceName, "-j", ipTablesLoggingChain); err == nil {
		err = DefaultNetUtilsCommandExecutor.ExecuteIPTablesCommand("4", "-t", "mangle", "-D", "POSTROUTING", "-o", dummyDeviceName, "-j", ipTablesLoggingChain)
		if err != nil {
			return fmt.Errorf("error deleting ip%stables rule for logging packets to dummy device: %w", "", err)
		}
	}

	if err := DefaultNetUtilsCommandExecutor.ExecuteIPTablesCommand("6", "-t", "mangle", "-C", "POSTROUTING", "-o", dummyDeviceName, "-j", ipTablesLoggingChain); err == nil {
		err = DefaultNetUtilsCommandExecutor.ExecuteIPTablesCommand("6", "-t", "mangle", "-D", "POSTROUTING", "-o", dummyDeviceName, "-j", ipTablesLoggingChain)
		if err != nil {
			return fmt.Errorf("error deleting ip%stables rule for logging packets to dummy device: %w", "6", err)
		}
	}

	out, _ := DefaultNetUtilsCommandExecutor.ExecuteIPRouteCommand("4", "link", "show")
	if strings.Contains(out, " "+dummyDeviceName+": ") {
		_, err := DefaultNetUtilsCommandExecutor.ExecuteIPRouteCommand("4", "link", "set", dummyDeviceName, "down")
		if err != nil {
			return fmt.Errorf("error bringing down dummy device: %w", err)
		}
		_, err = DefaultNetUtilsCommandExecutor.ExecuteIPRouteCommand("4", "link", "del", dummyDeviceName)
		if err != nil {
			return fmt.Errorf("error deleting dummy device: %w", err)
		}
		fmt.Println("Removed dummy device.")
	}

	fmt.Println("Removed iptables rules for logging packets to dummy device.")
	return nil
}

func GetBlackholeRoutes(ipVersion string) ([]string, error) {
	blackholeRoutes := []string{}

	ipOut, err := DefaultNetUtilsCommandExecutor.ExecuteIPRouteCommand(ipVersion, "route")

	if err != nil {
		return blackholeRoutes, err
	}

	lines := strings.Split(ipOut, "\n")
	for _, line := range lines {
		if strings.Contains(line, dummyDeviceName) && !strings.Contains(line, "fe80::/64") {
			fields := strings.Fields(line)
			addr := fields[0]
			blackholeRoutes = append(blackholeRoutes, addr)
		}
	}

	return blackholeRoutes, nil
}

func DeleteRoutes(ipVersion string, addrs []string) error {
	if len(addrs) == 0 {
		return nil
	}
	fmt.Printf("Deleting %d routes.\n", len(addrs))
	for i, addr := range addrs {
		addrs[i] = "route del " + addr + " dev " + dummyDeviceName
	}
	err := DefaultNetUtilsCommandExecutor.ExecuteIPRouteBatchCommand(ipVersion, strings.Join(addrs, "\n"))

	if err != nil {
		return fmt.Errorf("error deleting blackhole routes: %v", err)
	}
	fmt.Printf("Deleted %d routes.\n", len(addrs))
	return nil
}

func AddRoutes(ipVersion string, addrs []string) error {
	if len(addrs) == 0 {
		return nil
	}
	fmt.Printf("Adding %d routes.\n", len(addrs))
	for i, addr := range addrs {
		addrs[i] = "route add " + addr + " dev " + dummyDeviceName
	}
	err := DefaultNetUtilsCommandExecutor.ExecuteIPRouteBatchCommand(ipVersion, strings.Join(addrs, "\n"))

	if err != nil {
		return fmt.Errorf("error adding blackhole routes: %v", err)
	}
	fmt.Printf("Added %d routes.\n", len(addrs))
	return nil
}

func UpdateRoutes(ipVersion string, egressFilterList string) error {
	newAddrs := prepareAddrs(egressFilterList, true)
	fmt.Printf("Checking ipv%s egress filter list with %d entries against current settings...\n", ipVersion, len(newAddrs))

	currentAddrs, err := GetBlackholeRoutes(ipVersion)
	if err != nil {
		return err
	}
	fmt.Printf("Currently applied filter list contains %d entries\n", len(currentAddrs))

	addAddr, delAddr := diff(newAddrs, currentAddrs)
	err = AddRoutes(ipVersion, addAddr)
	if err != nil {
		return err
	}
	err = DeleteRoutes(ipVersion, delAddr)
	if err != nil {
		return err
	}
	return nil
}
