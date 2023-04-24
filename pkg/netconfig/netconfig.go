// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package netconfig

import (
	"errors"
	"fmt"
	"strings"
)

const (
	ipSetsMaxLen         = "65536"
	ipTablesLoggingChain = "LOGGING"
	ipTablesLogPrefix    = "Policy-Filter-Dropped:"
	ipTablesLogLimit     = "10/min"
	ipTablesLogLevel     = "4"
	dummyDeviceName      = "dummy0"
)

var (
	DefaultNetUtilsCommandExecutor NetUtilsCommandExecutor = &OSNetUtilsCommandExecutor{}
)

func GetDefaultNetworkDevice(ipVersion string) (string, error) {
	out, err := DefaultNetUtilsCommandExecutor.ExecuteIPRouteCommand(ipVersion, "route", "show", "default")
	if err != nil {
		return "", err
	}

	output := out.String()
	fields := strings.Fields(output)
	for i, field := range fields {
		if field == "dev" {
			return fields[i+1], nil
		}
	}
	return "", fmt.Errorf("default network device not found\n")
}

func InitLoggingChain(ipVersion string) error {
	err := DefaultNetUtilsCommandExecutor.ExecuteIPTablesCommand(ipVersion, "-t", "mangle", "-L", ipTablesLoggingChain)
	if err != nil {
		err := DefaultNetUtilsCommandExecutor.ExecuteIPTablesCommand(ipVersion, "-t", "mangle", "-N", ipTablesLoggingChain)
		if err != nil {
			return errors.New(fmt.Sprintf("Error creating ip%stables logging chain: %v\n", ipVersion, err))
		}
	}
	if err = DefaultNetUtilsCommandExecutor.ExecuteIPTablesCommand(ipVersion, "-t", "mangle", "-C", ipTablesLoggingChain, "-m", "limit", "--limit", ipTablesLogLimit, "-j", "LOG", "--log-prefix", ipTablesLogPrefix, "--log-level", ipTablesLogLevel); err != nil {
		err = DefaultNetUtilsCommandExecutor.ExecuteIPTablesCommand(ipVersion, "-t", "mangle", "-A", ipTablesLoggingChain, "-m", "limit", "--limit", ipTablesLogLimit, "-j", "LOG", "--log-prefix", ipTablesLogPrefix, "--log-level", ipTablesLogLevel)
		if err != nil {
			return errors.New(fmt.Sprintf("Error creating ip%stables logging rule: %v\n", ipVersion, err))
		}
	}

	if err = DefaultNetUtilsCommandExecutor.ExecuteIPTablesCommand(ipVersion, "-t", "mangle", "-C", ipTablesLoggingChain, "-j", "DROP"); err != nil {
		err = DefaultNetUtilsCommandExecutor.ExecuteIPTablesCommand(ipVersion, "-t", "mangle", "-A", ipTablesLoggingChain, "-j", "DROP")
		if err != nil {
			return errors.New(fmt.Sprintf("Error creating ip%stables drop rule: %v\n", ipVersion, err))
		}
	}
	return nil
}

// firewaller
func IPTablesLoggingChainRule(ipVersion string, protocol string, ipSet string, device string, check bool, blockIngress bool) error {
	action := "-A"
	if check {
		action = "-C"
	}

	ipTablesArgs := []string{
		"-t", "mangle",
		action, "POSTROUTING",
		"-o", device,
		"-p", protocol,
		"-m", "set",
		"--match-set", ipSet,
		"dst",
		"-j", "LOGGING",
	}

	if protocol == "tcp" {
		ipTablesArgs = []string{
			"-t", "mangle",
			action, "POSTROUTING",
			"-o", device,
			"-p", protocol,
			"--syn",
			"-m", "set",
			"--match-set", ipSet,
			"dst",
			"-j", "LOGGING",
		}

		if blockIngress {
			ipTablesArgs = []string{
				"-t", "mangle",
				action, "POSTROUTING",
				"-o", device,
				"-p", protocol,
				"-m", "set",
				"--match-set", ipSet,
				"dst",
				"-j", "LOGGING",
			}
		}
	}
	return DefaultNetUtilsCommandExecutor.ExecuteIPTablesCommand(ipVersion, ipTablesArgs...)
}

func AddIPTablesLoggingRules(ipVersion, ipSet, defaultNetworkDevice string, blockIngress bool) error {

	if err := IPTablesLoggingChainRule(ipVersion, "tcp", ipSet, defaultNetworkDevice, true, blockIngress); err != nil {
		err := IPTablesLoggingChainRule(ipVersion, "tcp", ipSet, defaultNetworkDevice, false, blockIngress)
		if err != nil {
			return fmt.Errorf("Error creating tcp logging chain rules for %s, device %s %v\n", ipSet, defaultNetworkDevice, err)
		}
	}
	if err := IPTablesLoggingChainRule(ipVersion, "udp", ipSet, defaultNetworkDevice, true, blockIngress); err != nil {
		err := IPTablesLoggingChainRule(ipVersion, "udp", ipSet, defaultNetworkDevice, false, blockIngress)
		if err != nil {
			return fmt.Errorf("Error creating udp logging chain rules for %s, device %s %v\n", ipSet, defaultNetworkDevice, err)
		}
	}
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
			return errors.New(fmt.Sprintf("Error creating IP set %s: %v\n", ipSetName, err))
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
				if trimSuffix && strings.HasSuffix(addr, "/32") {
					addr = strings.TrimSuffix(addr, "/32")
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
		return fmt.Errorf("Error adding addresses to ipset %w\n", err)
	}
	fmt.Printf("Added %d entries to ipset %s.\n", len(addrs), ipSetName)
	return nil
}

func UpdateIPSet(ipVersion, ipSetName, egressFilterList, defaultNetworkDevice string, blockIngress bool) error {
	inetVersion := ""
	if ipVersion == "6" {
		inetVersion = "6"
	}

	defer func() {
		fmt.Println("Clean-up")
		err := DefaultNetUtilsCommandExecutor.ExecuteIPSetCommand("destroy", "tmpIPSet")
		if err != nil {
			fmt.Printf("Error cleaning-up ipsets %v\n", err)
		}
	}()

	fmt.Printf("Creating temporary ipset with name \"%s\"...\n", "tmpIPSet")
	err := DefaultNetUtilsCommandExecutor.ExecuteIPSetCommand("create", "tmpIPSet", "hash:net", "family", "inet"+inetVersion, "maxelem", ipSetsMaxLen)
	if err != nil {
		return fmt.Errorf("Error creating temporary ipset: %w\n", err)
	}

	fmt.Printf("Temporary ipset with name \"%s\" created successfully.\n", "tmpIPSet")

	err = AddIPListToIPSet("tmpIPSet", egressFilterList)
	if err != nil {
		return fmt.Errorf("Error adding entries to temporary ipset: %w\n", err)
	}
	fmt.Println("Added entries into temporary ipset successfully.")

	err = AddIPTablesLoggingRules(ipVersion, ipSetName, defaultNetworkDevice, blockIngress)
	if err != nil {
		return fmt.Errorf("Error adding iptables rules %w\n", err)
	}

	fmt.Printf("Swapping new ipset %s against old one %s\n", "tmpIPSet", ipSetName)
	err = DefaultNetUtilsCommandExecutor.ExecuteIPSetCommand("swap", "tmpIPSet", ipSetName)
	if err != nil {
		return fmt.Errorf("Error swapping ipsets %w\n", err)
	}

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
	if !strings.Contains(out.String(), " "+dummyDeviceName+": ") {
		_, err := DefaultNetUtilsCommandExecutor.ExecuteIPRouteCommand("4", "link", "add", dummyDeviceName, "type", "dummy")
		if err != nil {
			return fmt.Errorf("Error creating dummy device: %v", err)
		}
		_, err = DefaultNetUtilsCommandExecutor.ExecuteIPRouteCommand("4", "link", "set", dummyDeviceName, "up")
		if err != nil {
			return fmt.Errorf("Error setting up dummy device: %v", err)
		}
	}
	if err := DefaultNetUtilsCommandExecutor.ExecuteIPTablesCommand("4", "-t", "mangle", "-C", "POSTROUTING", "-o", dummyDeviceName, "-j", "LOGGING"); err != nil {
		err = DefaultNetUtilsCommandExecutor.ExecuteIPTablesCommand("4", "-t", "mangle", "-A", "POSTROUTING", "-o", dummyDeviceName, "-j", "LOGGING")
		if err != nil {
			return errors.New(fmt.Sprintf("Error creating ip%stables rule for logging packets to dummy device: %v\n", "", err))
		}
	}

	if err := DefaultNetUtilsCommandExecutor.ExecuteIPTablesCommand("6", "-t", "mangle", "-C", "POSTROUTING", "-o", dummyDeviceName, "-j", "LOGGING"); err != nil {
		err = DefaultNetUtilsCommandExecutor.ExecuteIPTablesCommand("6", "-t", "mangle", "-A", "POSTROUTING", "-o", dummyDeviceName, "-j", "LOGGING")
		if err != nil {
			return errors.New(fmt.Sprintf("Error creating ip%stables rule for logging packets to dummy device: %v\n", "6", err))
		}
	}
	return nil
}

func GetBlackholeRoutes(ipVersion string) ([]string, error) {
	blackholeRoutes := []string{}

	ipOut, err := DefaultNetUtilsCommandExecutor.ExecuteIPRouteCommand(ipVersion, "route")

	if err != nil {
		return blackholeRoutes, err
	}

	lines := strings.Split(ipOut.String(), "\n")
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
		addrs[i] = "route del " + addr + " dev dummy0"
	}
	err := DefaultNetUtilsCommandExecutor.ExecuteIPRouteBatchCommand(ipVersion, strings.Join(addrs, "\n"))

	if err != nil {
		return fmt.Errorf("Error deleting blackhole routes: %v\n", err)
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
		addrs[i] = "route add " + addr + " dev dummy0"
	}
	err := DefaultNetUtilsCommandExecutor.ExecuteIPRouteBatchCommand(ipVersion, strings.Join(addrs, "\n"))

	if err != nil {
		return fmt.Errorf("Error adding blackhole routes: %v\n", err)
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

	fmt.Printf("Current filter list contains %d entries\n", len(currentAddrs))

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
