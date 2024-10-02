// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/gardener/egress-filter-refresher/pkg/netconfig"
)

const (
	ipv4IPSetName = "egress-filter-set-v4"
	ipv6IPSetName = "egress-filter-set-v6"
)

func updateBlackholeRoutes(ipv4EgressFilterList, ipv6EgressFilterList string) error {

	filterLists := []string{ipv4EgressFilterList, ipv6EgressFilterList}

	for i, v := range []string{"4", "6"} {
		egressFilterContent, err := os.ReadFile(filterLists[i])
		if err != nil {
			return fmt.Errorf("error reading egress filter list '%s': %v", filterLists[i], err)
		}
		err = netconfig.UpdateRoutes(v, string(egressFilterContent))
		if err != nil {
			return fmt.Errorf("updateRoutes failed for IPv%s: %v", v, err)
		}
	}
	return nil
}

func updateFirewall(blockIngress bool, ipv4EgressFilterList, ipv6EgressFilterList string) error {
	fmt.Println("Check initial setup")

	defaultNetworkDeviceV4, _ := netconfig.GetDefaultNetworkDevice("4")
	defaultNetworkDeviceV6, _ := netconfig.GetDefaultNetworkDevice("6")

	if defaultNetworkDeviceV4 == "" && defaultNetworkDeviceV6 == "" {
		return fmt.Errorf("no default network device found")
	} else if defaultNetworkDeviceV4 == "" {
		defaultNetworkDeviceV4 = defaultNetworkDeviceV6
	} else if defaultNetworkDeviceV6 == "" {
		defaultNetworkDeviceV6 = defaultNetworkDeviceV4
	}

	ipSetNames := []string{ipv4IPSetName, ipv6IPSetName}
	filterLists := []string{ipv4EgressFilterList, ipv6EgressFilterList}
	defaultNetworkDevices := []string{defaultNetworkDeviceV4, defaultNetworkDeviceV6}

	for i, v := range []string{"4", "6"} {
		_ = netconfig.InitIPSet(v, ipSetNames[i])
		egressFilterContent, err := os.ReadFile(filterLists[i])
		if err != nil {
			return fmt.Errorf("error reading egress filter list '%s': %v", filterLists[i], err)
		}
		err = netconfig.UpdateIPSet(v, ipSetNames[i], string(egressFilterContent), defaultNetworkDevices[i], blockIngress)
		if err != nil {
			return fmt.Errorf("UpdateIPSet failed for %s: %v", ipSetNames[i], err)
		}
	}
	return nil
}

func main() {
	var blackholing, blockIngress bool
	var filterListDir, ipV4List, ipV6List string
	var sleepDuration time.Duration
	flag.BoolVar(&blackholing, "blackholing", false, "Enable blackhole routes.")
	flag.BoolVar(&blockIngress, "block-ingress", false, "Block Ingress using iptables.")
	flag.StringVar(&filterListDir, "filter-list-dir", "/list", "Directory containing the filter list files.")
	flag.StringVar(&ipV4List, "filter-list-ipv4", "ipv4-list", "ipv4 policy list.")
	flag.StringVar(&ipV6List, "filter-list-ipv6", "ipv6-list", "ipv6 policy list.")
	flag.DurationVar(&sleepDuration, "sleep-duration", time.Hour, "Sleep time between policy updates.")
	flag.Parse()

	ipV4List = filterListDir + "/" + ipV4List
	ipV6List = filterListDir + "/" + ipV6List

	fmt.Printf("blackholing enabled: %v\n", blackholing)
	for {
		fmt.Println(time.Now())
		_ = netconfig.InitLoggingChain("4")
		_ = netconfig.InitLoggingChain("6")
		if blackholing {
			err := netconfig.InitDummyDevice()
			if err != nil {
				fmt.Printf("Error initializing dummy device: %v", err)
				os.Exit(1)
			}
			fmt.Printf("Updating blackhole routes...")
			err = updateBlackholeRoutes(ipV4List, ipV6List)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error updating blackhole routes: %v\n", err)
				os.Exit(1)
			}
		} else {
			fmt.Println("Updating iptables rules ...")
			err := updateFirewall(blockIngress, ipV4List, ipV6List)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error updating iptables: %v\n", err)
				os.Exit(1)
			}
		}
		fmt.Println(time.Now())
		fmt.Printf("Going to sleep for %v...\n", sleepDuration)
		time.Sleep(sleepDuration)
	}
}
