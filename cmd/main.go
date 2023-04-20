// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/gardener/egress-filter-refresher/pkg/netconfig"
)

const (
	ipv4IPSetName        = "egress-filter-set-v4"
	ipv6IPSetName        = "egress-filter-set-v6"
	ipv4EgressFilterList = "/lists/ipv4-list"
	ipv6EgressFilterList = "/lists/ipv6-list"
	ipsetScript          = "/tmp/ipset_script"

	sleepDuration = time.Hour
)

func updateBlackholeRoutes() {
	egressFilterContent, err := ioutil.ReadFile(ipv4EgressFilterList)
	if err != nil {
		fmt.Printf("Error reading egress filter list: %v\n", err)
	}
	netconfig.UpdateRoutes("4", string(egressFilterContent))
	if err != nil {
		fmt.Printf("Error: UpdateRoutes failed for: %v\n", err)
	}

	egressFilterContent, err = ioutil.ReadFile(ipv6EgressFilterList)
	if err != nil {
		fmt.Printf("Error reading egress filter list: %v\n", err)
	}
	netconfig.UpdateRoutes("6", string(egressFilterContent))
	if err != nil {
		fmt.Printf("Error: Routes failed for %v\n", err)
	}

}

func updateFirewall(blockIngress bool) {
	fmt.Println("Check initial setup")
	netconfig.InitIPSet("4", ipv4IPSetName)
	netconfig.InitIPSet("6", ipv6IPSetName)

	defaultNetworkDeviceV4, _ := netconfig.GetDefaultNetworkDevice("4")
	defaultNetworkDeviceV6, _ := netconfig.GetDefaultNetworkDevice("6")
	
	if defaultNetworkDeviceV4 == "" && defaultNetworkDeviceV6 == "" {
		fmt.Println("Error: No default network device found.")
		os.Exit(1)
	} else if defaultNetworkDeviceV4 == "" {
			defaultNetworkDeviceV4 = defaultNetworkDeviceV6
	} else if defaultNetworkDeviceV6 == "" {
			defaultNetworkDeviceV6 = defaultNetworkDeviceV4
	}
	
	if defaultNetworkDeviceV4 == "" && defaultNetworkDeviceV6 == "" {
		fmt.Println("Error: No default network device found.")
		os.Exit(1)
	}
	
	egressFilterContent, err := ioutil.ReadFile(ipv4EgressFilterList)
	if err != nil {
		fmt.Printf("Error reading egress filter list: %v\n", err)
	}
	err = netconfig.UpdateIPSet("4", ipv4IPSetName, string(egressFilterContent), defaultNetworkDeviceV4, blockIngress)
	if err != nil {
		fmt.Printf("Error: UpdateIPSet failed for %s: %v\n", ipv4IPSetName, err)
	}

	egressFilterContent, err = ioutil.ReadFile(ipv6EgressFilterList)
	if err != nil {
		fmt.Printf("Error reading egress filter list: %v\n", err)
	}
	err = netconfig.UpdateIPSet("6", ipv6IPSetName, string(egressFilterContent), defaultNetworkDeviceV6, blockIngress)
	if err != nil {
		fmt.Printf("Error: UpdateIPSet failed for %s: %v\n", ipv6IPSetName, err)
	}
}

func main() {
	var blackholing, blockIngress bool

	flag.BoolVar(&blackholing, "blackholing", false, "Enable blackhole routes.")
	flag.BoolVar(&blockIngress, "block-ingress", false, "Block Ingress using iptables.")
	flag.Parse()
	fmt.Printf("blackholing enabled: %v\n", blackholing)
	for {
		fmt.Println(time.Now())
		netconfig.InitLoggingChain("4")
		netconfig.InitLoggingChain("6")
		if blackholing {
			err := netconfig.InitDummyDevice()
			if err != nil {
				fmt.Printf("Error initializing dummy device %v", err)
			}
			fmt.Println("Update blackhole routes.")
			updateBlackholeRoutes()
		} else {
			fmt.Println("Update iptables rules.")
			updateFirewall(blockIngress)
		}
		fmt.Println(time.Now())
		fmt.Println("Going to sleep for %v...", sleepDuration)
		time.Sleep(sleepDuration)
	}
}
