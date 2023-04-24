// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package netconfig_test

import (
	"bytes"
	"errors"
	"io/ioutil"
	"testing"

	"github.com/gardener/egress-filter-refresher/pkg/netconfig"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Netconfig", func() {

	BeforeEach(func() {
		mockExecutor := &netconfig.MockNetUtilsCommandExecutor{}
		mockExecutor.MockIPRoutesStdOut = bytes.NewBufferString("default via 10.242.0.1 dev ens5 proto dhcp src 10.242.0.198 metric 1024")
		netconfig.DefaultNetUtilsCommandExecutor = mockExecutor

	})

	AfterEach(func() {
		realExecutor := &netconfig.OSNetUtilsCommandExecutor{}
		netconfig.DefaultNetUtilsCommandExecutor = realExecutor
	})

	Describe("GetDefaultNetworkDevice", func() {
		It("returns correct device name", func() {
			mockExecutor := &netconfig.MockNetUtilsCommandExecutor{}
			mockExecutor.MockIPRoutesStdOut = bytes.NewBufferString("default via 10.242.0.1 dev ens5 proto dhcp src 10.242.0.198 metric 1024")
			netconfig.DefaultNetUtilsCommandExecutor = mockExecutor
			device, err := netconfig.GetDefaultNetworkDevice("4")
			Expect(err).To(BeNil())
			Expect(device).To(Equal("ens5"))
		})
		It("returns an error if no device found", func() {
			mockExecutor := &netconfig.MockNetUtilsCommandExecutor{}
			mockExecutor.MockIPRoutesStdOut = bytes.NewBufferString("Error: any valid prefix is expected rather than \"default\".")
			netconfig.DefaultNetUtilsCommandExecutor = mockExecutor
			device, err := netconfig.GetDefaultNetworkDevice("4")
			Expect(err).NotTo(BeNil())
			Expect(device).To(BeEmpty())
			Expect(err.Error()).To(Equal("default network device not found\n"))
		})
	})

	Describe("InitLoggingChain", func() {
		It("calls the correct command if chain an rules exist", func() {
			err := netconfig.InitLoggingChain("4")
			Expect(err).To(BeNil())
			Expect(len(netconfig.DefaultNetUtilsCommandExecutor.(*netconfig.MockNetUtilsCommandExecutor).MockCmds)).To(Equal(3))
			Expect(netconfig.DefaultNetUtilsCommandExecutor.(*netconfig.MockNetUtilsCommandExecutor).MockCmds[0].Args).To(Equal([]string{"iptables", "-w", "-t", "mangle", "-L", "LOGGING"}))
			Expect(netconfig.DefaultNetUtilsCommandExecutor.(*netconfig.MockNetUtilsCommandExecutor).MockCmds[1].Args).To(Equal([]string{"iptables", "-w", "-t", "mangle", "-C", "LOGGING", "-m", "limit", "--limit", "10/min", "-j", "LOG", "--log-prefix", "Policy-Filter-Dropped:", "--log-level", "4"}))
			Expect(netconfig.DefaultNetUtilsCommandExecutor.(*netconfig.MockNetUtilsCommandExecutor).MockCmds[2].Args).To(Equal([]string{"iptables", "-w", "-t", "mangle", "-C", "LOGGING", "-j", "DROP"}))
		})
		It("calls the correct command if chain and rules don't exist", func() {
			mockExecutor := &netconfig.MockNetUtilsCommandExecutor{}
			mockExecutor.MockCheckError = errors.New("iptables: Bad rule (does a matching rule exist in that chain?).")
			netconfig.DefaultNetUtilsCommandExecutor = mockExecutor
			err := netconfig.InitLoggingChain("4")
			Expect(err).To(BeNil())
			Expect(len(netconfig.DefaultNetUtilsCommandExecutor.(*netconfig.MockNetUtilsCommandExecutor).MockCmds)).To(Equal(6))
			Expect(netconfig.DefaultNetUtilsCommandExecutor.(*netconfig.MockNetUtilsCommandExecutor).MockCmds[0].Args).To(Equal([]string{"iptables", "-w", "-t", "mangle", "-L", "LOGGING"}))
			Expect(netconfig.DefaultNetUtilsCommandExecutor.(*netconfig.MockNetUtilsCommandExecutor).MockCmds[1].Args).To(Equal([]string{"iptables", "-w", "-t", "mangle", "-N", "LOGGING"}))
			Expect(netconfig.DefaultNetUtilsCommandExecutor.(*netconfig.MockNetUtilsCommandExecutor).MockCmds[2].Args).To(Equal([]string{"iptables", "-w", "-t", "mangle", "-C", "LOGGING", "-m", "limit", "--limit", "10/min", "-j", "LOG", "--log-prefix", "Policy-Filter-Dropped:", "--log-level", "4"}))
			Expect(netconfig.DefaultNetUtilsCommandExecutor.(*netconfig.MockNetUtilsCommandExecutor).MockCmds[3].Args).To(Equal([]string{"iptables", "-w", "-t", "mangle", "-A", "LOGGING", "-m", "limit", "--limit", "10/min", "-j", "LOG", "--log-prefix", "Policy-Filter-Dropped:", "--log-level", "4"}))
			Expect(netconfig.DefaultNetUtilsCommandExecutor.(*netconfig.MockNetUtilsCommandExecutor).MockCmds[4].Args).To(Equal([]string{"iptables", "-w", "-t", "mangle", "-C", "LOGGING", "-j", "DROP"}))
			Expect(netconfig.DefaultNetUtilsCommandExecutor.(*netconfig.MockNetUtilsCommandExecutor).MockCmds[5].Args).To(Equal([]string{"iptables", "-w", "-t", "mangle", "-A", "LOGGING", "-j", "DROP"}))
		})
	})

	Describe("IPTablesLoggingChainRule", func() {

		DescribeTable("calls the correct command with the correct arguments",
			func(ipVersion, protocol, ipSet, device string, check bool, expectedArgs []string) {
				err := netconfig.IPTablesLoggingChainRule(ipVersion, protocol, ipSet, device, check, false)
				Expect(err).To(BeNil())
				Expect(netconfig.DefaultNetUtilsCommandExecutor.(*netconfig.MockNetUtilsCommandExecutor).MockCmds[0].Args).To(Equal(expectedArgs))
			},
			Entry("add rule", "", "tcp", "test-ipset", "ens5", false, []string{
				"iptables", "-w", "-t", "mangle", "-A", "POSTROUTING", "-o", "ens5", "-p", "tcp", "--syn", "-m", "set", "--match-set", "test-ipset", "dst", "-j", "LOGGING",
			}),
			Entry("check rule", "", "udp", "test-ipset", "ens5", true, []string{
				"iptables", "-w", "-t", "mangle", "-C", "POSTROUTING", "-o", "ens5", "-p", "udp", "-m", "set", "--match-set", "test-ipset", "dst", "-j", "LOGGING",
			}),
			Entry("add rule with different ip version", "6", "tcp", "test-ipset", "ens5", false, []string{
				"ip6tables", "-w", "-t", "mangle", "-A", "POSTROUTING", "-o", "ens5", "-p", "tcp", "--syn", "-m", "set", "--match-set", "test-ipset", "dst", "-j", "LOGGING",
			}),
		)
	})

	Describe("AddIPTablesLoggingRules", func() {
		It("makes the right calls to iptables if rules exist", func() {

			err := netconfig.AddIPTablesLoggingRules("4", "test-ipset", "ens5", false)
			Expect(err).To(BeNil())
			Expect(len(netconfig.DefaultNetUtilsCommandExecutor.(*netconfig.MockNetUtilsCommandExecutor).MockCmds)).To(Equal(2))
			Expect(netconfig.DefaultNetUtilsCommandExecutor.(*netconfig.MockNetUtilsCommandExecutor).MockCmds[0].Args).To(Equal([]string{"iptables", "-w", "-t", "mangle", "-C", "POSTROUTING", "-o", "ens5", "-p", "tcp", "--syn", "-m", "set", "--match-set", "test-ipset", "dst", "-j", "LOGGING"}))
			Expect(netconfig.DefaultNetUtilsCommandExecutor.(*netconfig.MockNetUtilsCommandExecutor).MockCmds[1].Args).To(Equal([]string{"iptables", "-w", "-t", "mangle", "-C", "POSTROUTING", "-o", "ens5", "-p", "udp", "-m", "set", "--match-set", "test-ipset", "dst", "-j", "LOGGING"}))
		})
		It("makes the right calls to iptables if rules don't exist", func() {
			mockExecutor := &netconfig.MockNetUtilsCommandExecutor{}
			mockExecutor.MockIPRoutesStdOut = bytes.NewBufferString("default via 10.242.0.1 dev ens5 proto dhcp src 10.242.0.198 metric 1024")
			mockExecutor.MockCheckError = errors.New("iptables: Bad rule (does a matching rule exist in that chain?).")
			netconfig.DefaultNetUtilsCommandExecutor = mockExecutor

			err := netconfig.AddIPTablesLoggingRules("4", "test-ipset", "ens5", false)
			Expect(err).To(BeNil())
			Expect(len(netconfig.DefaultNetUtilsCommandExecutor.(*netconfig.MockNetUtilsCommandExecutor).MockCmds)).To(Equal(4))
			Expect(netconfig.DefaultNetUtilsCommandExecutor.(*netconfig.MockNetUtilsCommandExecutor).MockCmds[0].Args).To(Equal([]string{"iptables", "-w", "-t", "mangle", "-C", "POSTROUTING", "-o", "ens5", "-p", "tcp", "--syn", "-m", "set", "--match-set", "test-ipset", "dst", "-j", "LOGGING"}))
			Expect(netconfig.DefaultNetUtilsCommandExecutor.(*netconfig.MockNetUtilsCommandExecutor).MockCmds[1].Args).To(Equal([]string{"iptables", "-w", "-t", "mangle", "-A", "POSTROUTING", "-o", "ens5", "-p", "tcp", "--syn", "-m", "set", "--match-set", "test-ipset", "dst", "-j", "LOGGING"}))
			Expect(netconfig.DefaultNetUtilsCommandExecutor.(*netconfig.MockNetUtilsCommandExecutor).MockCmds[2].Args).To(Equal([]string{"iptables", "-w", "-t", "mangle", "-C", "POSTROUTING", "-o", "ens5", "-p", "udp", "-m", "set", "--match-set", "test-ipset", "dst", "-j", "LOGGING"}))
			Expect(netconfig.DefaultNetUtilsCommandExecutor.(*netconfig.MockNetUtilsCommandExecutor).MockCmds[3].Args).To(Equal([]string{"iptables", "-w", "-t", "mangle", "-A", "POSTROUTING", "-o", "ens5", "-p", "udp", "-m", "set", "--match-set", "test-ipset", "dst", "-j", "LOGGING"}))

		})
	})
	Describe("InitIPSet", func() {
		It("check if ipset exists and stop if no error", func() {
			err := netconfig.InitIPSet("4", "test-ipset")
			Expect(err).To(BeNil())
			Expect(len(netconfig.DefaultNetUtilsCommandExecutor.(*netconfig.MockNetUtilsCommandExecutor).MockCmds)).To(Equal(1))
			Expect(netconfig.DefaultNetUtilsCommandExecutor.(*netconfig.MockNetUtilsCommandExecutor).MockCmds[0].Args).To(Equal([]string{"ipset", "list", "test-ipset"}))
		})
		It("check if ipset exists and is created if not", func() {
			mockExecutor := &netconfig.MockNetUtilsCommandExecutor{}
			mockExecutor.MockCheckError = errors.New("ipset v7.11: The set with the given name does not exist")
			netconfig.DefaultNetUtilsCommandExecutor = mockExecutor
			err := netconfig.InitIPSet("4", "test-ipset")
			Expect(err).To(BeNil())
			Expect(len(netconfig.DefaultNetUtilsCommandExecutor.(*netconfig.MockNetUtilsCommandExecutor).MockCmds)).To(Equal(2))
			Expect(netconfig.DefaultNetUtilsCommandExecutor.(*netconfig.MockNetUtilsCommandExecutor).MockCmds[0].Args).To(Equal([]string{"ipset", "list", "test-ipset"}))
			Expect(netconfig.DefaultNetUtilsCommandExecutor.(*netconfig.MockNetUtilsCommandExecutor).MockCmds[1].Args).To(Equal([]string{"ipset", "create", "test-ipset", "hash:net", "family", "inet", "maxelem", "65536"}))
		})
	})
	Describe("AddIPListToIPSet", func() {
		It("Check if all IPs are added", func() {
			ipList := `
line with []
- 1.2.3.4/32
- 5.6.7.0/24
- 9.8.7.16/28

`
			ipSetScript := `-A test-ipset 1.2.3.4/32
-A test-ipset 5.6.7.0/24
-A test-ipset 9.8.7.16/28
quit
`
			err := netconfig.AddIPListToIPSet("test-ipset", ipList)
			Expect(err).To(BeNil())
			Expect(len(netconfig.DefaultNetUtilsCommandExecutor.(*netconfig.MockNetUtilsCommandExecutor).MockCmds)).To(Equal(1))
			Expect(netconfig.DefaultNetUtilsCommandExecutor.(*netconfig.MockNetUtilsCommandExecutor).MockCmds[0].Args).To(Equal([]string{"ipset", "-"}))
			buf, _ := ioutil.ReadAll(netconfig.DefaultNetUtilsCommandExecutor.(*netconfig.MockNetUtilsCommandExecutor).MockCmds[0].Stdin)
			Expect(string(buf)).To(Equal(ipSetScript))
		})
	})

	Describe("UpdateIPSet", func() {
		It("correct commands are called", func() {
			ipList := `
line with []
- 1.2.3.4/32
- 5.6.7.0/24
- 9.8.7.16/28

`
			err := netconfig.UpdateIPSet("4", "test-ipset", ipList, "ens5", false)
			Expect(err).To(BeNil())
			Expect(len(netconfig.DefaultNetUtilsCommandExecutor.(*netconfig.MockNetUtilsCommandExecutor).MockCmds)).To(Equal(6))
			Expect(netconfig.DefaultNetUtilsCommandExecutor.(*netconfig.MockNetUtilsCommandExecutor).MockCmds[0].Args).To(Equal([]string{"ipset", "create", "tmpIPSet", "hash:net", "family", "inet", "maxelem", "65536"}))
			Expect(netconfig.DefaultNetUtilsCommandExecutor.(*netconfig.MockNetUtilsCommandExecutor).MockCmds[1].Args).To(Equal([]string{"ipset", "-"}))
			Expect(netconfig.DefaultNetUtilsCommandExecutor.(*netconfig.MockNetUtilsCommandExecutor).MockCmds[2].Args).To(Equal([]string{"iptables", "-w", "-t", "mangle", "-C", "POSTROUTING", "-o", "ens5", "-p", "tcp", "--syn", "-m", "set", "--match-set", "test-ipset", "dst", "-j", "LOGGING"}))
			Expect(netconfig.DefaultNetUtilsCommandExecutor.(*netconfig.MockNetUtilsCommandExecutor).MockCmds[3].Args).To(Equal([]string{"iptables", "-w", "-t", "mangle", "-C", "POSTROUTING", "-o", "ens5", "-p", "udp", "-m", "set", "--match-set", "test-ipset", "dst", "-j", "LOGGING"}))
			Expect(netconfig.DefaultNetUtilsCommandExecutor.(*netconfig.MockNetUtilsCommandExecutor).MockCmds[4].Args).To(Equal([]string{"ipset", "swap", "tmpIPSet", "test-ipset"}))
			Expect(netconfig.DefaultNetUtilsCommandExecutor.(*netconfig.MockNetUtilsCommandExecutor).MockCmds[5].Args).To(Equal([]string{"ipset", "destroy", "tmpIPSet"}))
		})
	})

	Describe("GetBlackholeRoutes", func() {
		mockExecutor := &netconfig.MockNetUtilsCommandExecutor{}
		mockExecutor.MockIPRoutesStdOut = bytes.NewBufferString("1.2.3.4/32 dev dummy0 scope link \n5.2.3.4/30 dev dummy0 scope link")
		netconfig.DefaultNetUtilsCommandExecutor = mockExecutor
		blackholeIPs, err := netconfig.GetBlackholeRoutes("4")
		Expect(err).To(BeNil())
		Expect(len(blackholeIPs)).To(Equal(2))
		Expect(blackholeIPs[0]).To(Equal("1.2.3.4/32"))
		Expect(blackholeIPs[1]).To(Equal("5.2.3.4/30"))
	})

	Describe("UpdateRoutes", func() {
		It("correct commands are called", func() {
			ipList := `
			line with []
			- 1.2.3.4/32
			- 5.6.7.0/24
			- 9.8.7.16/28
			
			`
			mockExecutor := &netconfig.MockNetUtilsCommandExecutor{}
			mockExecutor.MockIPRoutesStdOut = bytes.NewBufferString("1.2.3.4 dev dummy0 scope link \n5.2.3.4/30 dev dummy0 scope link")
			netconfig.DefaultNetUtilsCommandExecutor = mockExecutor
			err := netconfig.UpdateRoutes("4", ipList)
			Expect(err).To(BeNil())
			Expect(len(netconfig.DefaultNetUtilsCommandExecutor.(*netconfig.MockNetUtilsCommandExecutor).MockCmds)).To(Equal(3))
			Expect(netconfig.DefaultNetUtilsCommandExecutor.(*netconfig.MockNetUtilsCommandExecutor).MockCmds[0].Args).To(Equal([]string{"ip", "-4", "route"}))
			Expect(netconfig.DefaultNetUtilsCommandExecutor.(*netconfig.MockNetUtilsCommandExecutor).MockCmds[1].Args).To(Equal([]string{"ip", "-4", "-batch", "tmpFile"}))
			Expect(netconfig.DefaultNetUtilsCommandExecutor.(*netconfig.MockNetUtilsCommandExecutor).MockCmds[2].Args).To(Equal([]string{"ip", "-4", "-batch", "tmpFile"}))

		})
		It("correct commands are called, when there is no change", func() {
			ipList := `
			line with []
			- 1.2.3.4/32
			- 5.2.3.4/30
			
			`
			mockExecutor := &netconfig.MockNetUtilsCommandExecutor{}
			mockExecutor.MockIPRoutesStdOut = bytes.NewBufferString("1.2.3.4 dev dummy0 scope link \n5.2.3.4/30 dev dummy0 scope link")
			netconfig.DefaultNetUtilsCommandExecutor = mockExecutor
			err := netconfig.UpdateRoutes("4", ipList)
			Expect(err).To(BeNil())
			Expect(len(netconfig.DefaultNetUtilsCommandExecutor.(*netconfig.MockNetUtilsCommandExecutor).MockCmds)).To(Equal(1))
			Expect(netconfig.DefaultNetUtilsCommandExecutor.(*netconfig.MockNetUtilsCommandExecutor).MockCmds[0].Args).To(Equal([]string{"ip", "-4", "route"}))

		})

	})
})

func TestNetconfig(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Netconfig")
}
