// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package netconfig

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

type NetUtilsCommandExecutor interface {
	DetermineIPTablesBackend()
	ExecuteIPTablesCommand(ipVersion string, args ...string) error
	ExecuteIPRouteCommand(ipVersion string, args ...string) (string, error)
	ExecuteIPSetCommand(args ...string) error
	ExecuteIPSetScript(ipSetScript string) error
	ExecuteIPRouteBatchCommand(ipVersion, script string) error
}

type OSNetUtilsCommandExecutor struct {
	ipTablesBackend string
}

func (r *OSNetUtilsCommandExecutor) DetermineIPTablesBackend() {
	r.ipTablesBackend = "legacy"
	cmd := exec.Command("iptables-legacy-save")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return
	}
	outputV4 := out.String()

	r.ipTablesBackend = "legacy"
	cmd = exec.Command("ip6tables-legacy-save")

	cmd.Stdout = &out
	err = cmd.Run()
	if err != nil {
		return
	}
	outputV6 := out.String()

	if !strings.Contains(outputV4, "KUBE-IPTABLES-HINT") && !strings.Contains(outputV4, "KUBE-KUBELET-CANARY") && !strings.Contains(outputV6, "KUBE-IPTABLES-HINT") && !strings.Contains(outputV6, "KUBE-KUBELET-CANARY") {
		r.ipTablesBackend = "nft"
	}
}

func (r *OSNetUtilsCommandExecutor) ExecuteIPRouteCommand(ipVersion string, args ...string) (string, error) {
	args = append([]string{"-" + ipVersion}, args...)
	out, err := wrapCmd("ip", args...)
	return out, err
}

func (r *OSNetUtilsCommandExecutor) ExecuteIPRouteBatchCommand(ipVersion, script string) error {
	tmpFile, err := os.CreateTemp("", "ip-route-batch")
	if err != nil {
		return fmt.Errorf("error creating tmp file for ip route batch processing: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	err = os.WriteFile(tmpFile.Name(), []byte(script), 0600)
	if err != nil {
		return fmt.Errorf("error creating tmp file for ip route batch processing: %v", err)
	}

	_, err = wrapCmd("ip", "-"+ipVersion, "-batch", tmpFile.Name())
	return err
}

func (r *OSNetUtilsCommandExecutor) ExecuteIPTablesCommand(ipVersion string, args ...string) error {
	if ipVersion == "4" {
		ipVersion = ""
	}
	args = append([]string{"-w"}, args...)
	_, err := wrapCmd("ip"+ipVersion+"tables-"+r.ipTablesBackend, args...)
	return err
}

func (r *OSNetUtilsCommandExecutor) ExecuteIPSetCommand(args ...string) error {
	_, err := wrapCmd("ipset", args...)
	return err
}

func (r *OSNetUtilsCommandExecutor) ExecuteIPSetScript(script string) error {
	_, err := wrapCmdStdin("ipset", strings.NewReader(script), "-")
	return err
}

func wrapCmd(name string, arg ...string) (string, error) {
	return wrapCmdStdin(name, nil, arg...)
}

func wrapCmdStdin(name string, stdIn io.Reader, arg ...string) (string, error) {
	cmd := exec.Command(name, arg...)
	var stdOut, stdErr bytes.Buffer
	cmd.Stdout = &stdOut
	cmd.Stderr = &stdErr
	if stdIn != nil {
		cmd.Stdin = stdIn
	}
	err := cmd.Run()

	if err != nil {
		return "", fmt.Errorf("%w: stdout: %s  stderr: %s", err, stdOut.String(), stdErr.String())
	}

	return stdOut.String(), nil
}

type MockNetUtilsCommandExecutor struct {
	MockCmds           []*exec.Cmd
	MockIPRoutesStdOut string
	MockCheckError     error
	ipTablesBackend    string
}

func (m *MockNetUtilsCommandExecutor) ExecuteIPRouteCommand(ipVersion string, args ...string) (string, error) {
	args = append([]string{"-" + ipVersion}, args...)
	cmd := exec.Command("ip", args...)
	m.MockCmds = append(m.MockCmds, cmd)
	return m.MockIPRoutesStdOut, nil
}

func (m *MockNetUtilsCommandExecutor) ExecuteIPTablesCommand(ipVersion string, args ...string) error {
	if ipVersion == "4" {
		ipVersion = ""
	}
	args = append([]string{"-w"}, args...)
	cmd := exec.Command("ip"+ipVersion+"tables-"+m.ipTablesBackend, args...) // #nosec: G204 -- Test only.
	m.MockCmds = append(m.MockCmds, cmd)
	if args[3] == "-C" || args[3] == "-L" {
		return m.MockCheckError
	}
	return nil
}

func (m *MockNetUtilsCommandExecutor) ExecuteIPSetCommand(args ...string) error {
	cmd := exec.Command("ipset", args...)
	m.MockCmds = append(m.MockCmds, cmd)
	if args[0] == "list" {
		return m.MockCheckError
	}
	return nil
}

func (m *MockNetUtilsCommandExecutor) ExecuteIPSetScript(script string) error {
	cmd := exec.Command("ipset", "-")
	cmd.Stdin = strings.NewReader(script)
	m.MockCmds = append(m.MockCmds, cmd)
	return nil
}

func (m *MockNetUtilsCommandExecutor) ExecuteIPRouteBatchCommand(ipVersion, script string) error {
	cmd := exec.Command("ip", "-"+ipVersion, "-batch", "tmpFile") // #nosec: G204 -- Test only.
	cmd.Stdin = strings.NewReader(script)
	m.MockCmds = append(m.MockCmds, cmd)
	return nil
}

func (m *MockNetUtilsCommandExecutor) DetermineIPTablesBackend() {
	m.ipTablesBackend = "legacy"
}
