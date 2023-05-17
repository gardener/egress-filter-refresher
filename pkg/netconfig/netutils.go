// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package netconfig

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
)

type NetUtilsCommandExecutor interface {
	ExecuteIPTablesCommand(ipVersion string, args ...string) error
	ExecuteIPRouteCommand(ipVersion string, args ...string) (*bytes.Buffer, error)
	ExecuteIPSetCommand(args ...string) error
	ExecuteIPSetScript(ipSetScript string) error
	ExecuteIPRouteBatchCommand(ipVersion, script string) error
}

type OSNetUtilsCommandExecutor struct{}

func (r *OSNetUtilsCommandExecutor) ExecuteIPRouteCommand(ipVersion string, args ...string) (*bytes.Buffer, error) {
	args = append([]string{"-" + ipVersion}, args...)
	cmd := exec.Command("ip", args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	return &out, err
}

func (r *OSNetUtilsCommandExecutor) ExecuteIPRouteBatchCommand(ipVersion, script string) error {
	tmpFile, err := ioutil.TempFile("", "ip-route-batch")
	if err != nil {
		return fmt.Errorf("Error creating tmp file for ip route batch processing: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	err = ioutil.WriteFile(tmpFile.Name(), []byte(script), 0644)
	if err != nil {
		return fmt.Errorf("Error creating tmp file for ip route batch processing: %v", err)
	}

	cmd := exec.Command("ip", "-"+ipVersion, "-batch", tmpFile.Name())
	return cmd.Run()
}

func (r *OSNetUtilsCommandExecutor) ExecuteIPTablesCommand(ipVersion string, args ...string) error {
	if ipVersion == "4" {
		ipVersion = ""
	}
	args = append([]string{"-w"}, args...)
	cmd := exec.Command("ip"+ipVersion+"tables", args...)
	return cmd.Run()
}

func (r *OSNetUtilsCommandExecutor) ExecuteIPSetCommand(args ...string) error {
	cmd := exec.Command("ipset", args...)
	return cmd.Run()
}

func (r *OSNetUtilsCommandExecutor) ExecuteIPSetScript(script string) error {
	cmd := exec.Command("ipset", "-")
	cmd.Stdin = strings.NewReader(script)
	return cmd.Run()
}

type MockNetUtilsCommandExecutor struct {
	MockCmds           []*exec.Cmd
	MockIPRoutesStdOut *bytes.Buffer
	MockCheckError     error
}

func (m *MockNetUtilsCommandExecutor) ExecuteIPRouteCommand(ipVersion string, args ...string) (*bytes.Buffer, error) {
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
	cmd := exec.Command("ip"+ipVersion+"tables", args...)
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
	cmd := exec.Command("ip", "-"+ipVersion, "-batch", "tmpFile")
	cmd.Stdin = strings.NewReader(script)
	m.MockCmds = append(m.MockCmds, cmd)
	return nil
}
