// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package netconfig

import (
	"bytes"
	"os/exec"
)

type NetUtilsCommandExecutor interface {
	ExecuteIPTablesCommand(ipVersion string, args ...string) error
	ExecuteIPRouteCommand(ipVersion string, args ...string) (*bytes.Buffer, error)
	ExecuteIPSetCommand(args ...string) error
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
