// SPDX-License-Identifier: Apache-2.0
//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
)

// Restrict the new empty directory before writing any private material. Files
// inherit this ACL. Go's 0700/0600 modes do not establish Windows access controls.
func protectDirectory(path string) error {
	current, err := user.Current()
	if err != nil {
		return err
	}
	if !strings.HasPrefix(current.Uid, "S-1-") {
		return fmt.Errorf("cannot determine current user's Windows SID")
	}
	command := filepath.Join(os.Getenv("SystemRoot"), "System32", "icacls.exe")
	output, err := exec.Command(command, path, "/inheritance:r", "/grant:r", "*"+current.Uid+":(OI)(CI)F", "/Q").CombinedOutput()
	if err != nil {
		return fmt.Errorf("set current-user-only Windows ACL: %w (%q)", err, output)
	}
	return nil
}
