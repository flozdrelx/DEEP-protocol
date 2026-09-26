// SPDX-License-Identifier: Apache-2.0
//go:build !windows

package main

import "os"

func protectDirectory(path string) error { return os.Chmod(path, 0700) }
