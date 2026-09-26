//go:build unix

// SPDX-License-Identifier: Apache-2.0
package deep

import (
	"os"
	"syscall"
)

// Nonblocking open prevents a FIFO swapped into the served tree from holding
// a worker forever. The caller checks the opened descriptor before reading.
func openResourceFile(root *os.Root, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
