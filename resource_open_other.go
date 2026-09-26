//go:build !unix

// SPDX-License-Identifier: Apache-2.0
package deep

import "os"

func openResourceFile(root *os.Root, name string) (*os.File, error) {
	return root.Open(name)
}
