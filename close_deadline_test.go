// SPDX-License-Identifier: Apache-2.0
package deep

import (
	"errors"
	"net"
	"testing"
	"time"
)

type noWriteDeadlineConn struct{ net.Conn }

func (noWriteDeadlineConn) SetWriteDeadline(time.Time) error {
	return errors.New("write deadline unsupported")
}

func TestSessionCloseSkipsMessageWhenWriteDeadlineFails(t *testing.T) {
	local, remote := net.Pipe()
	defer remote.Close()
	session := &Session{connection: noWriteDeadlineConn{local}}
	done := make(chan error, 1)
	go func() { done <- session.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		remote.Close()
		t.Fatal("Close blocked on a transport without write deadlines")
	}
}
