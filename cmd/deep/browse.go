// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	deep "deepprotocol"
)

func viewerPath(executable string) string {
	return filepath.Join(filepath.Dir(executable), "viewer", "DEEP.Viewer.exe")
}

func viewerAvailable(executable string) bool {
	if runtime.GOOS != "windows" {
		return false
	}
	info, err := os.Stat(viewerPath(executable))
	return err == nil && info.Mode().IsRegular()
}

func launchViewer(ctx context.Context, executable, uri, config string) error {
	if !viewerAvailable(executable) {
		return errors.New("the graphical viewer requires Windows and bin/viewer/DEEP.Viewer.exe; build it with scripts/build-viewer.ps1, or use deep preview")
	}
	config, err := filepath.Abs(config)
	if err != nil {
		return err
	}
	args := []string{"--deep", executable, "--config", config}
	if uri != "" {
		args = append(args, "--uri", uri)
	}
	// The viewer owns its lifetime after launch, including its bounded fetch
	// children. No shell is used and remotely supplied URIs remain one argument.
	cmd := exec.Command(viewerPath(executable), args...)
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

func browseURI(ctx context.Context, args []string, diagnostic io.Writer) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	uri := ""
	if len(args) > 0 && len(args[0]) > 0 && args[0][0] != '-' {
		uri, args = args[0], args[1:]
		if _, err := deep.ParseURI(uri); err != nil {
			return err
		}
	}
	flags := newFlags("deep browse", diagnostic)
	config := flags.String("config", filepath.Join(filepath.Dir(executable), "config.json"), "Network and adapter registry")
	proceed, err := parseFlags(flags, args)
	if err != nil || !proceed {
		return err
	}
	return launchViewer(ctx, executable, uri, *config)
}

func previewCommand(ctx context.Context, args []string, out, diagnostic io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: deep preview deep://node.network/path [--config client.json]")
	}
	uri := args[0]
	if _, err := deep.ParseURI(uri); err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	flags := newFlags("deep preview", diagnostic)
	config := flags.String("config", filepath.Join(filepath.Dir(executable), "config.json"), "Network and adapter registry")
	proceed, err := parseFlags(flags, args[1:])
	if err != nil || !proceed {
		return err
	}
	return previewURI(ctx, uri, *config, out, diagnostic)
}
