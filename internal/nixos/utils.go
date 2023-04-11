package nixos

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"golang.org/x/crypto/ssh"
)

// nixOSRebuildFlakeRef modifies the given flakeRef in the same way that:
//
//	nixos-rebuild --flake $flake_ref
//
// ...modifies $flake_ref before actually building the derivation.
func nixOSRebuildFlakeRef(flakeRef, host string) string {
	// https://github.com/NixOS/nixpkgs/blob/3cd694d1bdf69d8413e8da74aaf39c11ac162366/pkgs/os-specific/linux/nixos-rebuild/nixos-rebuild.sh#L355

	var flakeAttr string
	if hashIdx := strings.LastIndexByte(flakeRef, '#'); hashIdx != -1 {
		if !strings.ContainsRune(flakeRef[hashIdx+1:], '"') {
			flakeAttr = flakeRef[hashIdx+1:]
			flakeRef = flakeRef[:hashIdx]
		}
	}
	if flakeAttr == "" {
		flakeAttr = fmt.Sprintf("nixosConfigurations.%s", host)
	} else {
		flakeAttr = fmt.Sprintf("nixosConfigurations.%s", flakeAttr)
	}

	return fmt.Sprintf("%s#%s.config.system.build.toplevel", flakeRef, flakeAttr)
}

// reportErrorWithTitle adds an error whose title is the given value and whose
// detail is err.Error() if err is non-nil. It returns whether err is non-nil.
// It should usually be used ih the following way:
//
//	..., err := foo()
//	if reportErrorWithTitle(err, "Title", diagnostics) {
//		return
//	}
func reportErrorWithTitle(err error, title string, diagnostics *diag.Diagnostics) bool {
	if err == nil {
		return false
	}

	diagnostics.AddError(title, err.Error())
	return true
}

// reportNotErrorIsWithTitle adds an error whose title is the given value and
// whose detail is err.Error() if err is non-nil and !errors.Is(err, target).
// It returns whether an error was reported. It should usually be used ih the
// following way:
//
//	..., err := foo()
//	if reportErrorWithTitle(err, io.EOF, "Title", diagnostics) {
//		return
//	}
func reportNotErrorIsWithTitle(err, target error, title string, diagnostics *diag.Diagnostics) bool {
	if err == nil || errors.Is(err, target) {
		return false
	}

	diagnostics.AddError(title, err.Error())
	return true
}

// combinedAndOutput reports the stdout, as well as the combined stdout and
// stderr resulting from the execution of cmd.
func combinedAndOutput(cmd *exec.Cmd) (output, combinedOutput []byte, err error) {
	var stdout, combined bytes.Buffer

	cmd.Stdout = io.MultiWriter(&stdout, &combined)
	cmd.Stderr = &combined

	err = cmd.Run()
	return stdout.Bytes(), combined.Bytes(), err
}

// createSession creates a session from the given client. If an error is
// encountered, it will be added to diagnostics and nil will be returned.
func createSession(client *ssh.Client, diagnostics *diag.Diagnostics) *ssh.Session {
	session, err := client.NewSession()
	if reportErrorWithTitle(err, "Could Not Create SSH Session", diagnostics) {
		return nil
	}

	return session
}

// output executes cmd, returning the stdout if it succeeds, or an error
// message (containing the stderr, if it is non-empty) if the execution fails.
func output(session *ssh.Session, cmd string) ([]byte, error) {
	defer session.Close()

	var stdout, stderr bytes.Buffer

	session.Stdout = &stdout
	session.Stderr = &stderr

	err := session.Run(cmd)
	if err != nil {
		if strings.TrimSpace(stderr.String()) != "" {
			return nil, fmt.Errorf("%w, stderr:\n%s", err, stderr.String())
		}

		return nil, err
	}

	return stdout.Bytes(), nil
}
