//go:generate go build -o testdata/bin1/nix testdata/nix1.go
//go:generate go build -o testdata/bin2/nix testdata/nix2.go
//go:generate go build -o testdata/bin3/nix testdata/nix3.go

package nixos

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"mtoohey.com/terraform-provider-nixos/internal/testutils/sshtest"
)

func testCheckSSHExecRequests(server *sshtest.Server, expected []string) resource.TestCheckFunc {
	return func(*terraform.State) error {
		actual := server.Requests()
		if !reflect.DeepEqual(expected, actual) {
			return fmt.Errorf("expected ssh exec requests %#v, got %#v", expected, actual)
		}

		return nil
	}
}

func testCheckGCRootDir(expectedSymlinks map[string]string) resource.TestCheckFunc {
	return func(*terraform.State) error {
		if expectedSymlinks == nil {
			// nil indicates that the directory should not exist at all

			_, err := os.Stat(".terraform-provider-nixos")
			if err == nil {
				return fmt.Errorf("expected gc root dir to not exist")
			}
			if !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("stat'ing gc root dir failed with unexpected error: %w", err)
			}

			return nil
		}

		entries, err := os.ReadDir(".terraform-provider-nixos")
		if err != nil {
			return fmt.Errorf("failed to read gc root dir: %w", err)
		}

		actual := map[string]string{}
		for _, entry := range entries {
			dest, err := os.Readlink(filepath.Join(".terraform-provider-nixos", entry.Name()))
			if err != nil {
				return fmt.Errorf("readlink failed: %w", err)
			}

			actual[entry.Name()] = dest
		}

		if !reflect.DeepEqual(expectedSymlinks, actual) {
			return fmt.Errorf("expected gc root dir %#v, got %#v", expectedSymlinks, actual)
		}

		return nil
	}
}

func TestNixOSHostResource(t *testing.T) {
	// Create and move to tempdir for duration of test

	tempDir := t.TempDir()

	oldWd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(tempDir))
	t.Cleanup(func() { require.NoError(t, os.Chdir(oldWd)) })

	// Start ssh server

	ts := sshtest.NewKeyAuthServer(t)

	// Write client private key to file

	clientPrivBytes, err := x509.MarshalPKCS8PrivateKey(ts.ClientPrivateKey)
	require.NoError(t, err)

	err = os.WriteFile("client-priv", pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: clientPrivBytes,
	}), 0o600)
	require.NoError(t, err)

	serverHost, serverPort, ok := strings.Cut(ts.Addr.String(), ":")
	require.True(t, ok)

	// Create mock bin directory
	require.NoError(t, os.Mkdir("bin", 0o700))

	// Find terraform, to be used when setting path later
	terraformPath, err := exec.LookPath("terraform")
	require.NoError(t, err)

	// Run tests
	resource.Test(t, resource.TestCase{
		IsUnitTest:               true,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				PreConfig: func() {
					t.Setenv("PATH", strings.Join([]string{
						filepath.Dir(terraformPath),
						filepath.Join(oldWd, "testdata", "bin1"),
					}, string(os.PathListSeparator)))

					ts.Reset(map[string][]sshtest.Response{
						"cat /etc/machine-id": {
							{Stdout: []byte("test-machine-id\n")},
							{Stdout: []byte("test-machine-id\n")},
							{Stdout: []byte("test-machine-id\n")},
						},
						"/nix/store/test-profile-path/bin/switch-to-configuration switch":            {{}},
						"nix-env -p /nix/var/nix/profiles/system --set /nix/store/test-profile-path": {{}},
						"stat -c %Y /run/current-system": {
							{Stdout: []byte("135123512\n")},
							{Stdout: []byte("135123512\n")},
						},
						"realpath /run/current-system": {{Stdout: []byte("/nix/store/test-profile-path\n")}},
					})
				},
				Config: providerConfig + fmt.Sprintf(`
resource "nixos_host" "test" {
  flake_ref        = "path/to/test/flake#test.flake.attr"
  username         = "test-username"
  host             = "%s"
  port             = %s
  public_key       = "%s"
  private_key_path = "client-priv"
}
`, serverHost, serverPort, ts.PublicKeyString()),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nixos_host.test", "id", "test-machine-id"),
					resource.TestCheckResourceAttr("nixos_host.test", "last_updated", time.Unix(135123512, 0).Format(time.RFC850)),
					resource.TestCheckResourceAttr("nixos_host.test", "profile_path", "/nix/store/test-profile-path"),

					resource.TestCheckResourceAttr("nixos_host.test", "flake_ref", "path/to/test/flake#test.flake.attr"),

					resource.TestCheckResourceAttr("nixos_host.test", "username", "test-username"),
					resource.TestCheckResourceAttr("nixos_host.test", "host", serverHost),
					resource.TestCheckResourceAttr("nixos_host.test", "port", serverPort),
					resource.TestCheckResourceAttr("nixos_host.test", "public_key", ts.PublicKeyString()),
					resource.TestCheckResourceAttr("nixos_host.test", "private_key_path", "client-priv"),

					testCheckSSHExecRequests(ts, []string{
						"cat /etc/machine-id",
						"cat /etc/machine-id",
						"cat /etc/machine-id",
						"/nix/store/test-profile-path/bin/switch-to-configuration switch",
						"nix-env -p /nix/var/nix/profiles/system --set /nix/store/test-profile-path",
						"stat -c %Y /run/current-system",
					}),
					testCheckGCRootDir(map[string]string{"test-machine-id": "/nix/store/test-profile-path"}),
				),
			},
			// Update and Read: flake_ref changes
			{
				PreConfig: func() {
					t.Setenv("PATH", strings.Join([]string{
						filepath.Dir(terraformPath),
						filepath.Join(oldWd, "testdata", "bin2"),
					}, string(os.PathListSeparator)))

					ts.Reset(map[string][]sshtest.Response{
						"realpath /run/current-system": {
							{Stdout: []byte("/nix/store/test-profile-path\n")},
							// Post Check
							{Stdout: []byte("/nix/store/other-profile-path\n")},
						},
						"stat -c %Y /run/current-system": {
							{Stdout: []byte("135123512\n")},
							{Stdout: []byte("135123513\n")},
							// Post Check
							{Stdout: []byte("135123513\n")},
						},
						"/nix/store/other-profile-path/bin/switch-to-configuration switch":            {{}},
						"nix-env -p /nix/var/nix/profiles/system --set /nix/store/other-profile-path": {{}},
					})
				},
				Config: providerConfig + fmt.Sprintf(`
resource "nixos_host" "test" {
  flake_ref        = "path/to/other/flake#other.flake.attr"
  username         = "test-username"
  host             = "%s"
  port             = %s
  public_key       = "%s"
  private_key_path = "client-priv"
}
`, serverHost, serverPort, ts.PublicKeyString()),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nixos_host.test", "id", "test-machine-id"),
					resource.TestCheckResourceAttr("nixos_host.test", "last_updated", time.Unix(135123513, 0).Format(time.RFC850)),
					resource.TestCheckResourceAttr("nixos_host.test", "profile_path", "/nix/store/other-profile-path"),

					resource.TestCheckResourceAttr("nixos_host.test", "flake_ref", "path/to/other/flake#other.flake.attr"),

					resource.TestCheckResourceAttr("nixos_host.test", "username", "test-username"),
					resource.TestCheckResourceAttr("nixos_host.test", "host", serverHost),
					resource.TestCheckResourceAttr("nixos_host.test", "port", serverPort),
					resource.TestCheckResourceAttr("nixos_host.test", "public_key", ts.PublicKeyString()),
					resource.TestCheckResourceAttr("nixos_host.test", "private_key_path", "client-priv"),

					testCheckSSHExecRequests(ts, []string{
						"realpath /run/current-system",
						"stat -c %Y /run/current-system",
						"/nix/store/other-profile-path/bin/switch-to-configuration switch",
						"nix-env -p /nix/var/nix/profiles/system --set /nix/store/other-profile-path",
						"stat -c %Y /run/current-system",
					}),
					testCheckGCRootDir(map[string]string{"test-machine-id": "/nix/store/other-profile-path"}),
				),
			},
			// Update and Read: output path produced by flake_ref changes
			{
				PreConfig: func() {
					t.Setenv("PATH", strings.Join([]string{
						filepath.Dir(terraformPath),
						filepath.Join(oldWd, "testdata", "bin3"),
					}, string(os.PathListSeparator)))

					ts.Reset(map[string][]sshtest.Response{
						"realpath /run/current-system": {
							{Stdout: []byte("/nix/store/other-profile-path\n")},
							// Post Check
							{Stdout: []byte("/nix/store/third-profile-path\n")},
						},
						"stat -c %Y /run/current-system": {
							{Stdout: []byte("135123513\n")},
							{Stdout: []byte("135123514\n")},
							// Post Check
							{Stdout: []byte("135123514\n")},
						},
						"/nix/store/third-profile-path/bin/switch-to-configuration switch":            {{}},
						"nix-env -p /nix/var/nix/profiles/system --set /nix/store/third-profile-path": {{}},
					})
				},
				Config: providerConfig + fmt.Sprintf(`
resource "nixos_host" "test" {
  flake_ref        = "path/to/other/flake#other.flake.attr"
  username         = "test-username"
  host             = "%s"
  port             = %s
  public_key       = "%s"
  private_key_path = "client-priv"
}
`, serverHost, serverPort, ts.PublicKeyString()),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nixos_host.test", "id", "test-machine-id"),
					resource.TestCheckResourceAttr("nixos_host.test", "last_updated", time.Unix(135123514, 0).Format(time.RFC850)),
					resource.TestCheckResourceAttr("nixos_host.test", "profile_path", "/nix/store/third-profile-path"),

					resource.TestCheckResourceAttr("nixos_host.test", "flake_ref", "path/to/other/flake#other.flake.attr"),

					resource.TestCheckResourceAttr("nixos_host.test", "username", "test-username"),
					resource.TestCheckResourceAttr("nixos_host.test", "host", serverHost),
					resource.TestCheckResourceAttr("nixos_host.test", "port", serverPort),
					resource.TestCheckResourceAttr("nixos_host.test", "public_key", ts.PublicKeyString()),
					resource.TestCheckResourceAttr("nixos_host.test", "private_key_path", "client-priv"),

					testCheckSSHExecRequests(ts, []string{
						"realpath /run/current-system",
						"stat -c %Y /run/current-system",
						"/nix/store/third-profile-path/bin/switch-to-configuration switch",
						"nix-env -p /nix/var/nix/profiles/system --set /nix/store/third-profile-path",
						"stat -c %Y /run/current-system",
					}),
					testCheckGCRootDir(map[string]string{"test-machine-id": "/nix/store/third-profile-path"}),
				),
			},
			// Delete
			{
				PreConfig: func() {
					t.Setenv("PATH", strings.Join([]string{
						filepath.Dir(terraformPath),
						filepath.Join(oldWd, "testdata", "bin3"),
					}, string(os.PathListSeparator)))

					ts.Reset(map[string][]sshtest.Response{
						"realpath /run/current-system":   {{Stdout: []byte("/nix/store/other-profile-path\n")}},
						"stat -c %Y /run/current-system": {{Stdout: []byte("135123514\n")}},
					})
				},
				Config: providerConfig,
				Check:  testCheckGCRootDir(nil),
			},
		},
	})
}

func TestNixOSHostResource_validateConfig(t *testing.T) {
	// Create and move to tempdir for duration of test

	tempDir := t.TempDir()

	oldWd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(tempDir))
	t.Cleanup(func() { require.NoError(t, os.Chdir(oldWd)) })

	// Set up keys

	pubEd, privEd, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	pub, err := ssh.NewPublicKey(pubEd)
	require.NoError(t, err)

	pubString := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))

	privBytes, err := x509.MarshalPKCS8PrivateKey(privEd)
	require.NoError(t, err)

	err = os.WriteFile("client-priv", pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	}), 0o600)
	require.NoError(t, err)

	err = os.WriteFile("client-priv-empty", nil, 0o600)
	require.NoError(t, err)

	resource.Test(t, resource.TestCase{
		IsUnitTest:               true,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Invalid Host
			{
				Config: providerConfig + fmt.Sprintf(`
resource "nixos_host" "test" {
  flake_ref        = "path/to/test/flake#test.flake.attr"
  username         = "test-username"
  host             = "***"
  public_key       = "%s"
  private_key_path = "client-priv"
}`, pubString),
				ExpectError: regexp.MustCompile(`(?s)Invalid Host.*Host is not a valid IP address or hostname`),
			},
			// Invalid Port, negative
			{
				Config: providerConfig + fmt.Sprintf(`
resource "nixos_host" "test" {
  flake_ref        = "path/to/test/flake#test.flake.attr"
  username         = "test-username"
  host             = "test-host"
  port             = -1
  public_key       = "%s"
  private_key_path = "client-priv"
}`, pubString),
				ExpectError: regexp.MustCompile(`(?s)Port Too Small.*Port was <= 0, expected positive, unsigned, 16-bit integer`),
			},
			// Invalid Port, positive, too large
			{
				Config: providerConfig + fmt.Sprintf(`
resource "nixos_host" "test" {
  flake_ref        = "path/to/test/flake#test.flake.attr"
  username         = "test-username"
  host             = "test-host"
  port             = 65536
  public_key       = "%s"
  private_key_path = "client-priv"
}`, pubString),
				ExpectError: regexp.MustCompile(`(?s)Port Too Large.*Port was > 65535, expected positive, unsigned, 16-bit integer`),
			},
			// Invalid PublicKey, not parseable
			{
				Config: providerConfig + `
resource "nixos_host" "test" {
  flake_ref        = "path/to/test/flake#test.flake.attr"
  username         = "test-username"
  host             = "test-host"
  public_key       = "***"
  private_key_path = "client-priv"
}`,
				ExpectError: regexp.MustCompile(`(?s)Could Not Parse SSH Public Key.*ssh: no key found`),
			},
			// Invalid PublicKey, multiple entries
			{
				Config: providerConfig + fmt.Sprintf(`
resource "nixos_host" "test" {
  flake_ref        = "path/to/test/flake#test.flake.attr"
  username         = "test-username"
  host             = "test-host"
  public_key       = "%s\n%[1]s"
  private_key_path = "client-priv"
}`, pubString),
				ExpectError: regexp.MustCompile(`(?s)SSH Public Key Contained More Than One Entry.*SSH public key should only contain a single entry, but it contained more than.*one`),
			},
			// Invalid PrivateKeyFile, missing
			{
				Config: providerConfig + fmt.Sprintf(`
resource "nixos_host" "test" {
  flake_ref        = "path/to/test/flake#test.flake.attr"
  username         = "test-username"
  host             = "test-host"
  public_key       = "%s"
  private_key_path = "bogus"
}`, pubString),
				ExpectError: regexp.MustCompile(`(?s)Could Not Read SSH Private Key.*open bogus: no such file or directory`),
			},
			// Invalid PrivateKeyFile, parse fails
			{
				Config: providerConfig + fmt.Sprintf(`
resource "nixos_host" "test" {
  flake_ref        = "path/to/test/flake#test.flake.attr"
  username         = "test-username"
  host             = "test-host"
  public_key       = "%s"
  private_key_path = "client-priv-empty"
}`, pubString),
				ExpectError: regexp.MustCompile(`(?s)Could Not Parse SSH Private Key.*ssh: no key found`),
			},
		},
	})
}
