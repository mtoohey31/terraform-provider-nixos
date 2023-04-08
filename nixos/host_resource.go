package nixos

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"golang.org/x/crypto/ssh"
)

// TODO: write tests: https://developer.hashicorp.com/terraform/tutorials/providers-plugin-framework/providers-plugin-framework-acceptance-testing

// TODO: improve error message when user doesn't have permission to switch
// system profile

// TODO: how can we avoid requiring privileged users and stuff and not using
// sudo on the remote host when it's not necessary

// TODO: use config validators to validate formats of string config entries
// up-front where possible

const (
	gcRootDir                 = ".terraform-provider-nixos"
	currentProfileSymlinkPath = "/run/current-system"
)

// Ensure the implementation satisfies the expected interfaces.
var _ resource.ResourceWithModifyPlan = nixOSHostResource{}

// NewNixOSHostResource is a helper function to simplify the provider
// implementation.
func NewNixOSHostResource() resource.Resource {
	return nixOSHostResource{}
}

// nixOSHostResource is the resource implementation.
type nixOSHostResource struct{}

// Metadata returns the resource type name.
func (nixOSHostResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_host"
}

// Schema defines the schema for the resource.
func (nixOSHostResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	// TODO: support reboot on apply

	// TODO: support remote builds

	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			// Computed state
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Unique identifier of remote system, should be considered opaque.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"last_updated": schema.StringAttribute{
				Computed:    true,
				Description: "Time at which the host's system profile as last updated.",
			},
			"profile_path": schema.StringAttribute{
				Computed:    true,
				Description: "Store path of the host's system profile.",
			},

			// NixOS system configuration
			"flake_ref": schema.StringAttribute{
				Required:            true,
				Description:         "The flake reference from which the host's configuration is built.",
				MarkdownDescription: "The [flake reference](https://github.com/NixOS/nix/blob/master/src/nix/flake.md#flake-references) from which the host's configuration is build.",
			},

			// SSH connection options
			"username": schema.StringAttribute{
				Required:    true,
				Description: "SSH username to log in with. This user must have permission to change the system profile.",
			},
			"host": schema.StringAttribute{
				Required:    true,
				Description: "Hostname or IP address to connect to with SSH.",
			},
			"port": schema.Int64Attribute{
				Optional:            true,
				Description:         "Port to connect to with SSH. Defaults to 22.",
				MarkdownDescription: "Port to connect to with SSH. Defaults to `22`.",
			},
			"public_key": schema.StringAttribute{
				Required:            true,
				Description:         "The public key that the server will present, in the format used in authorized_keys files. Can be obtained using ssh-keyscan.",
				MarkdownDescription: "The public key that the server will present, in the format used in `authorized_keys` files. Can be obtained using `ssh-keyscan`.",
			},
			"private_key_path": schema.StringAttribute{
				Required:    true,
				Description: "SSH private key path to authenticate with.",
			},
		},
	}
}

// hostResourceModel maps the resource schema data.
type hostResourceModel struct {
	// Computed state

	ID          types.String `tfsdk:"id"`
	LastUpdated types.String `tfsdk:"last_updated"`
	ProfilePath types.String `tfsdk:"profile_path"`

	// NixOS system configuration

	FlakeRef types.String `tfsdk:"flake_ref"`

	// SSH connection options

	Username       types.String `tfsdk:"username"`
	Host           types.String `tfsdk:"host"`
	Port           types.Int64  `tfsdk:"port"`
	PublicKey      types.String `tfsdk:"public_key"`
	PrivateKeyPath types.String `tfsdk:"private_key_path"`
}

// sshClient returns an ssh client based on the ssh connection options in this
// model. If an error is encountered, it will be added to diagnostics and nil
// will be returned.
func (m hostResourceModel) sshClient(diagnostics *diag.Diagnostics) *ssh.Client {
	buf, err := os.ReadFile(m.PrivateKeyPath.ValueString())
	if reportErrorWithTitle(err, "Could Not Read SSH Private Key", diagnostics) {
		return nil
	}

	priv, err := ssh.ParsePrivateKey(buf)
	if reportErrorWithTitle(err, "Could Not Parse SSH Private Key", diagnostics) {
		return nil
	}

	pub, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(m.PublicKey.ValueString()))
	if reportErrorWithTitle(err, "Could Not Parse SSH Public Key", diagnostics) {
		return nil
	}
	if len(rest) > 0 {
		diagnostics.AddError(
			"SSH Public Key Contained More Than One Entry",
			"SSH public key should only contain a single entry, but it contained more than one.",
		)
		return nil
	}

	sshConfig := &ssh.ClientConfig{
		User: m.Username.ValueString(),
		Auth: []ssh.AuthMethod{ssh.PublicKeys(priv)},
		HostKeyCallback: ssh.HostKeyCallback(func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			expected := pub.Marshal()
			actual := key.Marshal()
			if !bytes.Equal(expected, actual) {
				return fmt.Errorf("host key mismatch, expected: %s, got: %s",
					base64.StdEncoding.EncodeToString(expected),
					base64.StdEncoding.EncodeToString(actual),
				)
			}

			return nil
		}),
	}

	port := int64(22)
	if !m.Port.IsNull() {
		port = m.Port.ValueInt64()
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", m.Host.ValueString(), port), sshConfig)
	if reportErrorWithTitle(err, "Could Not Establish SSH Connection", diagnostics) {
		return nil
	}

	return client
}

// localBuild builds the given flakeRef locally, linking the output to a local
// directory (in order to create a gc root) whose path is based on id. If any
// errors are encountered, they are added to diagnostics, and an empty string
// will be returned.
func localBuild(flakeRef, host, id string, diagnostics *diag.Diagnostics) string {
	// Create gc root directory
	err := os.Mkdir(gcRootDir, 0o700)
	if reportNotErrorIsWithTitle(
		err,
		os.ErrExist, // Don't complain if the directory already exists
		"Could Not Create GC Root Directory",
		diagnostics,
	) {
		return ""
	}

	// TODO: run nix in internal-json logging mode, then parse output and pass
	// through important info to the terraform logs using the tflog package.
	//   - https://github.com/maralorn/nix-output-monitor/blob/532fb9a98d2150183a97f3cfd315a6e5186d7a47/lib/NOM/Parser/JSON.hs
	//   - https://developer.hashicorp.com/terraform/tutorials/providers-plugin-framework/providers-plugin-framework-logging

	// Build system profile and symlink result in gc root directory
	outLink := filepath.Join(gcRootDir, id)
	args := []string{"build", "--out-link", outLink, nixOSRebuildFlakeRef(flakeRef, host)}
	combinedOutput, err := exec.Command("nix", args...).CombinedOutput()
	if err != nil {
		diagnostics.AddError(
			"Failed to Build System Profile",
			fmt.Sprintf("%s, output:\n%s", err, combinedOutput),
		)
		return ""
	}

	// Read store path of system profile
	profilePath, err := filepath.EvalSymlinks(outLink)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			diagnostics.AddError(
				"`nix build` Did Not Create Out Link",
				fmt.Sprintf("`nix build` succeeded but did not create out link; output:\n%s", combinedOutput),
			)
			return ""
		}

		diagnostics.AddError("Failed to Evaluate Out Link", err.Error())
		return ""
	}

	return profilePath
}

// copyAndActivate copies the ProfilePath of m to the remote host and activates
// it. If an error is encountered, it will be added to diagnostics. It returns
// whether any errors were encountered.
func (m hostResourceModel) copyAndActivate(client *ssh.Client, diagnostics *diag.Diagnostics) bool {
	// TODO: it looks like the ssh used by `nix copy` is just based on path, so
	// we can potentially intercept the ssh connection stuff on the other side
	// of this and use this executable as the ssh binary (by creating temporary
	// symlinks and path entries, then checking os.Argv[0] on startup) to make
	// the ssh stuff as pure and deterministic as possible

	// Copy system profile closure
	remoteURI := fmt.Sprintf("ssh://%s@%s", m.Username.ValueString(), m.Host.ValueString())
	cmd := exec.Command("nix", "copy", "--to", remoteURI, m.ProfilePath.ValueString())
	envEntry := fmt.Sprintf("NIX_SSHOPTS=-p %d -i %s", m.Port.ValueInt64(), m.PrivateKeyPath.ValueString())
	cmd.Env = append(os.Environ(), envEntry)
	combinedOutput, err := cmd.CombinedOutput()
	if err != nil {
		diagnostics.AddError(
			"Failed to Copy System Profile",
			fmt.Sprintf("%s, output:\n%s", err, combinedOutput),
		)
		return false
	}

	// Activate new system profile
	session := createSession(client, diagnostics)
	if session == nil {
		return false
	}
	_, err = output(session, fmt.Sprintf("%s/bin/switch-to-configuration switch", m.ProfilePath.ValueString()))
	if reportErrorWithTitle(err, "Failed to Switch System Profile", diagnostics) {
		return false
	}

	// Record profile switch
	session = createSession(client, diagnostics)
	if session == nil {
		return false
	}
	_, err = output(session, fmt.Sprintf("nix-env -p /nix/var/nix/profiles/system --set %s", m.ProfilePath.ValueString()))
	if reportErrorWithTitle(err, "Failed to Set System Profile", diagnostics) {
		return false
	}

	return true
}

// Create creates the resource and sets the initial Terraform state.
func (nixOSHostResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	// TODO: maybe support infecting non-nixos hosts, if the user explicitly
	// enables that behaviour (since this would be destructive, so we should
	// make them set an extra option to ensure they've understood what they're
	// doing). This should probably be done by go:embed'ding the script source,
	// copying it over via ssh, then executing it

	// Retrieve values from plan
	var plan hostResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Establish ssh connection
	client := plan.sshClient(&resp.Diagnostics)
	if client == nil {
		return
	}
	defer client.Close()

	// Activate the new profile
	if !plan.copyAndActivate(client, &resp.Diagnostics) {
		return
	}
	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))

	// Set state to fully populated data
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Read refreshes the Terraform state with the latest data.
func (nixOSHostResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	// Get current state
	var state hostResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get refreshed profile path from host

	// Establish ssh connection
	client := state.sshClient(&resp.Diagnostics)
	if client == nil {
		return
	}
	defer client.Close()

	// Read desired profile path using nix show-derivation on flake ref locally

	cmd := exec.Command("nix", "show-derivation", nixOSRebuildFlakeRef(
		state.FlakeRef.ValueString(),
		state.Host.ValueString(),
	))
	showDerivationOutput, combinedOutput, err := combinedAndOutput(cmd)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to Show System Profile Derivation",
			fmt.Sprintf("%s, output:\n%s", err, combinedOutput),
		)
		return
	}

	var showData map[string]struct {
		Outputs struct {
			Out struct {
				Path *string `json:"path"`
			} `json:"out"`
		} `json:"outputs"`
	}
	if err := json.Unmarshal(showDerivationOutput, &showData); reportErrorWithTitle(
		err,
		"Failed to Unmarshal `nix show-derivation` Output",
		&resp.Diagnostics,
	) {
		return
	}
	if len(showData) == 0 {
		resp.Diagnostics.AddError(
			"`nix show-derivation` Returned No Derivations",
			fmt.Sprintf("`nix show-derivation` succeeded but did not return any derivations; output\n%s", combinedOutput),
		)
		return
	}
	if len(showData) > 1 {
		derivationPaths := make([]string, 0, len(showData))
		for derivationPath := range showData {
			derivationPaths = append(derivationPaths, derivationPath)
		}

		resp.Diagnostics.AddError(
			"`nix show-derivation` Returned Multiple Derivations",
			fmt.Sprintf(
				"`nix show-derivation` returned more than one derivation, expected one: %s",
				strings.Join(derivationPaths, ", "),
			),
		)
		return
	}

	var localProfilePath string
	for _, derivation := range showData {
		if derivation.Outputs.Out.Path == nil {
			resp.Diagnostics.AddError(
				"`nix show-derivation` Output Missing .outputs.out.path",
				fmt.Sprintf("`nix show-derivation` succeeded but returned a derivation missing the .outputs.out.path field; output\n%s", combinedOutput),
			)
			return
		}

		localProfilePath = *derivation.Outputs.Out.Path
	}

	// Read current profile path from remote host
	session := createSession(client, &resp.Diagnostics)
	if session == nil {
		return
	}
	realpathOutput, err := output(session, "realpath "+currentProfileSymlinkPath)
	if reportErrorWithTitle(err, "Failed to Read System Profile Path", &resp.Diagnostics) {
		return
	}
	remoteProfilePath := strings.TrimSuffix(string(realpathOutput), "\n")
	state.ProfilePath = types.StringValue(remoteProfilePath)

	// Compare local and remote profile paths
	if localProfilePath != remoteProfilePath {
		// Mismatch, will need to update the remote host's profile path. We
		// can't cause a difference between the configuration and the actual
		// value by messing with profile path since it's computed and not
		// specified by the user (and that would be semantically incorrect
		// anyways, because regardless of whether it matches, it's semantically
		// correct to say that the current state is whatever the remote profile
		// path is). However, since flake ref is specified by the user, it can
		// cause a conflict leading to an update, so we set it to unknown.
		// (This also makes sense semantically, because if the remote host's
		// profile path doesn't match the one corresponding to the flake ref,
		// then it's correct to say that we don't know what flake reference
		// constructed the host's current profile.)
		state.FlakeRef = types.StringNull()
	}

	// Read last_updated
	session = createSession(client, &resp.Diagnostics)
	if session == nil {
		return
	}
	statOutput, err := output(session, "stat -c %Y "+currentProfileSymlinkPath)
	if reportErrorWithTitle(err, "Failed to Stat System Profile Path", &resp.Diagnostics) {
		return
	}
	epoch, err := strconv.ParseInt(strings.TrimSuffix(string(statOutput), "\n"), 10, 64)
	if reportErrorWithTitle(err, "Failed to Parse Stat Output As Epoch Timestamp Integer", &resp.Diagnostics) {
		return
	}

	state.LastUpdated = types.StringValue(time.Unix(epoch, 0).Format(time.RFC850))

	// Set refreshed state
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// ModifyPlan modifies the planned Terraform state.
func (nixOSHostResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	// Check if plan is null, meaning the resource is planned for destruction.
	if req.Plan.Raw.IsNull() {
		return
	}

	// Retrieve values from plan
	var plan hostResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Check if state is null, meaning the resource is planned for creation, in
	// which case we'll need to connect to the machine and read the id since it
	// can be known before apply
	if req.State.Raw.IsNull() {
		// Retrieve values from config
		var config hostResourceModel
		resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
		if resp.Diagnostics.HasError() {
			return
		}

		// Establish ssh connection
		client := config.sshClient(&resp.Diagnostics)
		if client == nil {
			return
		}
		defer client.Close()

		// Read id from remote /etc/machine-id file
		session := createSession(client, &resp.Diagnostics)
		if session == nil {
			return
		}
		machineIDOutput, err := output(session, "cat /etc/machine-id")
		if reportErrorWithTitle(err, "Failed to Read /etc/machine-id File", &resp.Diagnostics) {
			return
		}
		id := strings.TrimSuffix(string(machineIDOutput), "\n")
		plan.ID = types.StringValue(id)
	}

	// BUG: the fact that the flake is externally defined leads to a
	// potentially un-fixable TOCTOU issue because this function is required by
	// terraform to report the same value of plan.ProfilePath for both the
	// "Initial Planned State" and "Final Planned State", but there's no way to
	// prevent the flake from being modified externally between the
	// computations of those two values, and we get called with the exact same
	// arguments in either case, so we can't detect the situation. Maybe we can
	// implement a hack that works around the API's shortcomings by storing
	// state inside the resource object to skip the calculation on the second
	// call.

	// Build the system profile locally
	profilePath := localBuild(plan.FlakeRef.ValueString(), plan.Host.ValueString(), plan.ID.ValueString(), &resp.Diagnostics)
	if profilePath == "" {
		return
	}
	plan.ProfilePath = types.StringValue(profilePath)

	// Set modified plan
	resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (nixOSHostResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	// Retrieve values from plan
	var plan hostResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Establish ssh connection
	client := plan.sshClient(&resp.Diagnostics)
	if client == nil {
		return
	}
	defer client.Close()

	// Activate the new profile
	if !plan.copyAndActivate(client, &resp.Diagnostics) {
		return
	}
	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))

	// Set modified state
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete deletes the resource and removes the Terraform state on success.
func (nixOSHostResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	// Retrieve values from state
	var state hostResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Remove the gc root symlink for this host
	err := os.Remove(filepath.Join(gcRootDir, state.ID.ValueString()))
	if reportNotErrorIsWithTitle(
		err,
		os.ErrNotExist, // Don't complain if there is no symlink
		"Could Not Remove GC Root Symlink",
		&resp.Diagnostics,
	) {
		return
	}

	// Check if the gcRootDir is empty, and if so, remove it

	entries, err := os.ReadDir(gcRootDir)
	if reportNotErrorIsWithTitle(
		err,
		os.ErrNotExist, // Don't complain if the gcRootDir is already gone
		"Could Not Read GC Root Directory",
		&resp.Diagnostics,
	) {
		return
	}

	if len(entries) > 0 {
		return
	}

	reportErrorWithTitle(
		os.Remove(gcRootDir),
		"Could Not Remove GC Root Directory",
		&resp.Diagnostics,
	)

	// We don't do anything to the remote system, because there isn't really
	// anything useful that we can do when a host resource is deleted.
}
