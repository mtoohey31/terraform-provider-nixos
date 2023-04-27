package nixos

import (
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/stretchr/testify/assert"
)

func TestNixOSRebuildFlakeRef(t *testing.T) {
	tests := []struct {
		flakeRef, host string
		expected       string
	}{
		{
			flakeRef: "foo/bar#baz",
			host:     "quux",
			expected: "foo/bar#nixosConfigurations.baz.config.system.build.toplevel",
		},
		{
			flakeRef: "foo/bar#",
			host:     "quux",
			expected: "foo/bar#nixosConfigurations.quux.config.system.build.toplevel",
		},
		{
			flakeRef: "foo/bar",
			host:     "quux",
			expected: "foo/bar#nixosConfigurations.quux.config.system.build.toplevel",
		},
		{
			flakeRef: `foo/bar#baz"`,
			host:     "quux",
			expected: `foo/bar#baz"#nixosConfigurations.quux.config.system.build.toplevel`,
		},
		{
			flakeRef: `foo/bar"#baz`,
			host:     "quux",
			expected: `foo/bar"#nixosConfigurations.baz.config.system.build.toplevel`,
		},
	}

	for _, test := range tests {
		actual := nixOSRebuildFlakeRef(test.flakeRef, test.host)
		if test.expected != actual {
			t.Errorf("expected %s, got: %s", test.expected, actual)
		}
	}
}

func TestReportErrorWithTitle(t *testing.T) {
	assert.False(t, reportErrorWithTitle(nil, "", nil))

	actualDiagnostics := diag.Diagnostics{}
	assert.True(t, reportErrorWithTitle(assert.AnError, "Test Error Title", &actualDiagnostics))

	expectedDiagnostics := diag.Diagnostics{}
	expectedDiagnostics.AddError("Test Error Title", assert.AnError.Error())
	assert.Equal(t, expectedDiagnostics, actualDiagnostics)
}

func TestReportNotErrorIsWithTitle(t *testing.T) {
	assert.False(t, reportNotErrorIsWithTitle(nil, nil, "", nil))

	assert.False(t, reportNotErrorIsWithTitle(os.ErrNotExist, os.ErrNotExist, "", nil))

	actualDiagnostics := diag.Diagnostics{}
	assert.True(t, reportNotErrorIsWithTitle(assert.AnError, os.ErrNotExist, "Test Error Title", &actualDiagnostics))

	expectedDiagnostics := diag.Diagnostics{}
	expectedDiagnostics.AddError("Test Error Title", assert.AnError.Error())
	assert.Equal(t, expectedDiagnostics, actualDiagnostics)
}
