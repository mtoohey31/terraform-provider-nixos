package nixos

import "testing"

func Test_nixOSRebuildFlakeRef(t *testing.T) {
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
