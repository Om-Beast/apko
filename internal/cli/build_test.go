// Copyright 2023 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cli_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/validate"
	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/internal/cli"
	"chainguard.dev/apko/pkg/build"
	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/lock"
	"chainguard.dev/apko/pkg/sbom/generator/spdx"
)

func TestBuild(t *testing.T) {
	unsetSourceDateEpoch(t)

	ctx := t.Context()
	tmp := t.TempDir()

	golden := filepath.Join("testdata", "golden")
	goldenSboms := filepath.Join(golden, "sboms")
	config := filepath.Join("testdata", "apko.yaml")

	archs := types.ParseArchitectures([]string{"amd64", "arm64"})
	opts := []build.Option{
		build.WithConfig(config, []string{}),
		build.WithSBOMGenerators(spdx.New()),
		build.WithTags("golden:latest"),
		build.WithAnnotations(map[string]string{
			"org.opencontainers.image.vendor": "Vendor",
			"org.opencontainers.image.title":  "Title",
		}),
	}

	sbomPath := filepath.Join(tmp, "sboms")
	err := os.MkdirAll(sbomPath, 0o750)
	require.NoError(t, err)

	err = cli.BuildCmd(ctx, "golden:latest", tmp, archs, []string{}, true, sbomPath, withIsolatedDirs(t, opts...)...)
	require.NoError(t, err)

	root, err := layout.ImageIndexFromPath(tmp)
	require.NoError(t, err)

	gold, err := layout.ImageIndexFromPath(golden)
	require.NoError(t, err)

	// Not strictly necessary, but this will validate that the index is well-formed.
	require.NoError(t, validate.Index(root))
	require.NoError(t, validate.Index(gold))

	// TODO: We should diff manifests and layer contents.
	got, err := root.Digest()
	require.NoError(t, err)

	want, err := gold.Digest()
	require.NoError(t, err)

	require.Equal(t, want, got)

	// Check that the sbomPath is not empty.
	sboms, err := os.ReadDir(goldenSboms)
	require.NoError(t, err)
	require.NotEmpty(t, sboms)

	for _, s := range sboms {
		goldSbom := filepath.Join(goldenSboms, s.Name())
		sbom := filepath.Join(sbomPath, s.Name())

		want, err := os.ReadFile(goldSbom)
		require.NoError(t, err)

		got, err := os.ReadFile(sbom)
		require.NoError(t, err)

		if bytes.Equal(want, got) {
			continue
		}

		// https://github.com/google/go-cmp/issues/224#issuecomment-650429859
		transformJSON := cmp.FilterValues(func(x, y []byte) bool {
			return json.Valid(x) && json.Valid(y)
		}, cmp.Transformer("ParseJSON", func(in []byte) (out any) {
			if err := json.Unmarshal(in, &out); err != nil {
				panic(err) // should never occur given previous filter to ensure valid JSON
			}
			return out
		}))

		if diff := cmp.Diff(want, got, transformJSON); diff != "" {
			t.Errorf("Mismatched SBOMs (-%q +%q):\n%s", goldSbom, sbom, diff)
		}
	}
}

func TestBuildLockfileMissingArchitectures(t *testing.T) {
	config := build.WithConfig("testdata/apko.yaml", nil)
	lockPath := filepath.Join(t.TempDir(), "amd64.lock.json")
	err := cli.LockCmd(t.Context(), lockPath, types.ParseArchitectures([]string{"x86_64"}), withIsolatedDirs(t, config))
	require.NoError(t, err)

	for _, tt := range []struct {
		name  string
		archs []types.Architecture
		sbom  bool
		want  string
	}{
		{"partially covered", nil, true, "arm64 (regenerate with apko lock --arch=amd64,arm64)"},
		{"entirely missing", []types.Architecture{"arm64"}, true, "arm64 (regenerate with apko lock --arch=arm64)"},
		{"multiple missing without SBOM", []types.Architecture{"s390x", "aarch64", "arm64"}, false, "arm64, s390x (regenerate with apko lock --arch=arm64,s390x)"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			out := t.TempDir()
			opts := withIsolatedDirs(t, config, build.WithLockFile(lockPath))
			if tt.sbom {
				opts = append(opts, build.WithSBOMGenerators(spdx.New()))
			}
			err := cli.BuildCmd(t.Context(), "test:latest", out, tt.archs, nil, tt.sbom, t.TempDir(), opts...)
			require.ErrorContains(t, err, fmt.Sprintf("lockfile %q has no packages for %s", lockPath, tt.want))
			require.NoFileExists(t, filepath.Join(out, "index.json"))
		})
	}
}

func TestBuildLockfileSubset(t *testing.T) {
	// The fixture was locked for amd64 and arm64. Both the config and the
	// installer must select only the APKs from the arm64 repository.
	l, err := lock.FromFile("testdata/apko.lock.json")
	require.NoError(t, err)
	buildSubset := func(path string) string {
		t.Helper()
		out := t.TempDir()
		opts := withIsolatedDirs(t, build.WithConfig("testdata/apko.yaml", nil), build.WithLockFile(path))
		err := cli.BuildCmd(t.Context(), "test:latest", out, []types.Architecture{"aarch64"}, nil, false, "", opts...)
		require.NoError(t, err)
		index, err := layout.ImageIndexFromPath(out)
		require.NoError(t, err)
		manifest, err := index.IndexManifest()
		require.NoError(t, err)
		require.Len(t, manifest.Manifests, 1)
		require.NotNil(t, manifest.Manifests[0].Platform)
		require.Equal(t, "linux/arm64", manifest.Manifests[0].Platform.String())
		return manifest.Manifests[0].Digest.String()
	}
	want := buildSubset("testdata/apko.lock.json")
	for i := range l.Contents.Packages {
		p := &l.Contents.Packages[i]
		p.Architecture = types.ParseArchitecture(p.Architecture).String()
	}
	path := filepath.Join(t.TempDir(), "oci.lock.json")
	require.NoError(t, l.SaveToFile(path))
	require.Equal(t, want, buildSubset(path))

	for i := range l.Contents.Packages {
		l.Contents.Packages[i].Architecture = "noarch"
	}
	path = filepath.Join(t.TempDir(), "noarch.lock.json")
	require.NoError(t, l.SaveToFile(path))
	require.Equal(t, want, buildSubset(path))
}

func TestBuildWithEmptyLockedPackageList(t *testing.T) {
	base := &types.BaseImageDescriptor{Image: "testdata/base_image", APKIndex: "testdata/base_image/metadata"}
	for _, tt := range []struct {
		name     string
		base     *types.BaseImageDescriptor
		packages []string
	}{
		{"empty world", nil, nil},
		{"base provides the requested package", base, []string{"package-x=1.0.0-r0"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			archs := types.ParseArchitectures([]string{"amd64", "arm64"})
			config := build.WithImageConfiguration(types.ImageConfiguration{Contents: types.ImageContents{
				Repositories: []string{"./testdata/packages"},
				Keyring:      []string{"./testdata/melange.rsa.pub"},
				BaseImage:    tt.base,
				Packages:     tt.packages,
			}})
			path := filepath.Join(t.TempDir(), "empty.lock.json")
			require.NoError(t, cli.LockCmd(t.Context(), path, archs, withIsolatedDirs(t, config)))
			l, err := lock.FromFile(path)
			require.NoError(t, err)
			require.Empty(t, l.Contents.Packages)

			out := t.TempDir()
			err = cli.BuildCmd(t.Context(), "test:latest", out, archs, nil, false, "",
				withIsolatedDirs(t, config, build.WithLockFile(path))...)
			require.NoError(t, err)
			index, err := layout.ImageIndexFromPath(out)
			require.NoError(t, err)
			manifest, err := index.IndexManifest()
			require.NoError(t, err)
			platforms := make([]string, 0, len(manifest.Manifests))
			for _, m := range manifest.Manifests {
				require.NotNil(t, m.Platform)
				platforms = append(platforms, m.Platform.String())
			}
			require.ElementsMatch(t, []string{"linux/amd64", "linux/arm64"}, platforms)

			// An extra package absent from the base still needs locked records.
			err = cli.BuildCmd(t.Context(), "test:latest", t.TempDir(), archs, nil, false, "",
				withIsolatedDirs(t, config, build.WithLockFile(path), build.WithExtraPackages([]string{"replayout"}))...)
			require.ErrorContains(t, err, "has no packages for amd64, arm64")
		})
	}
}

func TestBuildWithBase(t *testing.T) {
	unsetSourceDateEpoch(t)

	// top_image golden file can be regenerated using ./internal/cli/testdata/regenerate_golden_top_image.sh script.

	// TODO(sfc-gh-mhazy) Check sboms after base image support is reflected in them.

	ctx := t.Context()
	tmp := t.TempDir()
	apkoTempDir := t.TempDir()

	golden := filepath.Join("testdata", "top_image")
	config := filepath.Join("testdata", "image_on_top.apko.yaml")
	lockfile := filepath.Join("testdata", "image_on_top.apko.lock.json")

	archs := types.ParseArchitectures([]string{"amd64", "arm64"})
	opts := []build.Option{build.WithConfig(config, []string{}), build.WithSBOMGenerators(spdx.New()), build.WithTags("golden_top:latest"), build.WithLockFile(lockfile), build.WithTempDir(apkoTempDir)}

	sbomPath := filepath.Join(tmp, "sboms")
	err := os.MkdirAll(sbomPath, 0o750)
	require.NoError(t, err)

	err = cli.BuildCmd(ctx, "golden_top:latest", tmp, archs, []string{}, true, sbomPath, withIsolatedDirs(t, opts...)...)
	require.NoError(t, err)

	root, err := layout.ImageIndexFromPath(tmp)
	require.NoError(t, err)

	gold, err := layout.ImageIndexFromPath(golden)
	require.NoError(t, err)

	// Not strictly necessary, but this will validate that the index is well-formed.
	require.NoError(t, validate.Index(root))
	require.NoError(t, validate.Index(gold))

	// TODO: We should diff manifests and layer contents.
	got, err := root.Digest()
	require.NoError(t, err)

	want, err := gold.Digest()
	require.NoError(t, err)

	require.Equal(t, want, got)
}
