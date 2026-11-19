package workflows

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const tarballEpoch = 1795000000

var releaseTarballFiles = []string{"podtrace", "LICENSE", "README.md", "CHANGELOG.md"}

func openWorkRoot(t *testing.T, dir string) *os.Root {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return root
}

func stageReleaseFiles(t *testing.T, mtime time.Time) string {
	t.Helper()
	work := t.TempDir()
	root := openWorkRoot(t, work)
	if err := root.Mkdir("staging", 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range releaseTarballFiles {
		path := filepath.Join("staging", name)
		mode := os.FileMode(0o644)
		if name == "podtrace" {
			mode = 0o755
		}
		if err := root.WriteFile(path, []byte("content of "+name), mode); err != nil {
			t.Fatal(err)
		}
		if err := root.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if err := root.Chtimes(path, mtime, mtime); err != nil {
			t.Fatal(err)
		}
	}
	return work
}

func packagerCommand(t *testing.T, work, epoch string) *exec.Cmd {
	t.Helper()
	script, err := filepath.Abs("../../hack/package-release-tarball.sh")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-c", `"$PACKAGER" staging out.tar.gz podtrace LICENSE README.md CHANGELOG.md`)
	cmd.Dir = work
	cmd.Env = append(os.Environ(), "PACKAGER="+script, "SOURCE_DATE_EPOCH="+epoch)
	return cmd
}

func packReleaseTarball(t *testing.T, work string) []byte {
	t.Helper()
	if raw, err := packagerCommand(t, work, "1795000000").CombinedOutput(); err != nil {
		t.Fatalf("package-release-tarball.sh: %v\n%s", err, raw)
	}
	raw, err := openWorkRoot(t, work).ReadFile("out.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestReleaseTarballIsReproducible(t *testing.T) {
	first := packReleaseTarball(t, stageReleaseFiles(t, time.Unix(1700000000, 0)))
	time.Sleep(1100 * time.Millisecond)
	second := packReleaseTarball(t, stageReleaseFiles(t, time.Unix(1800000000, 0)))

	if !bytes.Equal(first, second) {
		t.Fatal("the same files packed twice gave different tarballs; a release re-run would change the published sha256")
	}
}

func TestReleaseTarballEntriesAreNormalised(t *testing.T) {
	raw := packReleaseTarball(t, stageReleaseFiles(t, time.Now()))
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if !zr.ModTime.IsZero() || zr.Name != "" {
		t.Errorf("gzip header carries mtime %v and name %q, want neither", zr.ModTime, zr.Name)
	}
	tr := tar.NewReader(zr)
	var names []string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, hdr.Name)
		if hdr.ModTime.Unix() != tarballEpoch {
			t.Errorf("%s mtime = %d, want SOURCE_DATE_EPOCH %d", hdr.Name, hdr.ModTime.Unix(), tarballEpoch)
		}
		if hdr.Uid != 0 || hdr.Gid != 0 || hdr.Uname != "" || hdr.Gname != "" {
			t.Errorf("%s owner = %d:%d (%q:%q), want numeric 0:0", hdr.Name, hdr.Uid, hdr.Gid, hdr.Uname, hdr.Gname)
		}
		wantMode := int64(0o644)
		if hdr.Name == "podtrace" {
			wantMode = 0o755
		}
		if hdr.Mode != wantMode {
			t.Errorf("%s mode = %o, want %o", hdr.Name, hdr.Mode, wantMode)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != "content of "+hdr.Name {
			t.Errorf("%s content = %q", hdr.Name, body)
		}
	}
	if strings.Join(names, ",") != strings.Join(releaseTarballFiles, ",") {
		t.Errorf("entries = %v, want %v in the order given", names, releaseTarballFiles)
	}
}

func TestReleaseTarballRefusesMissingEpoch(t *testing.T) {
	raw, err := packagerCommand(t, stageReleaseFiles(t, time.Now()), "").CombinedOutput()
	if err == nil || !strings.Contains(string(raw), "SOURCE_DATE_EPOCH") {
		t.Fatalf("missing SOURCE_DATE_EPOCH: err = %v, output %q; want a refusal naming it", err, raw)
	}
}

func TestMakeReleasePacksWithTheReproducibleScript(t *testing.T) {
	makefile := string(readRepoFile(t, "Makefile"))
	if !strings.Contains(makefile, "SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) ./hack/package-release-tarball.sh") {
		t.Fatal("make release no longer packs its tarballs with hack/package-release-tarball.sh")
	}
	if strings.Contains(makefile, "-czf \"podtrace_") {
		t.Fatal("make release still calls tar -czf directly, which stamps file mtimes and a gzip timestamp")
	}
}
