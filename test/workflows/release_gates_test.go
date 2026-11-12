package workflows

import (
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

type step struct {
	Name string            `json:"name"`
	If   string            `json:"if"`
	Run  string            `json:"run"`
	Env  map[string]string `json:"env"`
}

type job struct {
	If    string `json:"if"`
	Steps []step `json:"steps"`
}

type workflow struct {
	Jobs map[string]job `json:"jobs"`
}

func readRepoFile(t *testing.T, rel string) []byte {
	t.Helper()
	root, err := os.OpenRoot("../..")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	raw, err := root.ReadFile(rel)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func readWorkflow(t *testing.T, name string) workflow {
	t.Helper()
	var w workflow
	if err := yaml.Unmarshal(readRepoFile(t, ".github/workflows/"+name), &w); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return w
}

func findStep(t *testing.T, j job, name string) step {
	t.Helper()
	for _, s := range j.Steps {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("no step %q", name)
	return step{}
}

func TestReleasePublishJobsRunOnlyFromAReleaseTag(t *testing.T) {
	w := readWorkflow(t, "release.yml")
	for _, name := range []string{"image", "chart", "quickstart"} {
		condition := w.Jobs[name].If
		if !strings.Contains(condition, "startsWith(github.ref, 'refs/tags/v')") {
			t.Errorf("job %s runs on %q; it must require a release tag", name, condition)
		}
		if strings.Contains(condition, "workflow_dispatch") {
			t.Errorf("job %s condition %q lets a dispatch from a branch publish :latest and overwrite the chart", name, condition)
		}
	}
	if condition := w.Jobs["cli"].If; !strings.Contains(condition, "startsWith(github.ref, 'refs/tags/')") {
		t.Errorf("job cli runs on %q; it attests and releases, so it must require a tag", condition)
	}
	guard := w.Jobs["bpf-objects"].Steps[0]
	if !strings.Contains(guard.If, "!startsWith(github.ref, 'refs/tags/')") || !strings.Contains(guard.Run, "exit 1") {
		t.Errorf("the first bpf-objects step %q must fail a run from a branch, got if=%q", guard.Name, guard.If)
	}
}

func TestChartPushRequiresTheTaggedVersion(t *testing.T) {
	run := findStep(t, readWorkflow(t, "release.yml").Jobs["chart"], "Lint, package, push").Run
	check := strings.Index(run, `"v${version}" != "${GITHUB_REF_NAME}"`)
	push := strings.Index(run, "helm push")
	if check < 0 || push < 0 || check > push {
		t.Errorf("the chart job must compare Chart.yaml's version with the tag before helm push:\n%s", run)
	}
}

func TestReleasePleaseSkipsRequireABranchOfThisRepository(t *testing.T) {
	w := readWorkflow(t, "chainsaw.yml")
	for _, name := range []string{"chainsaw", "quickstart-smoke"} {
		condition := w.Jobs[name].If
		if !strings.Contains(condition, "release-please--") {
			t.Fatalf("job %s no longer skips release-please branches; update this test", name)
		}
		if !strings.Contains(condition, "github.event.pull_request.head.repo.full_name == github.repository") {
			t.Errorf("job %s skips on a branch name alone (%q); a fork can pick that name", name, condition)
		}
	}
}

func TestCRDCompatExitCodesReachTheWorkflow(t *testing.T) {
	raw := string(readRepoFile(t, ".github/workflows/go-ci.yml"))
	if strings.Contains(raw, "go run ./hack/crdcompat") {
		t.Error("go run reports every failure as exit 1, so a crdcompat error (2) reads as a declared break")
	}
	if !strings.Contains(raw, `go build -o "${RUNNER_TEMP}/crdcompat" ./hack/crdcompat`) {
		t.Error("crdcompat is not built before it runs")
	}
}

func TestMakefileToolsArePinnedToVersions(t *testing.T) {
	raw := string(readRepoFile(t, "Makefile"))
	for _, m := range regexp.MustCompile(`go install (\S+)@(\S+)`).FindAllStringSubmatch(raw, -1) {
		if strings.HasPrefix(m[2], "release-") || m[2] == "latest" || m[2] == "main" || m[2] == "master" {
			t.Errorf("%s installs from the moving ref %s", m[1], m[2])
		}
	}
	if !regexp.MustCompile(`(?m)^SETUP_ENVTEST_VERSION \?= v[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(raw) {
		t.Error("SETUP_ENVTEST_VERSION is not a release version Renovate can track")
	}
}

func gitIn(t *testing.T, dir string, env []string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	cmd.Env = append(cmd.Env, env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestDCOExemptionsHoldOnlyForThisRepository(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	script := findStep(t, readWorkflow(t, "dco.yml").Jobs["dco-check"], "Verify Signed-off-by on every commit").Run

	dir := t.TempDir()
	gitIn(t, dir, nil, "init", "-q", "-b", "main")
	commit := func(email, message string) string {
		env := []string{
			"GIT_AUTHOR_NAME=a", "GIT_AUTHOR_EMAIL=" + email,
			"GIT_COMMITTER_NAME=a", "GIT_COMMITTER_EMAIL=" + email,
		}
		gitIn(t, dir, env, "commit", "-q", "--allow-empty", "-m", message)
		return gitIn(t, dir, nil, "rev-parse", "HEAD")
	}
	base := commit("dev@example.com", "base\n\nSigned-off-by: dev <dev@example.com>")
	unsigned := commit("dev@example.com", "unsigned")
	botBase := gitIn(t, dir, nil, "rev-parse", "HEAD")
	botAuthored := commit("1+renovate[bot]@users.noreply.github.com", "bot")

	cases := []struct {
		name     string
		baseSHA  string
		headSHA  string
		headRef  string
		headRepo string
		wantPass bool
	}{
		{"release-please branch here", base, unsigned, "release-please--branches--main", "gma1k/podtrace", true},
		{"release-please branch from a fork", base, unsigned, "release-please--branches--main", "someone/podtrace", false},
		{"bot author here", botBase, botAuthored, "renovate/x", "gma1k/podtrace", true},
		{"bot author from a fork", botBase, botAuthored, "feature", "someone/podtrace", false},
		{"unsigned commit here", base, unsigned, "feature", "gma1k/podtrace", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("bash", "-c", script)
			cmd.Dir = dir
			cmd.Env = append(os.Environ(),
				"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
				"BASE_SHA="+tc.baseSHA, "HEAD_SHA="+tc.headSHA,
				"HEAD_REF="+tc.headRef, "HEAD_REPO="+tc.headRepo, "BASE_REPO=gma1k/podtrace",
			)
			out, err := cmd.CombinedOutput()
			if passed := err == nil; passed != tc.wantPass {
				t.Errorf("passed=%v, want %v\n%s", passed, tc.wantPass, out)
			}
		})
	}
}
