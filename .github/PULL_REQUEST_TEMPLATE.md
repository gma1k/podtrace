<!--
Thanks for opening a PR! A few quick conventions before you submit:

  • Title: Conventional Commit format — see CONTRIBUTING.md.
        feat: ...        new feature
        fix: ...         bug fix
        chore: ...       chore / refactor / dep bumps
        docs: ...        docs only
        test: ...        test-only
  • Subject ≤ 72 chars, imperative present tense, no trailing period.
  • Avoid Co-Authored-By trailers (project convention).
-->

## Summary

<!-- One or two sentences on what changes and why. Focus on the "why". -->

## Changes

<!-- Bullet list of the user-visible or operator-visible deltas. Skip
     this section for trivial chore/docs PRs. -->

-
-

## Test plan

<!-- Tick every box that applies. Strike-through (~~text~~) the ones
     that genuinely don't, with a one-line reason. -->

- [ ] `make test` (unit) green
- [ ] `make test-integration` green (or n/a for docs/chore)
- [ ] `make chainsaw` green on a local kind cluster (or n/a)
- [ ] `golangci-lint run ./...` clean
- [ ] `make manifests` / `make generate` / `make clientset` re-run if
      `api/v1alpha1/` types changed; regenerated files committed
- [ ] User-facing change → `docs/` updated
- [ ] Behavioral change → manual verification noted below

<!-- For UI-less infra changes, paste the relevant log/CR-status excerpts
     that prove the new behavior on a real cluster. -->

## Related issues

<!-- Link via "Closes #N" / "Refs #N" so GitHub auto-closes on merge. -->

Closes #

## Risk notes

<!-- Anything reviewers should look at extra carefully: schema changes,
     RBAC widening, default-behavior changes, performance hot paths,
     dropped backwards compatibility. Delete this section if none. -->
