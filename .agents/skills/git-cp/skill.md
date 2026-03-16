---
name: git-cp
description: Commit, push, and optionally create a GitHub release with version bump
user_invocable: true
---

# /git-cp — Commit, Push & Release

Workflow for committing changes, pushing to dev, checking CI, and creating releases.

## Usage

```
/git-cp                    # commit + push to dev (auto-detect changes)
/git-cp release patch      # bump patch version (0.1.0 → 0.1.1) + GitHub release
/git-cp release minor      # bump minor version (0.1.0 → 0.2.0) + GitHub release
/git-cp release major      # bump major version (0.1.0 → 1.0.0) + GitHub release
/git-cp pr                 # create PR from dev → main (if CI green)
```

## Instructions

When the user invokes this skill, follow these steps:

### Mode 1: `/git-cp` (commit + push only)

1. Run `git status` to see changes
2. Run `git diff --stat` to summarize
3. Stage relevant files (NOT .env, credentials, or large binaries)
4. Generate a concise commit message based on the changes
5. Commit with `Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>`
6. Push to current branch (`git push origin dev`)
7. Report: commit hash, files changed, branch

### Mode 2: `/git-cp release <patch|minor|major>`

1. Determine current version from `Cargo.toml` workspace `[workspace.package] version`
2. Calculate new version based on bump type:
   - `patch`: 0.1.0 → 0.1.1
   - `minor`: 0.1.0 → 0.2.0
   - `major`: 0.1.0 → 1.0.0
3. Update version in `Cargo.toml` under `[workspace.package]`
4. Run `cargo check --workspace` to verify
5. Run `cargo test --workspace` to verify all tests pass
6. If tests fail → STOP, do not release, report the failure
7. Commit: `release: v{NEW_VERSION}`
8. Push to dev
9. Wait for CI to pass (check with `gh run list --branch dev --limit 1`)
10. If CI fails → STOP, do not tag or release
11. Create git tag: `git tag -a v{NEW_VERSION} -m "Release v{NEW_VERSION}"`
12. Push tag: `git push origin v{NEW_VERSION}`
13. Create GitHub release:
    ```
    gh release create v{NEW_VERSION} \
      --title "v{NEW_VERSION}" \
      --notes "$(generate_release_notes)" \
      --target dev
    ```
14. Report: version, tag, release URL

#### Release Notes Generation

Generate release notes by looking at commits since last tag (or all commits if no tags):

```bash
# Get commits since last tag
git log $(git describe --tags --abbrev=0 2>/dev/null || git rev-list --max-parents=0 HEAD)..HEAD --oneline
```

Format as:
```
## What's New in v{VERSION}

### Features
- feature 1
- feature 2

### Fixes
- fix 1

### Stats
- X tests passing
- Y files changed
```

### Mode 3: `/git-cp pr`

1. Check current branch is `dev`
2. Check if there are unpushed commits → push first
3. Wait for CI to pass on dev
4. If CI fails → STOP, report failure
5. Create PR:
   ```
   gh pr create --base main --head dev \
     --title "{summary of changes}" \
     --body "{auto-generated body with test plan}"
   ```
6. Report: PR URL

## Important Rules

- NEVER push directly to `main` — always use `dev` branch
- NEVER create a release if tests fail
- NEVER create a release if CI fails
- Always include `Co-Authored-By` in commits
- Always wait for CI before creating PR or release
- Use semantic versioning strictly
