# QORE Actions

GitHub Actions for the QORE security platform. Each Action lives in its own folder and is referenced by path:

```yaml
- uses: Be4Breach/qore-actions/<action-folder>@v1
```

## Actions

| Action | Folder | What it does |
|---|---|---|
| **Security scan** | [`security-scan`](security-scan) | Scans your repository with QORE (code, dependencies, secrets) and fails the build on new findings |

## Versioning

The repository is versioned as a whole: a release tag (`v1.0.0`) covers every Action in it, and the moving major
tag (`v1`) always points at the latest `v1.x.y`. Use `@v1` for compatible updates, or pin a release tag or a full
commit SHA for a fixed version.

## Adding an Action

1. Create a folder named for what the Action does (`cloud-posture`, `container-scan`, ...).
2. Put an `action.yml` and a `README.md` in it. A composite Action can reference its own files with
   `${{ github.action_path }}`, and shared code in the repository root with `${{ github.action_path }}/..`.
3. Add a row to the table above.
4. Release a new tag. Breaking changes to an existing Action need a new major version for the whole repository.

## Notes

- A repository's Actions are only listed on the GitHub Marketplace when `action.yml` sits at the repository
  root. These Actions live in folders, so they are referenced by path and documented at
  <https://docs.be4breach.com>.
