# Documentation Deployment Comparison

Side-by-side comparison of GitHub Pages and GitLab Pages deployment for the USG EST Client documentation.

## Overview

Both platforms automatically build and deploy the Zensical documentation site, but use different approaches and configurations.

## Configuration Files

| Platform | Configuration | Documentation |
|----------|--------------|---------------|
| GitHub Pages | [.github/workflows/docs.yml](.github/workflows/docs.yml) | GitHub Actions Docs |
| GitLab Pages | [.gitlab-ci.yml](.gitlab-ci.yml) (pages job) | [GITLAB-CI.md](GITLAB-CI.md) |

## Side-by-Side Comparison

### GitHub Actions (docs.yml)

```yaml
name: Documentation
on:
  push:
    branches:
      - main
      - master
    paths:
      - "docs/**"
  workflow_dispatch:

permissions:
  contents: read
  pages: write
  id-token: write

jobs:
  deploy:
    environment:
      name: github-pages
      url: ${{ steps.deployment.outputs.page_url }}
    runs-on: ubuntu-latest
    steps:
      - uses: actions/configure-pages@v5
      - uses: actions/checkout@v6

      - name: Set up Python 3.14
        uses: actions/setup-python@v6
        with:
          python-version: 3.14

      - name: Install uv
        uses: astral-sh/setup-uv@v7

      - name: Install dependencies
        working-directory: ./docs
        run: |
          uv sync

      - name: Build Site
        working-directory: ./docs
        run: |
          uv run zensical build --clean

      - uses: actions/upload-pages-artifact@v4
        with:
          path: docs/site
      - uses: actions/deploy-pages@v4
        id: deployment
```

### GitLab CI/CD (pages job)

```yaml
pages:
  stage: docs
  image: python:3.14-slim
  before_script:
    # Install uv package manager (fast Python installer)
    - pip install --no-cache-dir uv
  script:
    # Build documentation site with Zensical
    - cd docs
    - uv sync
    - uv run zensical build --clean
    # GitLab Pages requires artifacts in 'public' directory at project root
    - mv site ../public
  artifacts:
    paths:
      - public
    expire_in: 1 week
  only:
    - main
  rules:
    # Only run when docs change or on main branch pushes
    - if: '$CI_COMMIT_BRANCH == "main"'
      changes:
        - docs/**/*
        - .gitlab-ci.yml
      when: always
    # Allow manual trigger for main branch
    - if: '$CI_COMMIT_BRANCH == "main"'
      when: manual
      allow_failure: true
```

## Key Differences

### 1. Trigger Configuration

**GitHub Actions:**
```yaml
on:
  push:
    branches: [main, master]
    paths: ["docs/**"]
  workflow_dispatch:  # Manual trigger
```

**GitLab CI/CD:**
```yaml
only:
  - main
rules:
  - if: '$CI_COMMIT_BRANCH == "main"'
    changes: [docs/**/*]
  - if: '$CI_COMMIT_BRANCH == "main"'
    when: manual  # Manual trigger
```

**Notes:**
- Both support automatic deployment on docs changes
- Both support manual triggering
- GitLab uses `rules:` for conditional logic, GitHub uses `on:` with `paths:`

### 2. Python Setup

**GitHub Actions:**
```yaml
- uses: actions/setup-python@v6
  with:
    python-version: 3.14
```

**GitLab CI/CD:**
```yaml
image: python:3.14-slim
```

**Notes:**
- GitHub uses action to install Python
- GitLab uses Docker image with Python pre-installed
- GitLab's `slim` image is smaller and faster

### 3. uv Installation

**GitHub Actions:**
```yaml
- uses: astral-sh/setup-uv@v7
```

**GitLab CI/CD:**
```yaml
- pip install --no-cache-dir uv
```

**Notes:**
- GitHub uses dedicated action
- GitLab uses direct pip install
- `--no-cache-dir` reduces image size

### 4. Build Process

**Both platforms:**
- Run `uv sync` to install dependencies
- Run `uv run zensical build --clean` to build site
- Working directory: `docs/`

**Identical steps - no differences**

### 5. Artifact Handling

**GitHub Actions:**
```yaml
- uses: actions/upload-pages-artifact@v4
  with:
    path: docs/site
- uses: actions/deploy-pages@v4
```

**GitLab CI/CD:**
```yaml
- mv site ../public
artifacts:
  paths:
    - public
```

**Notes:**
- GitHub requires artifact upload + deployment action
- GitLab requires `public/` directory at project root
- GitLab's approach is simpler (single step)

### 6. Deployment URL

**GitHub Pages:**
```
https://<username>.github.io/<repository>/
```

**GitLab Pages:**
```
https://<namespace>.gitlab.io/<project>/
```

**Notes:**
- Both use similar URL patterns
- Both support custom domains
- Both provide automatic HTTPS

### 7. Permissions

**GitHub Actions:**
```yaml
permissions:
  contents: read
  pages: write
  id-token: write
```

**GitLab CI/CD:**
- No explicit permissions needed
- Job runs with project-level permissions automatically

### 8. Environment Configuration

**GitHub Actions:**
```yaml
environment:
  name: github-pages
  url: ${{ steps.deployment.outputs.page_url }}
```

**GitLab CI/CD:**
- Environment is implicit (GitLab Pages)
- URL is auto-generated and shown in Settings > Pages

## Feature Comparison

| Feature | GitHub Pages | GitLab Pages |
|---------|--------------|--------------|
| **Automatic deployment** | ✅ On push to main with docs changes | ✅ On push to main with docs changes |
| **Manual trigger** | ✅ `workflow_dispatch` | ✅ Pipeline UI or API |
| **Build tool** | ✅ Zensical via uv | ✅ Zensical via uv |
| **Python version** | ✅ 3.14 | ✅ 3.14 |
| **HTTPS** | ✅ Automatic | ✅ Automatic |
| **Custom domain** | ✅ Via repository settings | ✅ Via project settings |
| **Deploy preview** | ⚠️ Via third-party | ✅ Native (review apps) |
| **Access control** | ⚠️ Public only* | ✅ Public or Private |
| **Build time limit** | ⚠️ 6 hours | ✅ Configurable |
| **Artifact retention** | ⚠️ Not configurable | ✅ Configurable (1 week default) |

\* GitHub Pages can be private with GitHub Pro/Enterprise

## Setup Instructions

### GitHub Pages

1. **Enable GitHub Pages:**
   - Go to **Settings > Pages**
   - Source: **GitHub Actions**
   - Branch: Leave blank (handled by workflow)

2. **Push workflow file:**
   ```bash
   git add .github/workflows/docs.yml
   git commit -m "Add documentation deployment"
   git push
   ```

3. **Access site:**
   - URL shown in **Settings > Pages**
   - Also in workflow run output

### GitLab Pages

1. **Enable GitLab Pages:**
   - Go to **Settings > Pages**
   - Usually enabled by default
   - Verify "Pages" section exists

2. **Push configuration:**
   ```bash
   git add .gitlab-ci.yml
   git commit -m "Add GitLab Pages deployment"
   git push
   ```

3. **Access site:**
   - After first `pages` job completes
   - URL shown in **Settings > Pages**
   - Format: `https://<namespace>.gitlab.io/<project>/`

## Custom Domain Setup

### GitHub Pages

1. **Settings > Pages > Custom domain**
2. Enter domain: `docs.example.com`
3. Add DNS records:
   ```
   CNAME: docs -> <username>.github.io
   ```
4. Verify domain and enable HTTPS

### GitLab Pages

1. **Settings > Pages > New Domain**
2. Enter domain: `docs.example.com`
3. Add DNS records:
   ```
   A: @ -> 35.185.44.232
   CNAME: docs -> <namespace>.gitlab.io
   ```
4. Add SSL certificate or use Let's Encrypt

## Troubleshooting

### GitHub Pages

**Issue: Site not updating**
- Check workflow run status in **Actions** tab
- Verify `docs/**` files were modified in commit
- Check for build errors in workflow logs

**Issue: 404 on site**
- Ensure `docs/site/index.html` exists after build
- Check artifact upload path matches build output
- Verify Pages is enabled in Settings

**Issue: Build fails**
- Check Python/uv installation logs
- Verify `uv.lock` is committed
- Test locally: `cd docs && uv run zensical build`

### GitLab Pages

**Issue: Site not updating**
- Check pipeline status in **CI/CD > Pipelines**
- Verify `pages` job completed successfully
- Check `public/` directory in job artifacts

**Issue: 404 on site**
- Ensure `public/index.html` exists in artifacts
- Verify `mv site ../public` executed correctly
- Check Pages is enabled: **Settings > Pages**

**Issue: Build fails**
- Check `pages` job logs for errors
- Verify Python image can pull successfully
- Test locally: `cd docs && uv run zensical build --clean`

## Performance Comparison

| Metric | GitHub Pages | GitLab Pages |
|--------|--------------|--------------|
| **Cold build time** | ~2-3 minutes | ~2-3 minutes |
| **Warm build time** | ~1-2 minutes (with cache) | ~1-2 minutes (with cache) |
| **Deployment time** | ~30 seconds | Instant (artifact-based) |
| **Total time** | ~2-3 minutes | ~2-3 minutes |
| **Image pull time** | N/A (VM-based) | ~10-20 seconds (Docker) |

**Note:** Performance is roughly equivalent for this use case.

## Migration Between Platforms

### GitHub → GitLab

1. Copy build logic from `.github/workflows/docs.yml`
2. Create `pages:` job in `.gitlab-ci.yml`
3. Change artifact path from `docs/site` to `public/`
4. Update trigger rules from `on:` to `rules:`
5. Test pipeline on GitLab

### GitLab → GitHub

1. Copy build logic from `pages:` job
2. Create `.github/workflows/docs.yml`
3. Add GitHub Pages-specific actions
4. Change artifact path from `public/` to `docs/site`
5. Enable GitHub Pages in repository settings

## Best Practices

### Both Platforms

1. **Version pinning**: Use specific Python version (`3.14` not `3.x`)
2. **Lock files**: Commit `uv.lock` for reproducible builds
3. **Clean builds**: Use `--clean` flag to ensure fresh output
4. **Manual triggers**: Enable for testing without code changes
5. **Path filters**: Only trigger on docs changes to save CI time

### Platform-Specific

**GitHub Pages:**
- Use `permissions:` for least-privilege access
- Set `environment:` for deployment tracking
- Consider branch protection rules

**GitLab Pages:**
- Use `expire_in:` for artifact cleanup
- Enable Pages for private projects if needed
- Configure review apps for preview deployments

## Cost Comparison

| Aspect | GitHub Pages | GitLab Pages |
|--------|--------------|--------------|
| **Public repos** | Free | Free |
| **Private repos** | Free* | Free |
| **Build minutes** | 2,000/month free | 400 CI/CD minutes/month free |
| **Storage** | 1 GB | 10 GB |
| **Bandwidth** | 100 GB/month | Unlimited** |

\* GitHub Pages for private repos requires GitHub Pro, Team, or Enterprise
\** GitLab Pages bandwidth is subject to fair use policy

## Conclusion

Both GitHub Pages and GitLab Pages provide excellent documentation hosting with similar capabilities. The choice depends on where your repository is hosted and your specific needs:

**Choose GitHub Pages if:**
- Repository is on GitHub
- You prefer GitHub's ecosystem
- You need GitHub-specific integrations

**Choose GitLab Pages if:**
- Repository is on GitLab
- You need private documentation hosting (free tier)
- You want review apps for preview deployments
- You prefer GitLab's CI/CD workflow

**Use Both if:**
- Mirror repository exists on both platforms
- Want redundancy/backup deployment
- Testing migration between platforms

## Additional Resources

- [GitHub Pages Documentation](https://docs.github.com/pages)
- [GitLab Pages Documentation](https://docs.gitlab.com/ee/user/project/pages/)
- [Zensical Documentation](https://zensical.dev/)
- [uv Package Manager](https://github.com/astral-sh/uv)

---

**Last Updated**: 2026-01-12
**Status**: Both deployments active and functionally equivalent
