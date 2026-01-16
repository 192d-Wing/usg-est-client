#!/bin/bash
# Verification script to check GitLab CI/CD template availability
# This helps diagnose "template not found" errors

set -e

echo "=========================================="
echo "GitLab CI/CD Template Verification"
echo "=========================================="
echo ""

# Check if we're in a git repository
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    echo "❌ Error: Not in a git repository"
    exit 1
fi

# Check if GitLab remote exists
if ! git remote -v | grep -q gitlab; then
    echo "⚠️  Warning: No GitLab remote found"
    echo "   This script is most useful when connected to a GitLab instance"
    echo ""
fi

# Check if gitlab-ci.yml exists
if [ ! -f ".gitlab-ci.yml" ]; then
    echo "❌ Error: .gitlab-ci.yml not found"
    exit 1
fi

echo "✅ Found .gitlab-ci.yml"
echo ""

# Parse includes from .gitlab-ci.yml
echo "Checking template includes in .gitlab-ci.yml:"
echo "----------------------------------------------"

if grep -q "template: Security/SAST.gitlab-ci.yml" .gitlab-ci.yml; then
    echo "  📋 Security/SAST.gitlab-ci.yml"
    echo "     Status: Configured"
    echo "     Requires: GitLab Ultimate or GitLab.com (Free tier includes SAST)"
    echo ""
    echo "     If you see errors about this template:"
    echo "     1. Check your GitLab tier (Ultimate includes all security templates)"
    echo "     2. GitLab.com Free tier includes SAST for public projects"
    echo "     3. Self-managed GitLab may require Ultimate license"
    echo "     4. You can comment out the include if not available"
    echo ""
fi

echo "----------------------------------------------"
echo ""

# Check if we can validate the pipeline
echo "Pipeline Validation:"
echo "--------------------"

# Try to validate using GitLab CI lint (requires API access)
if command -v gitlab-ci-lint &> /dev/null; then
    echo "  Running gitlab-ci-lint..."
    gitlab-ci-lint .gitlab-ci.yml
elif command -v glab &> /dev/null; then
    echo "  Running glab ci lint..."
    glab ci lint
else
    echo "  ℹ️  Install 'glab' CLI to validate pipeline: https://gitlab.com/gitlab-org/cli"
    echo "     Or use GitLab Web UI: Project → CI/CD → Pipelines → CI Lint"
fi

echo ""
echo "=========================================="
echo "Manual Verification Steps:"
echo "=========================================="
echo ""
echo "1. Push to GitLab and check pipeline:"
echo "   git push origin main"
echo ""
echo "2. View pipeline in GitLab Web UI:"
echo "   Project → CI/CD → Pipelines"
echo ""
echo "3. Check for SAST jobs in the 'test' stage"
echo "   - If present: Template is available ✅"
echo "   - If missing: Template not available, comment out include"
echo ""
echo "4. To disable SAST template if not available:"
echo "   Edit .gitlab-ci.yml and comment out lines 8-9:"
echo "   # include:"
echo "   #   - template: Security/SAST.gitlab-ci.yml"
echo ""
