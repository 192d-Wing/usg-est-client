#!/bin/bash
# Simulate the GitLab CI unwrap-tracking job locally

UNWRAP_BASELINE=339
UNWRAP_GOAL=68

echo "## unwrap() Tracking Dashboard" > report.md
echo "" >> report.md
echo "**Sprint Goal:** Reduce from ${UNWRAP_BASELINE} to ${UNWRAP_GOAL} unwrap() calls (80% reduction)" >> report.md
echo "**Timeline:** Q2 2026 (8 weeks)" >> report.md
echo "**Test Run:** Local execution" >> report.md
echo "" >> report.md

# Total count
TOTAL=$(grep -rn "unwrap()" src/ --include="*.rs" 2>/dev/null | wc -l | tr -d ' ')
REDUCTION=$((UNWRAP_BASELINE - TOTAL))
TARGET_REDUCTION=$((UNWRAP_BASELINE - UNWRAP_GOAL))

if [ "$TARGET_REDUCTION" -gt 0 ]; then
  PROGRESS=$((REDUCTION * 100 / TARGET_REDUCTION))
else
  PROGRESS=0
fi

echo "### Overall Progress" >> report.md
echo "" >> report.md
echo "| Metric | Value |" >> report.md
echo "|--------|-------|" >> report.md
echo "| **Current Count** | $TOTAL |" >> report.md
echo "| **Baseline (2026-01-14)** | ${UNWRAP_BASELINE} |" >> report.md
echo "| **Sprint Goal** | ${UNWRAP_GOAL} |" >> report.md
echo "| **Reduction So Far** | $REDUCTION |" >> report.md
echo "| **Progress** | $PROGRESS% |" >> report.md
echo "" >> report.md

# Check if count increased
if [ "$TOTAL" -gt "${UNWRAP_BASELINE}" ]; then
  INCREASE=$((TOTAL - UNWRAP_BASELINE))
  echo "❌ **ERROR: unwrap() count increased by $INCREASE!**" >> report.md
  echo "ERROR: unwrap() count increased from ${UNWRAP_BASELINE} to $TOTAL (+$INCREASE)"
  cat report.md
  exit 1
elif [ "$TOTAL" -eq "${UNWRAP_BASELINE}" ]; then
  echo "⚠️ No change in unwrap() count" >> report.md
else
  echo "✅ **Great progress! Reduced by $REDUCTION**" >> report.md
fi
echo "" >> report.md

# Top 15 files by unwrap() count
echo "### Top Files by unwrap() Count" >> report.md
echo "" >> report.md
echo "| File | Count | Sprint Phase |" >> report.md
echo "|------|-------|--------------|" >> report.md

grep -rc "unwrap()" src/ --include="*.rs" 2>/dev/null \
  | grep -v ":0$" \
  | sort -t: -k2 -rn \
  | head -15 \
  | while IFS=: read -r file count; do
      # Determine phase based on file path
      phase=""
      case "$file" in
        *hsm/pkcs11.rs*) phase="Phase 2 (HSM)" ;;
        *hsm/*) phase="Phase 2 (HSM)" ;;
        *windows/cng.rs*) phase="Phase 3 (Windows)" ;;
        *windows/certstore.rs*) phase="Phase 3 (Windows)" ;;
        *windows/service.rs*) phase="Phase 3 (Windows)" ;;
        *windows/tpm.rs*) phase="Phase 3 (Windows)" ;;
        *windows/*) phase="Phase 3 (Windows)" ;;
        *auto_enroll/*) phase="Phase 4 (Auto-Enroll)" ;;
        *operations/*) phase="Phase 4 (Auto-Enroll)" ;;
        *validation.rs*) phase="Phase 5 (Core)" ;;
        *logging/*) phase="Phase 5 (Core)" ;;
        *config.rs*) phase="Phase 5 (Core)" ;;
        *tls.rs*) phase="Phase 5 (Core)" ;;
        *) phase="Phase 5 (Core)" ;;
      esac
      echo "| \`${file#src/}\` | $count | $phase |" >> report.md
    done
echo "" >> report.md

# Module breakdown
echo "### Module Breakdown" >> report.md
echo "" >> report.md
echo "| Module | Count | Target | Phase |" >> report.md
echo "|--------|-------|--------|-------|" >> report.md

HSM_COUNT=$(grep -rn "unwrap()" src/hsm/ --include="*.rs" 2>/dev/null | wc -l | tr -d ' ')
echo "| \`src/hsm/\` | $HSM_COUNT | 5 | Phase 2 (Weeks 3-4) |" >> report.md

WINDOWS_COUNT=$(grep -rn "unwrap()" src/windows/ --include="*.rs" 2>/dev/null | wc -l | tr -d ' ')
echo "| \`src/windows/\` | $WINDOWS_COUNT | 8 | Phase 3 (Weeks 5-6) |" >> report.md

AUTOENROLL_COUNT=$(grep -rn "unwrap()" src/auto_enroll/ --include="*.rs" 2>/dev/null | wc -l | tr -d ' ')
OPERATIONS_COUNT=$(grep -rn "unwrap()" src/operations/ --include="*.rs" 2>/dev/null | wc -l | tr -d ' ')
PIPELINE_TOTAL=$((AUTOENROLL_COUNT + OPERATIONS_COUNT))
echo "| \`src/auto_enroll/\` + \`src/operations/\` | $PIPELINE_TOTAL | 5 | Phase 4 (Week 7) |" >> report.md

VALIDATION_COUNT=$(grep -n "unwrap()" src/validation.rs 2>/dev/null | wc -l | tr -d ' ')
LOGGING_COUNT=$(grep -rn "unwrap()" src/logging/ --include="*.rs" 2>/dev/null | wc -l | tr -d ' ')
CONFIG_COUNT=$(grep -n "unwrap()" src/config.rs 2>/dev/null | wc -l | tr -d ' ')
CORE_TOTAL=$((VALIDATION_COUNT + LOGGING_COUNT + CONFIG_COUNT))
echo "| Core (\`validation\`, \`logging\`, \`config\`) | $CORE_TOTAL | 10 | Phase 5 (Week 8) |" >> report.md

echo "" >> report.md

# Documentation links
echo "### Resources" >> report.md
echo "" >> report.md
echo "- 📘 [Error Handling Patterns Guide](docs/dev/ERROR-HANDLING-PATTERNS.md)" >> report.md
echo "- 📋 [Refactoring Sprint Plan](docs/ato/REFACTORING-SPRINT-PLAN.md)" >> report.md
echo "- 📊 [Executive Summary](docs/ato/EXECUTIVE-SUMMARY.md)" >> report.md
echo "" >> report.md

# Display report
cat report.md
