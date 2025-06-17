#!/bin/bash

# This script runs Go tests one package at a time to detect which one might be hanging
# It uses Go's built-in timeout feature instead of the Unix timeout command

echo "Running debug tests package by package..."

# Create a list of packages to test
PKGS=$(go list ./... | grep -v /mobile)

# Track success/failure
SUCCESS_COUNT=0
FAILURE_COUNT=0

# Run tests for each package individually with a timeout
for pkg in $PKGS; do
  echo "===== Testing package: $pkg ====="
  
  # Run the test with a short timeout (10s should be enough for most test packages)
  go test -v -count=1 -timeout=15s "$pkg"
  
  RESULT=$?
  if [ $RESULT -eq 0 ]; then
    echo "✅ PASSED: $pkg"
    ((SUCCESS_COUNT++))
  else
    echo "❌ FAILED: $pkg with exit code $RESULT"
    if [ $RESULT -eq 2 ]; then
      echo "Test timed out, which indicates this package might be causing the hang"
    fi
    ((FAILURE_COUNT++))
  fi
  
  echo ""
done

echo "========== TEST SUMMARY =========="
echo "Packages tested: $(echo "$PKGS" | wc -w)"
echo "Succeeded: $SUCCESS_COUNT"
echo "Failed: $FAILURE_COUNT"

if [ $FAILURE_COUNT -gt 0 ]; then
  echo "Some packages had test failures"
  exit 1
else
  echo "All packages tested successfully"
  exit 0
fi 