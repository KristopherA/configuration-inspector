#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$ROOT/.build/cache"
CORE=("$ROOT/Sources/Models.swift" "$ROOT/Sources/Runner.swift" "$ROOT/Sources/Profiles.swift" "$ROOT/Sources/Collector.swift" "$ROOT/Sources/Analysis.swift" "$ROOT/Sources/Files.swift")
xcrun swiftc -swift-version 5 -module-cache-path "$ROOT/.build/cache" -parse-as-library "${CORE[@]}" "$ROOT/Tests/Tests.swift" -o "$ROOT/.build/tests"
"$ROOT/.build/tests"
