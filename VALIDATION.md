# Validation record — 17 October 2026

## Completed checks

- Built arm64 and x86_64 slices of the native SwiftUI app and command-line collector, with a macOS 13 deployment target. No external runtime dependencies or third-party Swift packages are used.
- Passed **53 automated checks** covering requirements and path validation; duplicate/scope limits; direct preferences, MCX modes, PPPC policy, extension approval, and installed-profile wrappers; sensitive-value omission; exclusion of unrelated rules and launchd environments; scope labeling; matching and differing inspections; order-independent requirements; process PID normalization and absence; permission reports; signature timeout handling; JSON round trips; overwrite protection; owner-only file permissions; import schema checks; ZIP payload hashes; and process timeouts.
- Ran the command-line collector on the real app using Apple Silicon and the Intel executable through Rosetta. Both saved inspection JSON with application identity, requested preferences, and bounded collection evidence. Restricted command results were preserved as unavailable/Unknown rather than converted to successful observations.
- Ran a supplied-profile integration using two synthetic definitions for the selected bundle. It retained their differing Mode values, omitted a synthetic AccessToken sentinel, and labeled the definitions supplied/unverified. No profile was installed or modified.
- Exercised the native GUI: enter an application and expected bundle ID, label A and B, collect both, review readiness findings, compare snapshots, view evidence side by side, export a support ZIP, and import a saved inspection.
- Independently read the GUI-generated ZIP and verified all manifest payload hashes. Profile coverage remained explicit and raw profile bodies were absent.
- Exercised a synthetic manual permission report through the GUI. It appeared as an operator report and comparison difference, without granting or testing any actual permission.
- The walkthrough found that preference-key order alone could cause a requirements difference. Normalized comparison fixed it; regression tests and the corrected GUI walkthrough confirmed logically identical requirements no longer appear different.
- Prepared an unsigned installer assembly check using the app's own bundle identifier, macOS 13 minimum, both supported architectures, and `/Applications` destination. This test package is an intermediate and is not included in the release download.

## Runtime and deployment limits

The native GUI was exercised on the current Apple Silicon workstation running macOS 27.0.1. The Intel CLI was exercised through Rosetta, not on physical Intel hardware. Runtime testing on macOS 13 and other older supported releases remains part of your organization's acceptance matrix.

The installed Apple toolchain emitted warnings that its Swift compatibility-pack archive lacks an x86_64 slice. Both Intel binaries linked, and the Intel collector completed a real inspection under Rosetta. Validate physical Intel and the oldest supported OS before rollout.

The app and CLI are ad-hoc signed, not Developer ID signed or notarized. No organizational signing certificate or private key was accessed, and nothing was uploaded to Apple. The signing procedure provides the production release path. Final archive extraction is checked for valid local ad-hoc signatures; this is not Gatekeeper approval for a downloaded organization release.

During self-inspection inside the cloud-backed workspace, strict code-signature checks surfaced Finder/file-provider metadata on the app as a verification failure. The inspector displayed Needs review with the actual command error. The distribution ZIP excludes this metadata, and signature verification of the clean extracted release is the relevant packaging check. This result was not treated as an integrity pass or a notarization result.

The local account did not provide a controlled enterprise fleet with real conflicting device profiles, active vendor system extensions, approved launchd helpers, or managed preference policies. Parser fixtures and supplied definitions cover these formats, but end-to-end behavior in your organization's real MDM/enrollment and vendor environments requires acceptance testing. No real privacy grant was changed or verified, and no preference or device profile was modified for testing.

## Deliberate boundaries

- Current-user visibility is incomplete; absence of matching profile evidence does not establish absence of device policy.
- Only explicitly requested preference keys and supported matching profile payloads are analyzed. Vendor-specific policy stores and all DDM declarations are not covered.
- Supplied configuration remains unverified intent. The tool does not infer universal policy precedence or a winning profile.
- Privacy settings for another app remain Unknown unless an operator supplies a clearly labeled report; the tool does not read TCC databases.
- Process and service states are snapshots. A match, signature verification, or configured rule is not a readiness or security score.
- Exports omit raw profile bodies, unrelated process data, launchd arguments/environments, and sensitive-looking selected values, but are not fully redacted or encrypted.
- Root collection does not represent the affected user's preferences. The app does not elevate or impersonate another user.
- No remediation, startup service, telemetry, enrollment, installer scripts, or automatic update system is included.
