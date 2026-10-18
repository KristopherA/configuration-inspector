# Deployment and acceptance

## Release state

Configuration Inspector 1.0.0 is delivered as a universal Apple Silicon/Intel app and optional CLI with a macOS 13 deployment target. It is ad-hoc signed for local testing. It has not been signed with your organization's Developer ID identity or notarized.

Use [SIGNING.md](SIGNING.md) to create a signed, notarized installer. your organization's Developer ID Installer certificate signs the package; a separate Developer ID Application identity signs the app and optional CLI. Do not reuse Connection Workbench's bundle or package identifier for this app.

The primary installer should install only the GUI to `/Applications/Configuration Inspector.app`. Keep source, raw profile exports, test captures, and credentials out of installer payloads. Package the CLI separately if needed. This tool has no installer scripts, privileged helper, system extension, login item, daemon, enrollment requirement, or automatic update service.

## Operational setup

1. Have the application owner define a requirements JSON from vendor documentation: expected bundle ID, approved Team ID, relevant preference keys, exact launchd labels and scopes, required extension IDs, and required privacy permissions. Prefer empty/unspecified fields over guesses.
2. Test the requirements against both an affected and a verified working workstation. Record whether optional helpers are demand-triggered and which permissions require affected-user verification.
3. Store the reviewed requirements centrally with a revision record. Use the same requirements for paired inspections. Rules are declarative data, not executable tests.
4. Run collection as the affected standard user. Root collection cannot stand in for that user's preferences or GUI launchd domain. Administrative profile exports can be supplied separately through the approved process.
5. Decide where support bundles may be stored, who may access them, how long to retain them, and which ticket/transfer channel is approved. The app omits raw profile bodies and sensitive-looking values but does not promise complete redaction or encrypt bundles.

## Acceptance checklist

Complete these checks on each supported OS release and CPU architecture, using the actual MDM/download channel:

- Install the Developer ID-signed and notarized package. Verify package and installed app signatures, then launch as a standard user. Confirm the expected `/Applications` destination.
- Choose a known installed app and a missing expected path. Verify the distinction between existing files, correct bundle identity, and deployment status.
- Check a valid signature, an intentionally invalid test signature, an expected Team ID match, a mismatch, and unavailable metadata. Do not test destructive changes against production apps.
- Collect a benign, explicitly selected managed boolean preference and compare it with an unmanaged or absent value in the affected account. Validate against the affected app's own documented policy behavior.
- Verify profile collection under the organization's actual user/device enrollment modes. Confirm inaccessible data appears as Unknown. Attach an approved profile export and verify it is labeled as supplied, not proof of installation.
- Exercise direct app preferences, MCX Forced/Set-Once definitions, exact PPPC bundle-ID rules, system-extension approvals, and relevant service-management rules that apply to the actual supported products. Unsupported formats should remain unassessed rather than appearing applied.
- Confirm conflicts are surfaced without choosing a winning policy. Verify unrelated profile data, credential-like values, unrelated processes, and launchd arguments/environments are absent from the resulting bundle.
- Compare required extension state against the vendor's own diagnostics. Test a waiting-for-approval state and an absent/optional bundled extension.
- Verify system and current-user launchd scopes for both continuously running and demand-triggered components. Check restricted-access handling. Match executable observations against the selected install path and known external helpers.
- Have the affected user perform privacy checks. Confirm manual entries remain Reported; selecting an entry must not grant or request permissions.
- Save/import A and B across workstations. Reorder equivalent requirements and confirm it does not create a requirements difference. Change a real requirement and confirm it is flagged.
- Export a bundle, verify manifest hashes, and independently review privacy-sensitive content. Confirm a fresh launch has no automatically retained case history.
- Check keyboard navigation, VoiceOver, appearance, long application paths, and the minimum supported window size with help-desk staff.

The included fixtures do not replace these enterprise acceptance checks. See [VALIDATION.md](VALIDATION.md) for the specific local checks completed during development.

## Escalation ticket

- Application and expected bundle ID:
- User-visible symptom and reproduction time/time zone:
- Application version/build and macOS version:
- A condition and actual function tested:
- B condition and actual function tested:
- Requirements revision used:
- Profile collection scope and supplied export provenance:
- Relevant evidence IDs and observed differences:
- User-reported permission checks:
- Next test / application owner / MDM administrator needed:
- Bundle reviewed and attached via approved channel:

Keep credentials and unrelated personal information out of labels and selected preference keys.

## Recovery

There are no remediation actions to undo. If the tool itself fails, stop using that release, preserve the error and affected inspection files where permitted, and return to your organization's existing support procedure. Distribute a corrected version through the normal release process. Remove the application or roll back using your organization's managed-software procedure; saved support files are separate and remain subject to retention policy.
