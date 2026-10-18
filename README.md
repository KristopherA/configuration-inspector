# Configuration Inspector

[Download builds](https://github.com/KristopherA/configuration-inspector/releases) · [Signing and notarization](SIGNING.md) · [Deployment](DEPLOYMENT.md)

A portable native macOS workbench for asking **“Why isn't this managed application ready?”** Inspect an affected app, collect the same requirements on a working Mac, and compare the evidence.

## Run

Open **Configuration Inspector.app**. No Python, Homebrew, agent, or administrator access is needed to run it. The release contains Apple Silicon and Intel executable slices and targets macOS 13 or later. The optional `configuration-inspector` command supports scripted collection.

This is an ad-hoc-signed local build, not a Developer ID-signed or notarized release. Follow `SIGNING.md` before organization-wide distribution. Older macOS releases and physical Intel hardware require acceptance testing; see `VALIDATION.md` for what was actually exercised.

## Help-desk procedure

1. **Choose the affected app.** Choose its `.app` bundle or enter an absolute expected install path. The tool never launches the selected app. If the app is missing, supply its expected bundle ID so the missing installation can still be investigated.
2. **Set inspection requirements.** The selected app normally supplies its bundle ID. Expand **Inspection requirements** to specify the approved publisher Team ID, relevant preference keys, exact launchd service labels and scopes, required extension IDs, and required privacy permissions. Use vendor documentation or an administrator-maintained requirements file; do not guess that every app needs every permission or a continuously running service.
3. **Save shared requirements.** Save the requirements JSON and use the same file on the comparison Mac. Requirements contain declarative identifiers only; no scripts or executable checks are accepted.
4. **Optionally attach profile definitions.** Attach an approved unsigned XML or binary property-list export. It can be a `.mobileconfig` definition or a `profiles show` XML export. The app retains matching normalized rules, not the original file. Supplied definitions are always labeled as unverified configuration intent, even if they came from an MDM console.
5. **Record manual permission checks.** Ask the affected user to inspect the app's entries in System Settings → Privacy & Security. For each required permission, select **Not checked**, **Reported enabled**, or **Reported disabled**. These are reports, not measurements of the other app's grant. Do not change permissions just to make a check look successful.
6. **Inspect A.** Use a descriptive label such as “Affected Mac / user reproduced screen-sharing failure.” Wait until the progress indicator finishes. Review **Readiness** and use **View supporting evidence** on each relevant finding.
7. **Inspect or import B.** On a working Mac, load the same requirements, use an appropriate label, reproduce the actual application function, then save its inspection JSON. Import that JSON into slot B on the investigator's Mac. You can also collect B locally after changing one controlled condition.
8. **Compare and escalate.** Review the **Compare** tab and side-by-side **Evidence**. Export a support bundle after reviewing its contents. Include the original symptom, reproduction time, affected user context, app version, and the next team or test needed.

Captures remain in memory until saved or exported. **Start over** discards the current in-memory inspections and inputs. **Retake** clears that slot. Closing the app loses unsaved work. There is no background history or automatic upload.

## How to read results

| Label | Meaning |
|---|---|
| **Observed** | A bounded collection produced the stated observation. It is not an overall readiness or security pass. |
| **Configured** | A matching profile definition was found. This does not establish that the setting applied or identify a winning profile. |
| **Reported** | A technician recorded the affected user's manual permission observation. |
| **Needs review** | An identity mismatch, failed verification, differing rule definitions, or relevant extension state needs investigation. |
| **Unknown** | Evidence was unavailable, not requested, omitted, ambiguous, or insufficient to determine the state. |

There is deliberately no readiness score. A valid signature does not prove the app is notarized or benign. A running process does not prove functionality. A service can be registered without running because it is demand-triggered. A bundled extension might be optional. Profile conflicts are flagged without assuming a universal precedence rule.

## Collection details

- **Application identity:** bounded `Info.plist` fields, executable path, version, build, bundle ID, signing identifier, and Team ID. Bundled system extensions, login-item bundles, and `SMPrivilegedExecutables` helper identifiers are discovered where visible.
- **Code signature:** local `codesign --verify --deep --strict` integrity verification plus signing metadata. No signing, installation, or Gatekeeper bypass is performed.
- **Selected preferences:** `CFPreferencesCopyAppValue` and `CFPreferencesAppValueIsForced` for explicitly requested keys in the collector account. These are observations of the preference search path, not proof that the app honors those values. Values that appear sensitive and structured/binary values are omitted. Current-account preference observation is marked unknown during root collection.
- **Visible profiles:** bounded `profiles show -type configuration -output stdout-xml`. Standard-account results are not a complete inventory of device policy. Only matching rules are retained.
- **Profile normalization:** direct app preference payloads; `com.apple.ManagedClient.preferences` Forced and Set-Once values; exact matching PPPC bundle identifiers; matching system-extension approvals; and a subset of service-management rules. PPPC code requirements are retained as configuration intent, not evaluated against permission grants. Forced and Set-Once modes are kept distinct.
- **System extensions:** `systemextensionsctl list`, filtered to exact discovered or required extension IDs. Other extension inventory is discarded.
- **Launchd:** bounded discovery in visible standard LaunchAgents/LaunchDaemons locations and app-contained definitions, plus explicitly required labels. `launchctl print` retains selected top-level state fields; command arguments, environment blocks, and other unneeded fields are discarded.
- **Processes:** `ps` executable paths and PIDs, filtered to the selected bundle or explicitly associated launchd executable paths. Command-line arguments and unrelated process listings are not retained. Missing matches do not prove no component is running.
- **Privacy permissions:** no TCC database access or permission requests. Manual reports and relevant policy definitions remain separate from actual grant state.

The app does not inspect every DDM declaration, MDM server assignment, TCC rule, privileged-helper registration mechanism, browser policy engine, or vendor configuration store. It does not query package receipts or establish that a file was installed by MDM. Prefix/path-based policy matches and PPPC path identifiers are not currently resolved. A lack of matching rules means only that no supported matching rule was retained from the visible or supplied data.

Collection is sequential and can span configuration changes. Each command has a timeout and a 1 MB retained-output cap. Up to 30 services are assessed, each with a four-second timeout; signature and profile collection can each take 15 seconds. An inspection can take a few minutes in degraded conditions. There is no mid-inspection cancellation control in this version. Quitting stops the app, and spawned commands also have bounded lifetimes.

## Profile visibility and exports

Run the GUI as the affected standard user. It does not request elevation or Full Disk Access. Administrative profile exports can supplement limited visibility through your organization's existing support process.

An administrator can use the read-only profiles export command in an approved session, for example:

```sh
sudo profiles show -type configuration -output /path/to/approved-device-profiles.plist
```

Choose a protected destination and handle that raw export according to your organization’s policy: it may contain unrelated or sensitive configuration. Importing it does not preserve the raw export inside the support bundle, but the original file remains wherever the administrator created it. This app does not run `sudo`, collect private keys, or modify profiles. CMS-signed `.mobileconfig` files must be exported as an unsigned plist definition through an approved administration workflow before inspection; the app does not install or trust the profile.

## Requirements file

Start from `Examples/requirements-template.json`, replacing its example bundle ID. Every field shown is required by the current JSON schema, but optional lists may be empty and the expected Team ID may be an empty string.

```json
{
  "schemaVersion": 1,
  "bundleID": "com.vendor.application",
  "expectedTeamID": "",
  "preferenceKeys": ["Enabled", "Mode"],
  "services": [
    { "label": "com.vendor.agent", "domain": "gui" },
    { "label": "com.vendor.daemon", "domain": "system" }
  ],
  "extensionIDs": [],
  "permissions": ["Screen Recording", "Accessibility"]
}
```

Example identifiers are placeholders, not vendor recommendations. `gui` means the collector UID's GUI domain; it does not impersonate another user. Requirements permit at most 30 preference keys, 20 explicit services, and 30 extension IDs. No arbitrary command field exists. Preference keys containing credential-related terms are suppressed even if explicitly requested. Other selected values may still be sensitive, so scope the keys carefully.

## Scripted collection

```sh
./configuration-inspector inspect \
  --app /Applications/Example.app \
  --requirements ./requirements.json \
  --label 'Affected Mac / reproduced failure' \
  --output ./inspection-A.json
```

Optionally add `--profiles ./approved-profile-export.plist`. The CLI does not record manual permission observations; they remain unverified. It refuses to overwrite an existing output. Exit zero means an inspection was saved, even if observations are unknown or checks need review; a nonzero exit indicates invalid input, collection setup failure, or save failure. Import the JSON into the GUI for comparison and escalation export.

## Support-bundle handling

The ZIP contains `inspection-A.json`, optionally `inspection-B.json`, `requirements.json`, `report.md`, and `SHA256SUMS.txt`. Saved inspections can be imported without executing probes or commands. In a single-slot export, the existing inspection is named A inside the bundle, regardless of its GUI slot. If requirements differ between captures, each JSON retains its own requirements; `requirements.json` reflects A and the comparison flags the difference.

Saved inspections and ZIPs use owner-only file permissions. This is not encryption or complete redaction. Paths, profile names/identifiers, preference values, publisher identifiers, code requirements, UID, operator labels, and relevant service state may disclose internal details. Review before sharing and use approved storage, retention, and transfer channels. Raw profile bodies, unrelated process inventories, and launchd environments are not included. SHA-256 hashes detect subsequent file changes, not authenticity or forensic chain of custody.

Imports are untrusted observations; the collector does not independently verify their truth. Inspection JSON is bounded to 8 MB, profile input to 1 MB, and requirements JSON to 100 KB. Schema, identifier, duplicate-ID, and complexity checks are applied. Imported files never execute collection commands.

## Build and verify

Development requires Apple's Swift command-line toolchain and macOS SDK. Runtime users need neither. No third-party packages are used.

```sh
./build.sh ./dist
./test.sh
```

The tests cover requirements validation, profile normalization and scope, PPPC decisions, sensitive-value omission, Forced versus Set-Once semantics, launchd environment filtering, signature timeout handling, comparisons, manual-permission labeling, safe imports, output overwrite protection, file permissions, process timeout, and export hashes. Test profiles are synthetic definitions and are never installed.

Source is divided into `Models.swift`, `Runner.swift`, `Profiles.swift`, `Collector.swift`, `Analysis.swift`, `Files.swift`, the native `App.swift`, and the optional `CLI.swift`. The app bundle contains one executable and no embedded agent or service.
