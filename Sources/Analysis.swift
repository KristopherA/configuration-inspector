import Foundation

enum Analysis {
    static func checks(_ c: Inspection) -> [CheckResult] {
        var results: [CheckResult] = []
        func add(_ id: String, _ state: ResultState, _ title: String, _ detail: String, _ next: String, _ evidence: [String]) {
            results.append(CheckResult(id:id,state:state,title:title,detail:detail,next:next,evidenceIDs:evidence))
        }
        if !c.app.exists {
            add("installation",.review,"Application path is missing",c.app.path,"Check the expected install location and deployment result. A missing path does not establish that no other copy exists.",["identity"])
        } else {
            add("installation",.observed,"Application path exists","\(c.app.path)\nVersion \(c.app.version ?? "unknown") · build \(c.app.build ?? "unknown")","Compare this version and location against the vendor's supported deployment.",["identity"])
        }
        if c.app.bundleID != c.requirements.bundleID {
            add("bundleID",c.app.bundleID == nil ? .unknown : .review,"Application identity needs verification","Expected: \(c.requirements.bundleID)\nObserved: \(c.app.bundleID ?? "Not observed")","Confirm you selected the intended application. Requirements and profile matches are based on the expected bundle ID.",["identity"])
        }
        if let e = c.item("signature") {
            let good = e.exitCode == 0 && !e.timedOut && !e.truncated
            add("signature",good ? .observed : .review,good ? "Code signature integrity check completed" : "Code signature check did not pass",good ? "The selected app passed codesign's strict recursive verification. This does not establish notarization, publisher approval, or absence of malware." : "Exit \(e.exitCode). Timeout: \(e.timedOut). Truncated: \(e.truncated). Inspect the signature evidence.","Confirm the signing authority against the vendor or your organization's release record.",["signature","signatureDetails"])
        } else { add("signature",.unknown,"Code signature was not assessed","The selected app was not available for verification.","Confirm the install path before inspecting publisher identity.",["identity"]) }
        if !c.requirements.expectedTeamID.isEmpty {
            let state: ResultState = c.app.teamID == nil ? .unknown : c.app.teamID == c.requirements.expectedTeamID ? .observed : .review
            add("team",state,"Publisher Team ID comparison","Expected: \(c.requirements.expectedTeamID)\nObserved: \(c.app.teamID ?? "Not observed")","A mismatch needs release-owner review. Matching metadata alone does not establish trust; inspect signature verification too.",["identity","signature"])
        }
        if let p = c.item("processes"), p.exitCode == 0, !p.timedOut, !p.truncated {
            let found = !p.output.trimmingCharacters(in:.whitespacesAndNewlines).isEmpty
            add("processes",found ? .observed : .unknown,found ? "Matching executable paths were observed" : "No matching process was observed",found ? "A bounded process snapshot found paths within the selected app or an explicitly associated launchd program." : "The application may be closed, run on demand, use a helper outside the discovered paths, or be hidden from the current account.","Reproduce the symptom, then collect again. Process presence does not establish service health.",["processes"])
        } else { add("processes",.unknown,"Process evidence is incomplete","The snapshot was unavailable, timed out, or exceeded the limit.","Inspect collection status and use an approved administration session if required.",["processes"]) }
        let extensionIDs = Array(Set(c.app.extensionIDs + c.requirements.extensionIDs)).sorted()
        if extensionIDs.isEmpty { add("extensions-none",.unknown,"No extension requirement was supplied or discovered","This inspection does not assume the app requires a system extension.","Use vendor documentation to add exact required extension IDs if applicable.",["identity","extensions"]) }
        for id in extensionIDs {
            let e = c.item("extensions")
            let line = e?.output.components(separatedBy:.newlines).first { $0.split(whereSeparator: { $0.isWhitespace }).contains(Substring(id)) }
            let active = line?.contains("[activated enabled]") == true
            let valid = e?.exitCode == 0 && e?.timedOut == false && e?.truncated == false
            let expected = c.requirements.extensionIDs.contains(id)
            add("extension:"+id,!valid ? .unknown : active ? .observed : (expected || line != nil ? .review : .unknown),"System extension · \(id)",!valid ? "Inventory unavailable or incomplete." : line ?? "Not listed in the visible system-extension inventory. Bundled does not necessarily mean required.","Compare the listed state with vendor requirements and relevant extension-approval policy. A profile rule does not prove activation.",["extensions","profileRules"])
        }
        let services = c.evidence.filter { $0.id.hasPrefix("service:") }
        if services.isEmpty { add("services-none",.unknown,"No associated launchd service was assessed","No exact service requirements or bounded matching launchd definitions were found.","Add known service labels with system or gui scope from the vendor's deployment procedure.",["services"]) }
        for e in services {
            let valid = e.exitCode == 0 && !e.timedOut && !e.truncated
            let running = valid && e.output.components(separatedBy:.newlines).contains("state = running")
            add(e.id,valid ? .observed : .unknown,"Launchd · " + e.id.dropFirst(8),valid ? e.output : "Service was not observable in this scope. It may be unregistered or access may be restricted.",running ? "Running is a snapshot, not a functional health check. Reproduce the symptom and compare the working Mac." : "Check whether the service is intended to run continuously or on demand before treating this state as a fault.",[e.id,"services"])
        }
        for p in c.preferences {
            let visible = SafeValue.meaningful(p.value)
            add("preference:"+p.key,visible ? .observed : .unknown,"Preference · \(p.key)","Value: \(p.value)\nManaged/forced in the collector's preference search path: \(p.forced.map { $0 ? "yes" : "no" } ?? "unknown")","CFPreferences reports the current collector account's search path. Match relevant profile definitions and compare the same key on the working Mac; application-specific policy handling may differ.",["preferences","profileRules"])
        }
        if c.preferences.isEmpty { add("preferences-none",.unknown,"No preference keys requested","The app deliberately avoids dumping every preference value.","Add only the relevant preference keys from the vendor or administrator's requirements.",["preferences"]) }
        add("profileCoverage",.unknown,"Profile coverage is bounded",c.profileCoverage.map { "\($0.source): \($0.status), \($0.profilesExamined) profiles. \($0.scope). \($0.detail)" }.joined(separator:"\n"),"A standard account may not expose every device profile. Attach an approved export to inspect its declared rules; supplied definitions do not prove installation or application.",["profiles","suppliedProfiles"])
        let groups = Dictionary(grouping:c.rules,by: \.comparisonKey)
        for key in groups.keys.sorted() {
            let entries = groups[key]!
            let usable = entries.filter { SafeValue.meaningful($0.value) }
            let values = Set(usable.map(\.value))
            let installedOnly = Dictionary(grouping:usable,by: { $0.source })
            let withinSourceConflict = installedOnly.values.contains { Set($0.map(\.value)).count > 1 }
            let difference = values.count > 1
            let first = entries[0]
            add("rule:"+key,withinSourceConflict ? .review : difference ? .review : .configured,withinSourceConflict ? "Overlapping rule definitions differ · \(first.key)" : difference ? "Installed and supplied definitions differ · \(first.key)" : "Relevant profile rule · \(first.key)",entries.map { "\($0.profileName) [\($0.profileID)] · \($0.source) · \($0.scope) · \($0.mode)\n\($0.subject): \($0.value)" }.joined(separator:"\n\n"),"These are declared rules. Matching scope, code requirements, payload-specific precedence, and actual application behavior determine effects. No winning profile is inferred. Structured or sensitive values are not compared.",["profileRules"])
        }
        for permission in c.requirements.permissions {
            let report = c.manualPermissions.first { $0.name == permission }?.state ?? "Not checked"
            add("permission:"+permission,report == "Not checked" ? .unknown : .reported,"Privacy permission · \(permission)","\(report). The collector does not read or modify the TCC database and does not test another application's actual permission grant.","Have the affected user inspect this application's entry in System Settings → Privacy & Security. Record the result as reported evidence, then test the actual function.",["permissions","profileRules"])
        }
        if c.requirements.permissions.isEmpty { add("permissions-none",.unknown,"Privacy requirements are unspecified","There is no generic public API here that verifies another app's complete permission state.","Select the vendor-required permissions and record the affected user's manual checks.",["permissions"]) }
        return results
    }
    static func compare(_ a: Inspection, _ b: Inspection) -> [Difference] {
        guard a.requirements.bundleID == b.requirements.bundleID else { return [Difference(id:"target",title:"Different expected applications",first:a.requirements.bundleID,second:b.requirements.bundleID,next:"Use the same expected bundle ID in both captures.")] }
        var differences: [Difference] = []
        func add(_ id: String, _ title: String, _ x: String, _ y: String, _ next: String) {
            if x != y { differences.append(Difference(id:id,title:title,first:x,second:y,next:next)) }
        }
        if a.requirements.normalized != b.requirements.normalized {
            let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
            add("requirements","Inspection requirements differ",String(decoding:(try? encoder.encode(a.requirements.normalized)) ?? Data(),as:UTF8.self),String(decoding:(try? encoder.encode(b.requirements.normalized)) ?? Data(),as:UTF8.self),"Use an identical saved requirements file for a controlled comparison. Different checks can explain missing observations.")
        }
        add("os","macOS version",a.osVersion,b.osVersion,"Check vendor compatibility and OS-specific policy or permission behavior.")
        add("exists","Application availability",String(a.app.exists),String(b.app.exists),"Verify the intended installation location and deployment result.")
        add("bundle","Observed bundle ID",a.app.bundleID ?? "Unknown",b.app.bundleID ?? "Unknown","Confirm both selected bundles are the intended product.")
        add("version","Application version/build","\(a.app.version ?? "Unknown") / \(a.app.build ?? "Unknown")","\(b.app.version ?? "Unknown") / \(b.app.build ?? "Unknown")","Check supported versions and upgrade history.")
        add("team","Observed Team ID",a.app.teamID ?? "Unknown",b.app.teamID ?? "Unknown","Compare against the approved publisher; inspect signature integrity separately.")
        let aPrefs = Dictionary(uniqueKeysWithValues:a.preferences.map { ($0.key,$0) })
        let bPrefs = Dictionary(uniqueKeysWithValues:b.preferences.map { ($0.key,$0) })
        for key in Set(aPrefs.keys).union(bPrefs.keys).sorted() {
            let x = aPrefs[key], y = bPrefs[key]
            if let x, let y, SafeValue.meaningful(x.value), SafeValue.meaningful(y.value) {
                add("pref:"+key,"Effective preference · "+key,"\(x.value) (forced: \(x.forced.map(String.init) ?? "unknown"))","\(y.value) (forced: \(y.forced.map(String.init) ?? "unknown"))","Compare current-account scope and the relevant configured rules. A changed value alone does not establish the cause.")
            } else if x?.value != y?.value || x == nil || y == nil { differences.append(Difference(id:"pref:"+key,title:"Preference visibility differs · "+key,first:x?.value ?? "Not requested",second:y?.value ?? "Not requested",next:"Do not interpret missing or omitted values as equal or as a default value.")) }
        }
        func ruleLines(_ c: Inspection) -> String { c.rules.map { "\($0.source) | \($0.scope) | \($0.profileID) | \($0.comparisonKey) = \($0.value)" }.sorted().joined(separator:"\n") }
        add("profiles","Relevant declared profile rules",ruleLines(a),ruleLines(b),"Check scope and coverage. Supplied exports are not proof of installed policy, and a missing rule may reflect limited visibility.")
        add("coverage","Profile collection scope",a.profileCoverage.map { "\($0.source): \($0.scope); \($0.status)" }.sorted().joined(separator:"\n"),b.profileCoverage.map { "\($0.source): \($0.scope); \($0.status)" }.sorted().joined(separator:"\n"),"Compare equivalent collection scopes before interpreting missing policy.")
        func processState(_ c: Inspection) -> String {
            guard let e = c.item("processes"), e.exitCode == 0, !e.timedOut, !e.truncated else { return "Unknown: process snapshot incomplete" }
            let paths = e.output.components(separatedBy:.newlines).compactMap { line -> String? in
                let parts = line.trimmingCharacters(in:.whitespaces).split(maxSplits:1,whereSeparator: { $0.isWhitespace })
                guard parts.count == 2 else { return nil }
                let path = String(parts[1]).trimmingCharacters(in:.whitespaces)
                return path.hasPrefix(c.app.path + "/") ? "[Selected app]/" + path.dropFirst(c.app.path.count + 1) : path
            }
            return paths.isEmpty ? "No matching executables observed" : Set(paths).sorted().joined(separator:"\n")
        }
        add("processes","Matching executable observations",processState(a),processState(b),"PIDs and duplicate instances are excluded. App-local paths are normalized across install locations. Presence or absence is a snapshot, not a functional check.")
        for id in Set(a.evidence.map(\.id)).union(b.evidence.map(\.id)).filter({ $0.hasPrefix("service:") || $0 == "extensions" || $0 == "signature" }).sorted() {
            func stable(_ e: Evidence?) -> String {
                guard let e else { return "Not collected" }
                if e.exitCode != 0 || e.timedOut || e.truncated { return "Incomplete: exit \(e.exitCode), timeout \(e.timedOut), truncated \(e.truncated)" }
                if id == "signature" { return "Integrity verification completed" }
                return e.output.components(separatedBy:.newlines).filter { !$0.hasPrefix("pid = ") && !$0.hasPrefix("runs = ") }.joined(separator:"\n")
            }
            add(id,"Observed state · "+id,stable(a.item(id)),stable(b.item(id)),"Review both evidence records. Service counters and PIDs are excluded from this comparison; observations are collected at different times.")
        }
        for name in Set(a.requirements.permissions).union(b.requirements.permissions).sorted() {
            add("permission:"+name,"Reported permission · "+name,a.manualPermissions.first { $0.name == name }?.state ?? "Not checked",b.manualPermissions.first { $0.name == name }?.state ?? "Not checked","These are operator reports, not measured grants. Reproduce the same application function on both Macs.")
        }
        if differences.isEmpty { differences.append(Difference(id:"same",title:"No differences found among comparable fields",first:"Unknown or omitted evidence remains unknown.",second:"Unknown or omitted evidence remains unknown.",next:"These snapshots cannot establish that the app is ready or exclude untested causes. Reproduce the user-visible function.")) }
        return differences
    }
}
