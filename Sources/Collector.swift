import Foundation
import Security
import CoreFoundation

enum Collector {
    static func info(_ path: String) -> [String:Any]? {
        guard let metadata = try? URL(fileURLWithPath:path).resourceValues(forKeys:[.fileSizeKey,.isRegularFileKey]), metadata.isRegularFile == true,
              let size = metadata.fileSize, size <= 1_048_576,
              let data = try? Data(contentsOf:URL(fileURLWithPath:path)), let object = try? PropertyListSerialization.propertyList(from:data,options:[],format:nil) else { return nil }
        return object as? [String:Any]
    }
    static func identity(at path: String) -> AppIdentity {
        let root = URL(fileURLWithPath:path).standardizedFileURL.resolvingSymlinksInPath()
        let plist = info(root.appendingPathComponent("Contents/Info.plist").path)
        let executableName = plist?["CFBundleExecutable"] as? String
        var result = AppIdentity(path:root.path,exists:FileManager.default.fileExists(atPath:root.path),bundleID:plist?["CFBundleIdentifier"] as? String,name:plist?["CFBundleDisplayName"] as? String ?? plist?["CFBundleName"] as? String,version:plist?["CFBundleShortVersionString"] as? String,build:plist?["CFBundleVersion"] as? String,executable:executableName.map { root.appendingPathComponent("Contents/MacOS").appendingPathComponent($0).path },extensionIDs:[],helperIDs:[])
        if let executableName, executableName.contains("/") || executableName == ".." { result.executable = nil }
        for (folder, suffix, isExtension) in [("Contents/Library/SystemExtensions", ".systemextension", true), ("Contents/Library/LoginItems", ".app", false)] {
            let directory = root.appendingPathComponent(folder)
            for url in ((try? FileManager.default.contentsOfDirectory(at:directory,includingPropertiesForKeys:nil)) ?? []).sorted(by: { $0.path < $1.path }).prefix(40) where url.path.hasSuffix(suffix) {
                if let id = info(url.appendingPathComponent("Contents/Info.plist").path)?["CFBundleIdentifier"] as? String {
                    if isExtension { result.extensionIDs.append(id) } else { result.helperIDs.append(id) }
                }
            }
        }
        result.helperIDs += Array((plist?["SMPrivilegedExecutables"] as? [String:Any] ?? [:]).keys)
        result.helperIDs = Array(Set(result.helperIDs)).sorted()
        result.extensionIDs = Array(Set(result.extensionIDs)).sorted()
        var code: SecStaticCode?
        if SecStaticCodeCreateWithPath(root as CFURL,[],&code) == errSecSuccess, let code {
            var data: CFDictionary?
            if SecCodeCopySigningInformation(code,SecCSFlags(rawValue:kSecCSSigningInformation),&data) == errSecSuccess, let dict = data as? [String:Any] {
                result.teamID = dict[kSecCodeInfoTeamIdentifier as String] as? String
                result.signingIdentifier = dict[kSecCodeInfoIdentifier as String] as? String
            }
        }
        return result
    }
    static func validatePath(_ input: String) throws -> String {
        guard input.hasPrefix("/"), input.hasSuffix(".app"), input.count <= 2048, !input.contains(where: { $0.isNewline || $0 == "\0" }) else { throw InspectorError.message("Choose an application bundle, or enter its absolute path ending in .app. Missing application paths can be inspected when an expected bundle ID is supplied.") }
        return URL(fileURLWithPath:input).standardizedFileURL.path
    }
    static func validateManual(_ entries: [ManualPermission], requirements: Requirements) throws {
        guard Set(entries.map(\.name)).count == entries.count, entries.allSatisfy({ requirements.permissions.contains($0.name) && ["Not checked", "Reported enabled", "Reported disabled"].contains($0.state) }) else { throw InspectorError.message("Manual permission observations must match the selected requirements.") }
    }
    static func serviceSummary(_ raw: String) -> String {
        var selected: [String] = []
        for line in raw.components(separatedBy:.newlines) {
            let s = line.trimmingCharacters(in:.whitespaces)
            // launchctl's top-level fields have one tab. Do not parse braces in untrusted argument/environment values.
            if line.hasPrefix("\t"), !line.hasPrefix("\t\t"), !line.hasPrefix("\t "), ["path = ", "type = ", "state = ", "program = ", "pid = ", "runs = ", "last exit code = ", "last terminating signal = "].contains(where: { s.hasPrefix($0) }) { selected.append(s) }
        }
        return selected.isEmpty ? "Service was registered; no recognized state fields were returned." : selected.joined(separator:"\n")
    }
    static func launchdCandidates(app: AppIdentity, requirements: Requirements) -> [(ServiceSpec,String?)] {
        var result = requirements.services.map { ($0, Optional<String>.none) }
        let locations: [(String,String)] = [("/Library/LaunchDaemons","system"),("/Library/LaunchAgents","gui"),(FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/LaunchAgents").path,"gui"),(app.path + "/Contents/Library/LaunchDaemons","system"),(app.path + "/Contents/Library/LaunchAgents","gui")]
        for (folder,domain) in locations {
            for filename in ((try? FileManager.default.contentsOfDirectory(atPath:folder)) ?? []).sorted().prefix(500) where filename.hasSuffix(".plist") {
                guard let dict = info(folder + "/" + filename), let label = dict["Label"] as? String else { continue }
                let program = dict["Program"] as? String ?? (dict["ProgramArguments"] as? [String])?.first
                let associated = (dict["AssociatedBundleIdentifiers"] as? [String] ?? []) + ((dict["AssociatedBundleIdentifiers"] as? String).map { [$0] } ?? [])
                let matches = program.map { $0.hasPrefix(app.path + "/") } == true || associated.contains(requirements.bundleID) || app.helperIDs.contains(label)
                guard matches, label.range(of:"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$",options:.regularExpression) != nil else { continue }
                let spec = ServiceSpec(label:label,domain:domain)
                if let index = result.firstIndex(where: { $0.0 == spec }) { result[index].1 = program } else { result.append((spec,program)) }
            }
        }
        return Array(result.prefix(30))
    }
    static func collect(path: String, label: String, requirements: Requirements, manual: [ManualPermission], profileData: Data?, progress: @escaping (String)->Void) throws -> Inspection {
        let path = try validatePath(path)
        try requirements.validate()
        try validateManual(manual,requirements:requirements)
        guard !label.trimmingCharacters(in:.whitespacesAndNewlines).isEmpty, label.count <= 120 else { throw InspectorError.message("Use a condition label of 1–120 characters.") }
        progress("Reading application identity…")
        let app = identity(at:path)
        var capture = Inspection(label:label,osVersion:ProcessInfo.processInfo.operatingSystemVersionString,collectorUID:getuid(),requirements:requirements,app:app,preferences:[],rules:[],profileCoverage:[],manualPermissions:manual,evidence:[])
        capture.evidence.append(Evidence(id:"identity",command:"Read bounded Info.plist and Security signing metadata",output:"Path: \(app.path)\nExists: \(app.exists)\nBundle ID: \(app.bundleID ?? "Not observed")\nVersion: \(app.version ?? "Not observed")\nBuild: \(app.build ?? "Not observed")\nExecutable: \(app.executable ?? "Not observed")\nSigning identifier: \(app.signingIdentifier ?? "Not observed")\nTeam ID: \(app.teamID ?? "Not observed")\nBundled extensions: \(app.extensionIDs.joined(separator:", "))\nDeclared helpers: \(app.helperIDs.joined(separator:", "))",exitCode:0,timedOut:false))
        if app.exists {
            progress("Checking code signature integrity…")
            capture.evidence.append(Runner.run("signature","/usr/bin/codesign",["--verify","--deep","--strict","--verbose=2",app.path],timeout:15))
            capture.evidence.append(Runner.run("signatureDetails","/usr/bin/codesign",["--display","--verbose=4",app.path]))
        }
        progress("Inspecting selected preference keys…")
        for key in requirements.preferenceKeys {
            let value: String
            let forced: Bool?
            if SafeValue.sensitive(key) { value = "[Sensitive value omitted]"; forced = nil }
            else if getuid() == 0 { value = "[Unknown: root collection does not represent the affected user's preferences]"; forced = nil }
            else {
                value = SafeValue.display(CFPreferencesCopyAppValue(key as CFString,requirements.bundleID as CFString),key:key)
                forced = CFPreferencesAppValueIsForced(key as CFString,requirements.bundleID as CFString)
            }
            capture.preferences.append(PreferenceObservation(key:key,value:value,forced:forced))
        }
        capture.evidence.append(Evidence(id:"preferences",command:"CFPreferencesCopyAppValue + CFPreferencesAppValueIsForced for explicitly selected keys",output:capture.preferences.map { "\($0.key): \($0.value) | forced: \($0.forced.map(String.init) ?? "unknown")" }.joined(separator:"\n"),exitCode:0,timedOut:false))
        let subjects = Set([requirements.bundleID] + app.extensionIDs + app.helperIDs + requirements.extensionIDs)
        progress("Reading visible configuration profiles…")
        var profiles = Runner.run("profiles","/usr/bin/profiles",["show","-type","configuration","-output","stdout-xml"],timeout:15)
        let scope = getuid() == 0 ? "Device scope (root collector)" : "Current account visibility; device completeness unknown"
        if profiles.exitCode == 0, !profiles.timedOut, !profiles.truncated {
            do {
                let parsed = try ProfileParser.parse(Data(profiles.output.utf8),requirements:requirements,subjects:subjects,teamID:app.teamID,source:"installed")
                capture.rules += parsed.rules
                capture.profileCoverage.append(ProfileCoverage(source:"installed",scope:scope,status:"Parsed",profilesExamined:parsed.count,detail:"Only matching rules were retained. No matching rule does not establish absence of device policy."))
                profiles.output = "Parsed \(parsed.count) visible profiles. Retained \(parsed.rules.count) relevant rules. Raw profile bodies omitted.\nScope: \(scope)"
            } catch {
                capture.profileCoverage.append(ProfileCoverage(source:"installed",scope:scope,status:"Unknown",profilesExamined:0,detail:"Output could not be interpreted: \(error.localizedDescription)"))
                profiles.output = "Profile output could not be parsed. Raw content omitted. " + error.localizedDescription
            }
        } else {
            capture.profileCoverage.append(ProfileCoverage(source:"installed",scope:scope,status:"Unknown",profilesExamined:0,detail:"Command unavailable, denied, timed out, or output exceeded the limit."))
            profiles.output = "Profile evidence unavailable. Raw output omitted. Inspect exit status, timeout, and truncation flags."
        }
        capture.evidence.append(profiles)
        if let profileData {
            progress("Inspecting supplied profile definitions…")
            let parsed = try ProfileParser.parse(profileData,requirements:requirements,subjects:subjects,teamID:app.teamID,source:"supplied")
            capture.rules += parsed.rules
            capture.profileCoverage.append(ProfileCoverage(source:"supplied",scope:"Exported definitions; installation unverified",status:"Parsed",profilesExamined:parsed.count,detail:"Supplied XML/plist is configuration intent, not evidence that a device installed or applied it."))
            capture.evidence.append(Evidence(id:"suppliedProfiles",command:"Parse operator-supplied plist; never execute",output:"Parsed \(parsed.count) profile definitions; retained \(parsed.rules.count) relevant rules. Raw file and filename omitted.",exitCode:0,timedOut:false))
        }
        capture.evidence.append(Evidence(id:"profileRules",command:"Normalize relevant profile rules only",output:capture.rules.map { "[\($0.source) / \($0.scope)] \($0.profileName) [\($0.profileID)]\n\($0.payloadType) | \($0.mode) | \($0.subject) | \($0.key) = \($0.value)" }.joined(separator:"\n\n"),exitCode:0,timedOut:false))
        progress("Checking relevant system extension states…")
        var extensions = Runner.run("extensions","/usr/bin/systemextensionsctl",["list"])
        let extensionIDs = Set(app.extensionIDs + requirements.extensionIDs)
        if extensions.exitCode == 0 {
            extensions.output = extensions.output.components(separatedBy:.newlines).filter { line in
                let tokens = Set(line.split(whereSeparator: { $0.isWhitespace }).map(String.init))
                return !tokens.isDisjoint(with:extensionIDs)
            }.joined(separator:"\n")
        } else { extensions.output = "Extension inventory unavailable. No unrelated inventory retained." }
        capture.evidence.append(extensions)
        progress("Finding associated launchd services…")
        let candidates = launchdCandidates(app:app,requirements:requirements)
        for (spec,_) in candidates {
            progress("Checking \(spec.label)…")
            let target = spec.domain == "system" ? "system/" + spec.label : "gui/\(getuid())/" + spec.label
            var evidence = Runner.run("service:"+spec.id,"/bin/launchctl",["print",target],timeout:4)
            evidence.output = evidence.exitCode == 0 ? serviceSummary(evidence.output) : "Service state unavailable or service not registered in this scope. Exit \(evidence.exitCode). No arguments or environment retained."
            capture.evidence.append(evidence)
        }
        capture.evidence.append(Evidence(id:"services",command:"Bounded matching LaunchAgents/LaunchDaemons discovery",output:candidates.map { $0.0.id }.joined(separator:"\n"),exitCode:0,timedOut:false))
        progress("Checking matching executable paths…")
        var processes = Runner.run("processes","/bin/ps",["-ww","-axo","pid=,comm="])
        let helperPrograms = Set(candidates.compactMap { $0.1 })
        if processes.exitCode == 0 {
            processes.output = processes.output.components(separatedBy:.newlines).filter { line in
                let parts = line.trimmingCharacters(in:.whitespaces).split(maxSplits:1,whereSeparator: { $0.isWhitespace })
                guard parts.count == 2 else { return false }
                let exe = String(parts[1]).trimmingCharacters(in:.whitespaces)
                return exe.hasPrefix(app.path + "/") || helperPrograms.contains(exe)
            }.joined(separator:"\n")
        } else { processes.output = "Process snapshot unavailable. Unrelated process inventory not retained." }
        capture.evidence.append(processes)
        capture.evidence.append(Evidence(id:"permissions",command:"Operator-reported check; no TCC database access",output:requirements.permissions.map { permission in "\(permission): \(manual.first { $0.name == permission }?.state ?? "Not checked")" }.joined(separator:"\n"),exitCode:0,timedOut:false))
        for index in capture.evidence.indices {
            let bytes = Data(capture.evidence[index].output.utf8)
            if bytes.count > 1_048_576 {
                capture.evidence[index].output = String(decoding:bytes.prefix(1_048_576),as:UTF8.self)
                capture.evidence[index].truncated = true
            }
        }
        capture.finished = Date()
        return capture
    }
}
