import Foundation

struct ProfileParseResult {
    var rules: [ProfileRule]
    var count: Int
}
enum ProfileParser {
    static func parse(_ data: Data, requirements: Requirements, subjects: Set<String>, teamID: String?, source: String) throws -> ProfileParseResult {
        guard data.count <= 1_048_576 else { throw InspectorError.message("Profile input exceeds 1 MB. Export a smaller relevant set of profiles.") }
        let object = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
        guard object is [String: Any] || object is [Any] else { throw InspectorError.message("The profile file is not a dictionary or array.") }
        var rules: [ProfileRule] = []
        var count = 0
        var exceeded = false
        func add(_ profile: [String:Any], _ scope: String, _ type: String, _ subject: String, _ key: String, _ value: Any, _ index: Int, mode: String = "Profile setting") {
            let pid = profile["ProfileIdentifier"] as? String ?? profile["PayloadIdentifier"] as? String ?? "[Identifier unavailable]"
            let name = profile["ProfileDisplayName"] as? String ?? profile["PayloadDisplayName"] as? String ?? pid
            let policyDecision = type == "com.apple.TCC.configuration-profile-policy" && key.hasSuffix(".Authorization") && ["allow", "deny", "allowstandardusertosetsystemservice"].contains((value as? String ?? "").lowercased())
            let text = SafeValue.display(value, key: policyDecision ? "PolicyDecision" : key)
            rules.append(ProfileRule(id: "\(source)-\(index)-\(rules.count)", profileID: String(pid.prefix(300)), profileName: String(name.prefix(300)), scope: scope, source: source, payloadType: type, mode: mode, subject: subject, key: key, value: text))
        }
        func payload(_ p: [String:Any], profile: [String:Any], scope: String, index: Int) {
            guard let type = p["PayloadType"] as? String else { return }
            // Installed profiles can wrap a payload's actual settings in PayloadContent.
            let body = p["PayloadContent"] as? [String:Any] ?? p
            if type == requirements.bundleID {
                for key in requirements.preferenceKeys { if let v = body[key] { add(profile,scope,"preferences",requirements.bundleID,key,v,index) } }
            }
            if type == "com.apple.ManagedClient.preferences", let domain = body[requirements.bundleID] as? [String:Any] {
                for group in ["Forced", "Set-Once"] {
                    for entry in domain[group] as? [[String:Any]] ?? [] {
                        let settings = entry["mcx_preference_settings"] as? [String:Any] ?? [:]
                        for key in requirements.preferenceKeys { if let value = settings[key] { add(profile,scope,"preferences",requirements.bundleID,key,value,index,mode:group) } }
                    }
                }
            }
            if type == "com.apple.TCC.configuration-profile-policy" {
                for (service, entries) in body["Services"] as? [String: [[String:Any]]] ?? [:] {
                    for entry in entries {
                        guard let identifier = entry["Identifier"] as? String, subjects.contains(identifier) else { continue }
                        // CodeRequirement and service names are retained to explain intended matching; they do not evaluate target permission.
                        for key in ["Authorization", "Allowed", "CodeRequirement", "IdentifierType", "StaticCode"] {
                            if let value = entry[key] { add(profile,scope,type,identifier,service + "." + key,value,index) }
                        }
                    }
                }
            }
            if type == "com.apple.system-extension-policy" {
                for (team, extensions) in body["AllowedSystemExtensions"] as? [String:[String]] ?? [:] {
                    for ext in extensions where subjects.contains(ext) { add(profile,scope,type,ext,"AllowedTeamIdentifier",team,index) }
                }
                if let teamID, (body["AllowedTeamIdentifiers"] as? [String] ?? []).contains(teamID) {
                    add(profile,scope,type,teamID,"TeamAllowed",true,index)
                }
            }
            if type == "com.apple.servicemanagement" {
                for entry in body["Rules"] as? [[String:Any]] ?? [] {
                    guard let ruleType = entry["RuleType"] as? String, let value = entry["RuleValue"] as? String else { continue }
                    let match = (ruleType == "BundleIdentifier" && subjects.contains(value)) || (ruleType == "TeamIdentifier" && value == teamID) || (ruleType == "Label" && requirements.services.contains { $0.label == value })
                    if match { add(profile,scope,type,value,"RuleType",ruleType,index) }
                }
            }
        }
        func walk(_ value: Any, scope: String, depth: Int) {
            guard depth <= 20, count < 500, rules.count < 2000 else { exceeded = true; return }
            if let array = value as? [Any] { for entry in array { walk(entry,scope:scope,depth:depth+1) }; return }
            guard let dict = value as? [String:Any] else { return }
            let isProfile = dict["ProfileIdentifier"] != nil || dict["ProfileItems"] != nil || dict["PayloadType"] as? String == "Configuration"
            if isProfile {
                count += 1
                let entries = dict["ProfileItems"] as? [[String:Any]] ?? dict["PayloadContent"] as? [[String:Any]] ?? []
                for entry in entries { payload(entry,profile:dict,scope:scope,index:count) }
                return
            }
            for key in dict.keys.sorted() {
                let childScope = key.lowercased() == "_computerlevel" ? "Device" : (depth == 0 && key != "PayloadContent" ? "User/export scope" : scope)
                walk(dict[key]!,scope:childScope,depth:depth+1)
            }
        }
        walk(object,scope:source == "installed" ? "Visible account scope" : "Supplied profile; installation unverified",depth:0)
        if exceeded || rules.count >= 2000 { throw InspectorError.message("Profile complexity limit exceeded. Use a smaller relevant export; partial rules are not treated as complete.") }
        if count == 0 {
            let emptyWrapper = (object as? [String:Any]).map { $0.isEmpty || $0.values.allSatisfy { ($0 as? [Any])?.isEmpty == true } } ?? ((object as? [Any])?.isEmpty == true)
            guard emptyWrapper else { throw InspectorError.message("No recognized configuration-profile structure was found.") }
        }
        return ProfileParseResult(rules: rules, count: count)
    }
}
