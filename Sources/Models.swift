import Foundation
import CoreFoundation

enum InspectorError: LocalizedError {
    case message(String)
    var errorDescription: String? { if case .message(let value) = self { return value }; return nil }
}
struct Evidence: Codable, Identifiable {
    var id: String
    var command: String
    var output: String
    var exitCode: Int32
    var timedOut: Bool
    var started = Date()
    var duration: Double = 0
    var truncated: Bool = false
}
struct ServiceSpec: Codable, Equatable, Identifiable {
    var label: String
    var domain: String // system or gui; never an arbitrary launchctl target
    var id: String { domain + "/" + label }
}
struct Requirements: Codable, Equatable {
    var schemaVersion = 1
    var bundleID: String
    var expectedTeamID = ""
    var preferenceKeys: [String] = []
    var services: [ServiceSpec] = []
    var extensionIDs: [String] = []
    var permissions: [String] = []
    static let permissionNames = ["Screen Recording", "Accessibility", "Full Disk Access", "Input Monitoring", "Microphone", "Camera"]
    var normalized: Requirements {
        var result = self
        result.preferenceKeys.sort()
        result.services.sort { $0.id < $1.id }
        result.extensionIDs.sort()
        result.permissions.sort()
        return result
    }
    func validate() throws {
        func identifier(_ s: String) -> Bool { !s.isEmpty && s.count <= 200 && s.range(of: "^[A-Za-z0-9][A-Za-z0-9._-]*$", options: .regularExpression) != nil }
        guard schemaVersion == 1, identifier(bundleID), expectedTeamID.isEmpty || expectedTeamID.range(of: "^[A-Z0-9]{10}$", options: .regularExpression) != nil,
              preferenceKeys.count <= 30, Set(preferenceKeys).count == preferenceKeys.count,
              preferenceKeys.allSatisfy({ identifier($0) }), services.count <= 20,
              Set(services.map(\.id)).count == services.count,
              services.allSatisfy({ ["system", "gui"].contains($0.domain) && identifier($0.label) }),
              extensionIDs.count <= 30, Set(extensionIDs).count == extensionIDs.count, extensionIDs.allSatisfy({ identifier($0) }),
              Set(permissions).count == permissions.count, permissions.allSatisfy({ Self.permissionNames.contains($0) }) else {
            throw InspectorError.message("Requirements must use a valid bundle ID; a 10-character Team ID if specified; at most 30 unique preference keys, 20 services, and 30 extensions; and supported permission names. Services use system or gui scope.")
        }
    }
}
struct ManualPermission: Codable, Equatable, Identifiable {
    var name: String
    var state: String // Not checked, Reported enabled, Reported disabled
    var id: String { name }
}
struct AppIdentity: Codable {
    var path: String
    var exists: Bool
    var bundleID: String?
    var name: String?
    var version: String?
    var build: String?
    var executable: String?
    var teamID: String?
    var signingIdentifier: String?
    var extensionIDs: [String]
    var helperIDs: [String]
}
struct PreferenceObservation: Codable, Identifiable {
    var key: String
    var value: String
    var forced: Bool?
    var id: String { key }
}
struct ProfileRule: Codable, Identifiable, Equatable {
    var id: String
    var profileID: String
    var profileName: String
    var scope: String
    var source: String
    var payloadType: String
    var mode: String
    var subject: String
    var key: String
    var value: String
    var comparisonKey: String { payloadType + "|" + mode + "|" + subject + "|" + key }
}
struct ProfileCoverage: Codable {
    var source: String
    var scope: String
    var status: String
    var profilesExamined: Int
    var detail: String
}
struct Inspection: Codable, Identifiable {
    var schemaVersion = 1
    var appVersion = "1.0.0"
    var id = UUID()
    var started = Date()
    var finished = Date()
    var label: String
    var osVersion: String
    var collectorUID: UInt32
    var requirements: Requirements
    var app: AppIdentity
    var preferences: [PreferenceObservation]
    var rules: [ProfileRule]
    var profileCoverage: [ProfileCoverage]
    var manualPermissions: [ManualPermission]
    var evidence: [Evidence]
    func item(_ key: String) -> Evidence? { evidence.first { $0.id == key } }
}
enum ResultState: String, CaseIterable {
    case observed = "Observed", review = "Needs review", unknown = "Unknown", configured = "Configured", reported = "Reported"
}
struct CheckResult: Identifiable {
    var id: String
    var state: ResultState
    var title: String
    var detail: String
    var next: String
    var evidenceIDs: [String]
}
struct Difference: Identifiable {
    var id: String
    var title: String
    var first: String
    var second: String
    var next: String
}
enum SafeValue {
    static func sensitive(_ key: String) -> Bool {
        key.range(of: "password|passwd|secret|token|credential|cookie|private.?key|authorization|session|recovery.?key", options: [.regularExpression, .caseInsensitive]) != nil
    }
    static func display(_ value: Any?, key: String) -> String {
        if sensitive(key) { return "[Sensitive value omitted]" }
        guard let value else { return "[Not observed]" }
        if let n = value as? NSNumber {
            return CFGetTypeID(n) == CFBooleanGetTypeID() ? (n.boolValue ? "true" : "false") : n.stringValue
        }
        if let s = value as? String { return String(s.prefix(512)) + (s.count > 512 ? " [truncated]" : "") }
        if value is Data { return "[Binary value omitted]" }
        if value is Date { return "[Date value omitted]" }
        if value is [Any] || value is [String: Any] { return "[Structured value omitted]" }
        return "[Unsupported value omitted]"
    }
    static func meaningful(_ value: String) -> Bool { !value.hasPrefix("[") && !value.contains("[truncated]") }
}
