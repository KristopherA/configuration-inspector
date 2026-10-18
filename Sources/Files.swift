import Foundation
import CryptoKit

enum Files {
    static let encoder: JSONEncoder = { let e = JSONEncoder(); e.dateEncodingStrategy = .iso8601; e.outputFormatting = [.prettyPrinted,.sortedKeys]; return e }()
    static func boundedData(_ url: URL, max: Int = 8_000_000) throws -> Data {
        let info = try url.resourceValues(forKeys:[.fileSizeKey,.isRegularFileKey])
        guard info.isRegularFile == true else { throw InspectorError.message("Choose a regular local file; directories and special files are not supported.") }
        let size = info.fileSize ?? 0
        guard size <= max else { throw InspectorError.message("File exceeds the \(max)-byte import limit.") }
        let data = try Data(contentsOf:url)
        guard data.count <= max else { throw InspectorError.message("File changed or exceeds the import limit.") }
        return data
    }
    static func readRequirements(_ url: URL) throws -> Requirements {
        let r = try JSONDecoder().decode(Requirements.self,from:boundedData(url,max:100_000)); try r.validate(); return r
    }
    static func readInspection(_ url: URL) throws -> Inspection {
        let d = JSONDecoder(); d.dateDecodingStrategy = .iso8601
        let c = try d.decode(Inspection.self,from:boundedData(url))
        try c.requirements.validate()
        try Collector.validateManual(c.manualPermissions,requirements:c.requirements)
        _ = try Collector.validatePath(c.app.path)
        guard c.schemaVersion == 1, !c.label.isEmpty, c.label.count <= 120, c.evidence.count <= 100, Set(c.evidence.map(\.id)).count == c.evidence.count,
              c.preferences.count <= 30, Set(c.preferences.map(\.key)).count == c.preferences.count,
              c.preferences.allSatisfy({ c.requirements.preferenceKeys.contains($0.key) }), c.rules.count <= 2000,
              Set(c.rules.map(\.id)).count == c.rules.count, c.profileCoverage.count <= 10,
              c.evidence.allSatisfy({ $0.output.utf8.count <= 1_048_576 && $0.duration >= 0 && $0.duration.isFinite }), c.finished >= c.started else { throw InspectorError.message("Unsupported, inconsistent, or oversized inspection record.") }
        return c
    }
    static func write(_ data: Data, to url: URL, overwrite: Bool = true) throws {
        try data.write(to:url,options:overwrite ? .atomic : .withoutOverwriting)
        try FileManager.default.setAttributes([.posixPermissions:0o600],ofItemAtPath:url.path)
    }
    static let scope = "Configured rules express intent; observed state is a bounded snapshot; reported permissions are operator observations; unknown evidence remains unknown. The app does not read TCC databases, grant permissions, modify profiles, start services, activate extensions, remediate, or upload data. Standard-user profile visibility is incomplete; supplied exports do not prove installation. Current-user CFPreferences values may differ from the affected app's own policy handling. Sensitive-looking keys and structured values are omitted, but remaining selected values, paths, profile names, Team IDs, code requirements, and labels may still be sensitive. Bundles are not fully redacted or encrypted. Hashes detect file changes; they do not prove authenticity or chain of custody. Imported evidence is untrusted data and never executes commands."
    static func report(_ a: Inspection, _ b: Inspection?) -> String {
        var text = "# Configuration Inspector report\n\nCreated: \(Date().ISO8601Format())\n\n"
        for (index,c) in [a,b].compactMap({ $0 }).enumerated() {
            text += "## \(index == 0 ? "A" : "B"): \(c.label)\n\nExpected bundle: \(c.requirements.bundleID)\nPath: \(c.app.path)\nStarted: \(c.started.ISO8601Format())\nFinished: \(c.finished.ISO8601Format())\nOS: \(c.osVersion)\nCollector UID: \(c.collectorUID)\n\n"
            for result in Analysis.checks(c) { text += "### [\(result.state.rawValue)] \(result.title)\n\n\(result.detail)\n\nNext: \(result.next)\nEvidence: \(result.evidenceIDs.joined(separator:", "))\n\n" }
        }
        if let b {
            text += "## Comparison\n\n"
            for d in Analysis.compare(a,b) { text += "### \(d.title)\n\nA: \(d.first)\n\nB: \(d.second)\n\nNext: \(d.next)\n\n" }
        }
        text += "## Scope and handling\n\n" + scope + "\n"
        return text
    }
    static func bundle(_ a: Inspection, _ b: Inspection?, to destination: URL) throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("ConfigurationInspector-" + UUID().uuidString)
        try FileManager.default.createDirectory(at:dir,withIntermediateDirectories:true,attributes:[.posixPermissions:0o700])
        defer { try? FileManager.default.removeItem(at:dir) }
        var entries: [(String,Data)] = [("inspection-A.json",try encoder.encode(a)),("requirements.json",try encoder.encode(a.requirements)),("report.md",Data(report(a,b).utf8))]
        if let b { entries.append(("inspection-B.json",try encoder.encode(b))) }
        var manifest = ""
        for (name,data) in entries {
            try write(data,to:dir.appendingPathComponent(name))
            manifest += SHA256.hash(data:data).map { String(format:"%02x",$0) }.joined() + "  " + name + "\n"
        }
        try write(Data(manifest.utf8),to:dir.appendingPathComponent("SHA256SUMS.txt"))
        let zipped = Runner.run("zip","/usr/bin/ditto",["-c","-k","--norsrc","--keepParent",dir.path,destination.path],timeout:20)
        guard zipped.exitCode == 0, !zipped.timedOut else { throw InspectorError.message("Export did not finish: " + zipped.output) }
        try FileManager.default.setAttributes([.posixPermissions:0o600],ofItemAtPath:destination.path)
    }
}
