import Foundation
import CryptoKit

@main struct Tests {
    static var total = 0
    static func check(_ value: @autoclosure () -> Bool, _ title: String) {
        total += 1
        guard value() else { fputs("FAIL: \(title)\n",stderr); exit(1) }
    }
    static func mustThrow(_ title: String,_ work: () throws -> Void) {
        do { try work(); check(false,title) } catch { check(true,title) }
    }
    static func fixture(_ r: Requirements) -> Inspection {
        Inspection(label:"Test observation",osVersion:"Fixture",collectorUID:501,requirements:r,app:AppIdentity(path:"/Applications/Fixture.app",exists:true,bundleID:r.bundleID,name:"Fixture",version:"1.0",build:"1",executable:"/Applications/Fixture.app/Contents/MacOS/Fixture",teamID:"ABCDE12345",signingIdentifier:r.bundleID,extensionIDs:[],helperIDs:[]),preferences:[],rules:[],profileCoverage:[],manualPermissions:[],evidence:[Evidence(id:"signature",command:"Fixture",output:"valid",exitCode:0,timedOut:false),Evidence(id:"processes",command:"Fixture",output:"101 /Applications/Fixture.app/Contents/MacOS/Fixture",exitCode:0,timedOut:false)])
    }
    static func main() throws {
        let r = Requirements(bundleID:"com.example.fixture",expectedTeamID:"ABCDE12345",preferenceKeys:["Enabled","Mode","AccessToken"],services:[ServiceSpec(label:"com.example.agent",domain:"gui")],extensionIDs:["com.example.fixture.extension"],permissions:["Screen Recording"])
        try r.validate(); check(true,"valid requirements")
        for id in ["", "--option", "com.example/app", "com.example\nfoo"] {
            mustThrow("invalid bundle ID") { var invalid = r; invalid.bundleID = id; try invalid.validate() }
        }
        mustThrow("invalid service scope") { var invalid = r; invalid.services = [ServiceSpec(label:"agent",domain:"root")]; try invalid.validate() }
        mustThrow("duplicate preference keys") { var invalid = r; invalid.preferenceKeys = ["Enabled","Enabled"]; try invalid.validate() }
        mustThrow("bad team ID") { var invalid = r; invalid.expectedTeamID = "wrong"; try invalid.validate() }
        mustThrow("unsupported permission") { var invalid = r; invalid.permissions = ["Everything"]; try invalid.validate() }
        mustThrow("relative app path") { _ = try Collector.validatePath("Fixture.app") }
        mustThrow("non-app target") { _ = try Collector.validatePath("/bin/sh") }
        mustThrow("manual observation injection") { try Collector.validateManual([ManualPermission(name:"Screen Recording",state:"Verified by tool")],requirements:r) }
        check(SafeValue.display("secret",key:"AccessToken") == "[Sensitive value omitted]","sensitive preferences suppressed")
        check(SafeValue.display(["secret":"value"],key:"Settings") == "[Structured value omitted]","structured values suppressed")
        check(SafeValue.display(true,key:"Enabled") == "true","boolean value normalized")
        check(!SafeValue.meaningful("[Not observed]"),"missing value not comparable")
        let custom: [String:Any] = ["PayloadType":"com.example.fixture","Enabled":true,"Mode":"managed","AccessToken":"DO-NOT-EXPORT","Unrelated":"NEVER-EXPORT"]
        let pppc: [String:Any] = ["PayloadType":"com.apple.TCC.configuration-profile-policy","Services":["ScreenCapture":[["Identifier":"com.example.fixture","IdentifierType":"bundleID","Authorization":"Deny","CodeRequirement":"identifier com.example.fixture"]],"Accessibility":[["Identifier":"com.unrelated.app","Allowed":true]]]]
        let ext: [String:Any] = ["PayloadType":"com.apple.system-extension-policy","AllowedSystemExtensions":["ABCDE12345":["com.example.fixture.extension","com.unrelated.extension"]]]
        let profile: [String:Any] = ["PayloadType":"Configuration","PayloadIdentifier":"test.policy","PayloadDisplayName":"Fixture policy","PayloadContent":[custom,pppc,ext]]
        let data = try PropertyListSerialization.data(fromPropertyList:profile,format:.xml,options:0)
        let subjects = Set([r.bundleID] + r.extensionIDs)
        let parsed = try ProfileParser.parse(data,requirements:r,subjects:subjects,teamID:r.expectedTeamID,source:"supplied")
        check(parsed.count == 1,"mobileconfig profile recognized")
        check(parsed.rules.contains { $0.key == "Enabled" && $0.value == "true" },"direct preference rule parsed")
        check(parsed.rules.contains { $0.key == "ScreenCapture.Authorization" && $0.value == "Deny" },"PPPC decision preserved")
        check(parsed.rules.contains { $0.subject == "com.example.fixture.extension" },"matching extension approval parsed")
        check(!parsed.rules.contains { $0.value.contains("DO-NOT-EXPORT") || $0.value.contains("NEVER-EXPORT") || $0.subject.contains("unrelated") },"unrelated and sensitive profile values excluded")
        check(parsed.rules.allSatisfy { $0.source == "supplied" && $0.scope.contains("unverified") },"supplied configuration is unverified")
        let installed: [String:Any] = ["_computerlevel":[["ProfileIdentifier":"installed.policy","ProfileDisplayName":"Installed policy","ProfileItems":[custom]]]]
        let installedResult = try ProfileParser.parse(PropertyListSerialization.data(fromPropertyList:installed,format:.xml,options:0),requirements:r,subjects:subjects,teamID:nil,source:"installed")
        check(installedResult.count == 1 && installedResult.rules.first?.scope == "Device","profiles installed wrapper scope")
        let mcx: [String:Any] = ["PayloadType":"Configuration","PayloadIdentifier":"mcx","PayloadContent":[["PayloadType":"com.apple.ManagedClient.preferences","PayloadContent":[r.bundleID:["Forced":[["mcx_preference_settings":["Enabled":false]]],"Set-Once":[["mcx_preference_settings":["Enabled":true]]]]]]]]
        let mcxResult = try ProfileParser.parse(PropertyListSerialization.data(fromPropertyList:mcx,format:.binary,options:0),requirements:r,subjects:subjects,teamID:nil,source:"supplied")
        check(Set(mcxResult.rules.map(\.mode)) == Set(["Forced","Set-Once"]),"forced and set-once modes retained separately")
        mustThrow("arbitrary plist rejected") { _ = try ProfileParser.parse(PropertyListSerialization.data(fromPropertyList:["not":"profile"],format:.xml,options:0),requirements:r,subjects:subjects,teamID:nil,source:"supplied") }
        mustThrow("malformed profile rejected") { _ = try ProfileParser.parse(Data("bad".utf8),requirements:r,subjects:subjects,teamID:nil,source:"supplied") }
        let rawService = "gui/501/com.example.agent = {\n\tstate = running\n\tpid = 123\n\targuments = {\n\t\t--secret\n\t}\n\tenvironment = {\n\t\tTOKEN = secret\n\t\tstate = fake\n\t}\n}\n"
        let summary = Collector.serviceSummary(rawService)
        check(summary.contains("state = running") && summary.contains("pid = 123"),"service state parsed")
        check(!summary.contains("secret") && !summary.contains("fake"),"arguments and nested environment excluded")
        var a = fixture(r)
        a.rules = parsed.rules
        a.preferences = [PreferenceObservation(key:"Enabled",value:"true",forced:true)]
        var b = a
        check(Analysis.compare(a,b).first?.id == "same","identical snapshots compare without false differences")
        b.requirements.preferenceKeys.reverse()
        check(Analysis.compare(a,b).first?.id == "same","equivalent requirements ignore key order")
        b.requirements.services.append(ServiceSpec(label:"com.example.another",domain:"system"))
        check(Analysis.compare(a,b).contains { $0.id == "requirements" },"semantically different requirements detected")
        b = a
        b.evidence[1].output = "102 /Applications/Fixture.app/Contents/MacOS/Fixture"
        check(Analysis.compare(a,b).first?.id == "same","process PID changes ignored")
        b.evidence[1].output = ""
        check(Analysis.compare(a,b).contains { $0.id == "processes" },"matching process absence compared")
        b = a
        b.app.version = "2.0"
        check(Analysis.compare(a,b).contains { $0.id == "version" },"version difference detected")
        b.preferences[0].value = "false"
        check(Analysis.compare(a,b).contains { $0.id == "pref:Enabled" },"preference difference detected")
        b.preferences[0].value = "[Not observed]"
        check(Analysis.compare(a,b).first { $0.id == "pref:Enabled" }?.title.contains("visibility") == true,"unknown preference not treated as a real value")
        b.requirements.bundleID = "com.other.app"
        check(Analysis.compare(a,b).first?.id == "target","different expected targets rejected")
        check(Analysis.checks(a).first { $0.id == "permission:Screen Recording" }?.state == .unknown,"unmeasured permission remains unknown")
        a.manualPermissions = [ManualPermission(name:"Screen Recording",state:"Reported enabled")]
        check(Analysis.checks(a).first { $0.id == "permission:Screen Recording" }?.state == .reported,"manual permission is reported, not measured")
        var conflicting = parsed.rules.first { $0.key == "Enabled" }!
        conflicting.id = "different"; conflicting.profileID = "other.policy"; conflicting.value = "false"
        a.rules.append(conflicting)
        check(Analysis.checks(a).contains { $0.state == .review && $0.title.contains("Overlapping") },"conflicting definitions flagged without winner")
        a.evidence[0].timedOut = true
        check(Analysis.checks(a).first { $0.id == "signature" }?.state != .observed,"timed-out signature never passing")
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at:dir,withIntermediateDirectories:true)
        defer { try? FileManager.default.removeItem(at:dir) }
        let file = dir.appendingPathComponent("inspection.json")
        try Files.write(Files.encoder.encode(a),to:file,overwrite:false)
        let loaded = try Files.readInspection(file)
        check(loaded.id == a.id && loaded.rules == a.rules,"inspection roundtrip")
        mustThrow("existing output protected") { try Files.write(Data(),to:file,overwrite:false) }
        let fileMode = try FileManager.default.attributesOfItem(atPath:file.path)[.posixPermissions] as? Int
        check(fileMode == 0o600,"owner-only permissions")
        var malformed = a; malformed.evidence.append(malformed.evidence[0])
        try Files.write(Files.encoder.encode(malformed),to:file)
        mustThrow("duplicate evidence IDs rejected") { _ = try Files.readInspection(file) }
        malformed = a; malformed.schemaVersion = 99
        try Files.write(Files.encoder.encode(malformed),to:file)
        mustThrow("unsupported inspection schema rejected") { _ = try Files.readInspection(file) }
        let zip = dir.appendingPathComponent("bundle.zip")
        try Files.bundle(a,a,to:zip)
        let extraction = dir.appendingPathComponent("unpacked")
        let unzip = Runner.run("unzip","/usr/bin/unzip",["-q",zip.path,"-d",extraction.path])
        check(unzip.exitCode == 0,"bundle extracts")
        let base = try FileManager.default.contentsOfDirectory(at:extraction,includingPropertiesForKeys:nil)[0]
        let manifest = try String(contentsOf:base.appendingPathComponent("SHA256SUMS.txt"),encoding:.utf8)
        check(manifest.split(separator:"\n").count == 4,"manifest covers both inspections requirements and report")
        for line in manifest.split(separator:"\n") {
            let pieces = line.split(separator:" ")
            let payload = try Data(contentsOf:base.appendingPathComponent(String(pieces[1])))
            check(SHA256.hash(data:payload).map { String(format:"%02x",$0) }.joined() == pieces[0],"payload checksum matches")
        }
        let timeout = Runner.run("timeout","/bin/sleep",["3"],timeout:0.1)
        check(timeout.timedOut && timeout.duration < 2,"bounded process timeout")
        print("PASS: \(total) checks")
    }
}
