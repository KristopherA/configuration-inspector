import SwiftUI
import AppKit
import UniformTypeIdentifiers

@MainActor final class InspectorModel: ObservableObject {
    @Published var path = ""
    @Published var bundleID = ""
    @Published var teamID = ""
    @Published var keys = ""
    @Published var systemServices = ""
    @Published var userServices = ""
    @Published var extensionIDs = ""
    @Published var permissions: Set<String> = []
    @Published var manual: [String:String] = [:]
    @Published var labelA = "Affected Mac"
    @Published var labelB = "Working Mac"
    @Published var a: Inspection?
    @Published var b: Inspection?
    @Published var busy = false
    @Published var progress = ""
    @Published var error: String?
    @Published var selectedView = 0
    @Published var sourceID = "identity"
    @Published var detailSlot = 0
    @Published var focusedEvidence: [String] = []
    @Published var showRequirements = false
    @Published var profileData: Data?
    @Published var profileAttached = false
    var locked: Bool { busy || a != nil || b != nil }
    func parts(_ value: String) -> [String] { value.split(whereSeparator: { $0 == "," || $0.isNewline }).map { $0.trimmingCharacters(in:.whitespacesAndNewlines) }.filter { !$0.isEmpty }.sorted() }
    func requirements() throws -> Requirements {
        let id = bundleID.trimmingCharacters(in:.whitespacesAndNewlines).isEmpty ? Collector.identity(at:path).bundleID ?? "" : bundleID.trimmingCharacters(in:.whitespacesAndNewlines)
        let r = Requirements(bundleID:id,expectedTeamID:teamID.trimmingCharacters(in:.whitespacesAndNewlines),preferenceKeys:parts(keys),services:parts(systemServices).map { ServiceSpec(label:$0,domain:"system") } + parts(userServices).map { ServiceSpec(label:$0,domain:"gui") },extensionIDs:parts(extensionIDs),permissions:permissions.sorted())
        try r.validate()
        return r
    }
    func apply(_ r: Requirements) {
        bundleID = r.bundleID; teamID = r.expectedTeamID; keys = r.preferenceKeys.joined(separator:", ")
        systemServices = r.services.filter { $0.domain == "system" }.map(\.label).joined(separator:", ")
        userServices = r.services.filter { $0.domain == "gui" }.map(\.label).joined(separator:", ")
        extensionIDs = r.extensionIDs.joined(separator:", "); permissions = Set(r.permissions)
    }
    func chooseApp() {
        let p = NSOpenPanel(); p.allowedContentTypes = [.applicationBundle]; p.canChooseDirectories = false
        p.directoryURL = URL(fileURLWithPath:"/Applications"); p.message = "Choose the application to inspect. It will not be launched."
        guard p.runModal() == .OK, let url = p.url else { return }
        path = url.path
        if !locked { bundleID = Collector.identity(at:path).bundleID ?? "" }
    }
    func capture(_ slot: Int) {
        do {
            let path = try Collector.validatePath(self.path)
            let r = try requirements()
            let label = slot == 0 ? labelA : labelB
            let reported = r.permissions.map { ManualPermission(name:$0,state:manual[$0] ?? "Not checked") }
            guard !label.isEmpty, label.count <= 120 else { throw InspectorError.message("Use a condition label of 1–120 characters.") }
            self.bundleID = r.bundleID
            let supplied = profileData
            busy = true; progress = "Starting inspection…"
            Task { [self] in
                do {
                    let result = try await Task.detached { [weak self] in
                        try Collector.collect(path:path,label:label,requirements:r,manual:reported,profileData:supplied) { value in Task { @MainActor in self?.progress = value } }
                    }.value
                    if slot == 0 { a = result } else { b = result }
                    detailSlot = slot
                    selectedView = (a != nil && b != nil) ? 1 : 0
                    focusedEvidence = []; progress = "Inspection \(slot == 0 ? "A" : "B") complete."
                } catch { self.error = error.localizedDescription }
                busy = false
            }
        } catch { self.error = error.localizedDescription }
    }
    func importInspection(_ slot: Int) {
        let p = NSOpenPanel(); p.allowedContentTypes = [.json]; p.message = "Import an inspection JSON. Imported evidence never executes commands."
        guard p.runModal() == .OK, let url = p.url else { return }
        do {
            let c = try Files.readInspection(url)
            if let other = slot == 0 ? b : a, other.requirements.bundleID != c.requirements.bundleID { throw InspectorError.message("The inspection targets a different bundle ID. Start over to inspect another app.") }
            if a == nil && b == nil { apply(c.requirements); path = c.app.path }
            if slot == 0 { a = c; labelA = c.label } else { b = c; labelB = c.label }
            detailSlot = slot
            selectedView = a != nil && b != nil ? 1 : 0; focusedEvidence = []
        } catch { self.error = error.localizedDescription }
    }
    func saveInspection(_ c: Inspection) {
        let p = NSSavePanel(); p.allowedContentTypes = [.json]; p.nameFieldStringValue = "inspection-\(c.id.uuidString.prefix(8)).json"
        guard p.runModal() == .OK, let url = p.url else { return }
        do { try Files.write(Files.encoder.encode(c),to:url) } catch { self.error = error.localizedDescription }
    }
    func importRequirements() {
        let p = NSOpenPanel(); p.allowedContentTypes = [.json]; p.message = "Load a shared, declarative requirements file. No commands or scripts are accepted."
        guard p.runModal() == .OK, let url = p.url else { return }
        do { apply(try Files.readRequirements(url)); showRequirements = true } catch { self.error = error.localizedDescription }
    }
    func saveRequirements() {
        do {
            let r = try requirements()
            let p = NSSavePanel(); p.allowedContentTypes = [.json]; p.nameFieldStringValue = "requirements.json"
            guard p.runModal() == .OK, let url = p.url else { return }
            try Files.write(Files.encoder.encode(r),to:url)
        } catch { self.error = error.localizedDescription }
    }
    func attachProfiles() {
        let p = NSOpenPanel(); p.allowedContentTypes = [.propertyList,.xml,UTType(filenameExtension:"mobileconfig") ?? .data]; p.message = "Select an unsigned XML or binary plist export. Only matching rules are retained. This does not prove the profile is installed."
        guard p.runModal() == .OK, let url = p.url else { return }
        do {
            let data = try Files.boundedData(url,max:1_048_576)
            _ = try PropertyListSerialization.propertyList(from:data,options:[],format:nil)
            profileData = data; profileAttached = true
        } catch { self.error = "Could not read this profile export. Use unsigned XML/binary plist, not a CMS-signed profile. " + error.localizedDescription }
    }
    func export() {
        guard let first = a ?? b else { return }
        let p = NSSavePanel(); p.allowedContentTypes = [.zip]; p.nameFieldStringValue = "Configuration-Inspector-Support.zip"
        p.message = "Includes selected settings, profile identifiers, paths, and labels. Sensitive-looking values are omitted, but the bundle is not fully redacted or encrypted. Review before sharing."
        guard p.runModal() == .OK, let url = p.url else { return }
        do { try Files.bundle(first,a == nil ? nil : b,to:url); progress = "Support bundle saved." } catch { self.error = error.localizedDescription }
    }
    func reset() {
        a = nil; b = nil; path = ""; bundleID = ""; teamID = ""; keys = ""; systemServices = ""; userServices = ""; extensionIDs = ""; permissions = []; manual = [:]; labelA = "Affected Mac"; labelB = "Working Mac"; profileData = nil; profileAttached = false; selectedView = 0; focusedEvidence = []; progress = ""
    }
}

@main struct ConfigurationInspectorApp: App {
    @StateObject private var model = InspectorModel()
    var body: some Scene {
        WindowGroup("Configuration Inspector") { ContentView().environmentObject(model) }.defaultSize(width:1200,height:860)
            .commands { CommandGroup(replacing:.newItem) {} }
    }
}
struct ContentView: View {
    @EnvironmentObject var m: InspectorModel
    private let accent = Color(red:0.27,green:0.32,blue:0.68)
    func color(_ state: ResultState) -> Color {
        switch state { case .observed: return Color(red:0.05,green:0.46,blue:0.40); case .review: return Color(red:0.66,green:0.34,blue:0.03); case .unknown: return .secondary; case .configured: return accent; case .reported: return .purple }
    }
    var body: some View {
        HStack(spacing:0) {
            VStack(alignment:.leading,spacing:22) {
                Image(systemName:"slider.horizontal.3").font(.system(size:34)).foregroundStyle(accent)
                Text("CONFIGURATION\nINSPECTOR").font(.system(size:15,weight:.bold,design:.rounded)).tracking(1.5)
                Text("Understand what is set.\nSee what is observed.").font(.callout).foregroundStyle(.secondary)
                Divider()
                step("1","Choose the application","Inspect its expected install path.")
                step("2","Set requirements","Use the same requirements on both Macs.")
                step("3","Collect evidence","Profiles, preferences, services, and extensions.")
                step("4","Compare a working Mac","Keep unknowns visible.")
                step("5","Hand off the evidence","Save or export before closing.")
                Spacer()
                Label("Read-only · local",systemImage:"internaldrive").font(.caption)
                Text("No app launch, permission changes, remediation, or uploads. Standard-user collection may be incomplete.").font(.caption).foregroundStyle(.secondary)
                Text("macOS 13+ · v1.0").font(.caption2).foregroundStyle(.secondary)
            }.padding(24).frame(width:220).frame(maxHeight:.infinity).background(accent.opacity(0.055))
            Divider()
            ScrollView {
                VStack(alignment:.leading,spacing:20) {
                    HStack(alignment:.top) {
                        VStack(alignment:.leading,spacing:7) {
                            Text("Why isn’t this app ready?").font(.system(size:29,weight:.semibold,design:.rounded))
                            Text("A repeatable inspection for help desk, sysadmins, and analysts.").foregroundStyle(.secondary)
                        }; Spacer()
                        Button("Start over") { m.reset() }.disabled(m.busy)
                    }
                    targetCard
                    HStack(alignment:.top,spacing:14) { slot(0); slot(1) }
                    if m.busy { HStack { ProgressView().controlSize(.small); Text(m.progress).font(.callout) } }
                    else if !m.progress.isEmpty { Label(m.progress,systemImage:"checkmark.circle").font(.callout).foregroundStyle(accent) }
                    if m.a != nil || m.b != nil { results }
                    else {
                        VStack(spacing:10) {
                            Image(systemName:"doc.text.magnifyingglass").font(.system(size:30)).foregroundStyle(accent)
                            Text("Evidence without guesswork.").font(.headline)
                            Text("Collect on this Mac or import a saved inspection. Configuration intent, observed state, and reported permissions stay separate.").multilineTextAlignment(.center).foregroundStyle(.secondary)
                        }.frame(maxWidth:.infinity).padding(26)
                    }
                }.padding(28)
            }.background(Color(nsColor:.windowBackgroundColor))
        }.frame(minWidth:1040,minHeight:760).tint(accent)
            .alert("Configuration Inspector",isPresented:Binding(get:{ m.error != nil },set:{ if !$0 { m.error = nil } })) { Button("OK") { m.error = nil } } message: { Text(m.error ?? "") }
    }
    func step(_ number: String,_ title: String,_ subtitle: String) -> some View {
        HStack(alignment:.top,spacing:10) {
            Text(number).font(.caption.bold()).frame(width:23,height:23).foregroundStyle(accent).background(accent.opacity(0.12),in:Circle())
            VStack(alignment:.leading,spacing:4) { Text(title).font(.callout.weight(.semibold)); Text(subtitle).font(.caption).foregroundStyle(.secondary) }
        }
    }
    var targetCard: some View {
        VStack(alignment:.leading,spacing:14) {
            Text("APPLICATION TO INSPECT").font(.caption.weight(.semibold)).tracking(1)
            HStack {
                TextField("/Applications/Example.app",text:$m.path).textFieldStyle(.roundedBorder).disabled(m.busy)
                Button("Choose app…") { m.chooseApp() }.disabled(m.busy)
            }
            HStack { Text("Expected bundle ID").font(.caption); TextField("com.vendor.application",text:$m.bundleID).textFieldStyle(.roundedBorder).disabled(m.locked) }
            Text("Choosing an app fills its bundle ID. For a missing app, enter its expected path and bundle ID. The selected app is never launched.").font(.caption).foregroundStyle(.secondary)
            DisclosureGroup("Inspection requirements",isExpanded:$m.showRequirements) {
                VStack(alignment:.leading,spacing:12) {
                    Text("Optional expectations from the vendor or your organization’s administrator. Save this file and use it on both Macs. Empty fields remain unspecified.").font(.caption).foregroundStyle(.secondary)
                    field("Publisher Team ID",placeholder:"Optional 10-character Team ID",text:$m.teamID)
                    field("Preference keys",placeholder:"Comma-separated keys; selected values only",text:$m.keys)
                    field("System launchd labels",placeholder:"com.vendor.service",text:$m.systemServices)
                    field("User launchd labels",placeholder:"com.vendor.agent",text:$m.userServices)
                    field("Required extension IDs",placeholder:"com.vendor.product.extension",text:$m.extensionIDs)
                    Text("Required privacy permissions").font(.caption.weight(.semibold))
                    LazyVGrid(columns:[GridItem(.flexible()),GridItem(.flexible())],alignment:.leading) {
                        ForEach(Requirements.permissionNames,id:\.self) { name in
                            Toggle(name,isOn:Binding(get:{ m.permissions.contains(name) },set:{ if $0 { m.permissions.insert(name) } else { m.permissions.remove(name) } })).font(.callout).disabled(m.locked)
                        }
                    }
                    HStack {
                        Button("Load requirements…") { m.importRequirements() }.disabled(m.locked)
                        Button("Save requirements…") { m.saveRequirements() }.disabled(m.busy)
                        Spacer()
                    }
                }.padding(.top,12)
            }
            HStack {
                Button(m.profileAttached ? "Replace profile export…" : "Attach profile export…") { m.attachProfiles() }.disabled(m.busy)
                if m.profileAttached { Label("Supplied definitions · installation unverified",systemImage:"doc.badge.plus").font(.caption).foregroundStyle(accent); Button("Remove") { m.profileData = nil; m.profileAttached = false }.disabled(m.busy) }
            }
            if !m.permissions.isEmpty {
                Divider()
                Text("Manual permission check for the next capture").font(.callout.weight(.semibold))
                Text("Ask the affected user to check System Settings → Privacy & Security. These selections record reports; they do not verify or change permission grants.").font(.caption).foregroundStyle(.secondary)
                ForEach(m.permissions.sorted(),id:\.self) { name in
                    HStack { Text(name).font(.callout); Spacer(); Picker(name,selection:Binding(get:{ m.manual[name] ?? "Not checked" },set:{ m.manual[name] = $0 })) { Text("Not checked").tag("Not checked"); Text("Reported enabled").tag("Reported enabled"); Text("Reported disabled").tag("Reported disabled") }.labelsHidden().frame(width:190).disabled(m.busy) }
                }
            }
        }.padding(18).background(.background,in:RoundedRectangle(cornerRadius:14))
    }
    func field(_ title: String,placeholder: String,text: Binding<String>) -> some View {
        HStack { Text(title).font(.caption).frame(width:150,alignment:.leading); TextField(placeholder,text:text).textFieldStyle(.roundedBorder).disabled(m.locked) }
    }
    func slot(_ index: Int) -> some View {
        let c = index == 0 ? m.a : m.b
        return VStack(alignment:.leading,spacing:11) {
            HStack { Text(index == 0 ? "A · FIRST OBSERVATION" : "B · COMPARISON").font(.caption.weight(.semibold)).tracking(0.7); Spacer(); if c != nil { Image(systemName:"checkmark.circle.fill").foregroundStyle(accent) } }
            TextField("Condition and workstation",text:index == 0 ? $m.labelA : $m.labelB).textFieldStyle(.roundedBorder).disabled(m.busy || c != nil)
            if let c {
                Text("\(c.app.name ?? c.requirements.bundleID) · \(c.app.version ?? "version unknown")").font(.callout.weight(.medium))
                Text(c.started.formatted(date:.abbreviated,time:.standard)).font(.caption).foregroundStyle(.secondary)
                HStack { Button("Save inspection…") { m.saveInspection(c) }; Button("Retake") { if index == 0 { m.a = nil } else { m.b = nil }; m.focusedEvidence = [] } }.disabled(m.busy)
            } else {
                Text(index == 0 ? "Inspect the affected condition on this Mac." : "Inspect again, or import a working Mac's JSON.").font(.caption).foregroundStyle(.secondary)
                HStack {
                    Button("Inspect \(index == 0 ? "A" : "B")") { m.capture(index) }.buttonStyle(.borderedProminent).disabled(m.busy || m.path.isEmpty)
                    Button("Import…") { m.importInspection(index) }.disabled(m.busy)
                }
            }
        }.frame(maxWidth:.infinity,minHeight:130,alignment:.topLeading).padding(18).background(.background,in:RoundedRectangle(cornerRadius:14))
    }
    var results: some View {
        VStack(alignment:.leading,spacing:16) {
            HStack {
                Picker("View",selection:$m.selectedView) { Text("Readiness").tag(0); Text("Compare").tag(1); Text("Evidence").tag(2); Text("Scope").tag(3) }.pickerStyle(.segmented).frame(width:400)
                Spacer(); Button { m.export() } label: { Label("Export support bundle",systemImage:"square.and.arrow.up") }.disabled(m.busy)
            }
            if m.selectedView == 0 {
                HStack { Picker("Inspection",selection:$m.detailSlot) { if m.a != nil { Text("A").tag(0) }; if m.b != nil { Text("B").tag(1) } }.pickerStyle(.segmented).frame(width:100); Text("Readiness is not scored. Each result identifies its evidence and limits.").font(.caption).foregroundStyle(.secondary) }
                let capture = m.detailSlot == 0 ? (m.a ?? m.b!) : (m.b ?? m.a!)
                let checks = Analysis.checks(capture)
                HStack(spacing:12) { ForEach(ResultState.allCases,id:\.rawValue) { state in let count = checks.filter { $0.state == state }.count; if count > 0 { Text("\(count) \(state.rawValue)").font(.caption.weight(.medium)).foregroundStyle(color(state)) } } }
                ForEach(checks) { check in checkCard(check) }
            } else if m.selectedView == 1 {
                if let a = m.a, let b = m.b {
                    ForEach(Analysis.compare(a,b)) { difference in
                        VStack(alignment:.leading,spacing:12) {
                            Text(difference.title).font(.headline)
                            HStack(alignment:.top,spacing:14) { compareText("A · " + a.label,difference.first); compareText("B · " + b.label,difference.second) }
                            Text("Next · " + difference.next).font(.callout).foregroundStyle(accent)
                            Button("Inspect evidence") { m.focusedEvidence = []; m.selectedView = 2 }
                        }.padding(18).frame(maxWidth:.infinity,alignment:.leading).background(.background,in:RoundedRectangle(cornerRadius:12))
                    }
                } else { Label("Collect or import both inspections to compare. Use the same requirements file.",systemImage:"info.circle").foregroundStyle(.secondary) }
            } else if m.selectedView == 2 { evidenceView }
            else {
                VStack(alignment:.leading,spacing:12) { Text("What this inspection establishes").font(.headline); Text(Files.scope).font(.callout).textSelection(.enabled); Text("Save or export before closing. There is no automatic history, remediation, background agent, or remote upload.").font(.callout) }.padding(20).background(.background,in:RoundedRectangle(cornerRadius:12))
            }
        }
    }
    func checkCard(_ c: CheckResult) -> some View {
        VStack(alignment:.leading,spacing:10) {
            HStack(alignment:.top) { Text(c.title).font(.headline); Spacer(); Text(c.state.rawValue.uppercased()).font(.system(size:10,weight:.bold)).tracking(0.7).foregroundStyle(color(c.state)).padding(.horizontal,9).padding(.vertical,5).background(color(c.state).opacity(0.08),in:Capsule()) }
            Text(c.detail).font(.callout).textSelection(.enabled)
            Text("Next · " + c.next).font(.callout).foregroundStyle(accent)
            Button("View supporting evidence") {
                m.focusedEvidence = c.evidenceIDs
                let ids = Set((m.a?.evidence.map(\.id) ?? []) + (m.b?.evidence.map(\.id) ?? []))
                m.sourceID = c.evidenceIDs.first(where:{ ids.contains($0) }) ?? "identity"
                m.selectedView = 2
            }.font(.caption)
        }.frame(maxWidth:.infinity,alignment:.leading).padding(18).background(.background,in:RoundedRectangle(cornerRadius:12))
    }
    func compareText(_ label: String,_ text: String) -> some View {
        VStack(alignment:.leading,spacing:7) { Text(label).font(.caption.weight(.semibold)).foregroundStyle(.secondary); Text(text.isEmpty ? "No retained entries." : text).font(.system(.caption,design:.monospaced)).textSelection(.enabled) }.frame(maxWidth:.infinity,alignment:.leading)
    }
    var evidenceView: some View {
        let all = Set((m.a?.evidence.map(\.id) ?? []) + (m.b?.evidence.map(\.id) ?? []))
        let ids = (m.focusedEvidence.isEmpty ? all.sorted() : m.focusedEvidence.filter { all.contains($0) })
        return VStack(alignment:.leading,spacing:14) {
            HStack {
                Picker("Evidence source",selection:$m.sourceID) { ForEach(ids,id:\.self) { Text($0).tag($0) } }.frame(maxWidth:430)
                if !m.focusedEvidence.isEmpty { Button("Show all evidence") { m.focusedEvidence = [] } }
            }
            HStack(alignment:.top,spacing:14) { if let a = m.a { evidenceColumn(a,"A") }; if let b = m.b { evidenceColumn(b,"B") } }
        }
    }
    func evidenceColumn(_ c: Inspection,_ title: String) -> some View {
        VStack(alignment:.leading,spacing:10) {
            Text(title + " · " + c.label).font(.headline)
            if let e = c.item(m.sourceID) {
                Text("Exit \(e.exitCode) · \(e.timedOut ? "Timed out" : String(format:"%.2fs",e.duration))\(e.truncated ? " · TRUNCATED" : "")\n\(e.started.ISO8601Format())").font(.caption).foregroundStyle(.secondary)
                Text(e.command).font(.system(.caption,design:.monospaced)).foregroundStyle(.secondary).textSelection(.enabled)
                Divider()
                Text(e.output.isEmpty ? "No matching output observed. Inspect scope and status before interpreting absence." : e.output).font(.system(.caption,design:.monospaced)).textSelection(.enabled)
            } else { Text("Not collected in this inspection.").foregroundStyle(.secondary) }
        }.frame(maxWidth:.infinity,alignment:.leading).padding(16).background(.background,in:RoundedRectangle(cornerRadius:12))
    }
}
