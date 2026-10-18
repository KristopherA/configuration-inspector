import Foundation

@main struct CLI {
    static func main() {
        do {
            let args = Array(CommandLine.arguments.dropFirst())
            if args.isEmpty || args == ["--help"] {
                print("Configuration Inspector 1.0\nUsage: configuration-inspector inspect --app /Applications/Example.app --requirements requirements.json --label 'Affected Mac' --output inspection.json [--profiles exported-profiles.plist]\nRead-only collection. No application is launched and no settings are changed. Saved inspections contain selected configuration details. Run as the affected standard user; root collections do not represent that user's preferences.")
                return
            }
            guard args.first == "inspect", args.count % 2 == 1 else { throw InspectorError.message("Use --help for the supported command format.") }
            var options: [String:String] = [:]
            let allowed = Set(["--app","--requirements","--label","--output","--profiles"])
            for i in stride(from:1,to:args.count,by:2) {
                guard allowed.contains(args[i]), options[args[i]] == nil else { throw InspectorError.message("Unknown or duplicated option: " + args[i]) }
                options[args[i]] = args[i+1]
            }
            guard let path = options["--app"], let requirementsFile = options["--requirements"], let label = options["--label"], let output = options["--output"] else { throw InspectorError.message("--app, --requirements, --label, and --output are required.") }
            let destination = URL(fileURLWithPath:output)
            guard !FileManager.default.fileExists(atPath:destination.path) else { throw InspectorError.message("Output already exists. Choose another filename.") }
            let requirements = try Files.readRequirements(URL(fileURLWithPath:requirementsFile))
            let profileData = try options["--profiles"].map { try Files.boundedData(URL(fileURLWithPath:$0),max:1_048_576) }
            let capture = try Collector.collect(path:path,label:label,requirements:requirements,manual:[],profileData:profileData) { print($0) }
            try Files.write(Files.encoder.encode(capture),to:destination,overwrite:false)
            print("Saved " + destination.path)
        } catch { fputs(error.localizedDescription + "\n",stderr); exit(1) }
    }
}
