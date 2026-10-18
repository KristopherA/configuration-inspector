import Foundation
import Darwin

enum Runner {
    static func run(_ id: String, _ path: String, _ args: [String], timeout: Double = 8) -> Evidence {
        let start = Date()
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        do {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            defer { try? FileManager.default.removeItem(at: dir) }
            let out = dir.appendingPathComponent("out")
            FileManager.default.createFile(atPath: out.path, contents: nil, attributes: [.posixPermissions: 0o600])
            let handle = try FileHandle(forWritingTo: out)
            defer { try? handle.close() }
            let p = Process()
            p.executableURL = URL(fileURLWithPath: path)
            p.arguments = args
            p.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C", "HOME": dir.path]
            p.standardOutput = handle
            p.standardError = handle
            p.standardInput = FileHandle.nullDevice
            try p.run()
            let end = Date().addingTimeInterval(timeout)
            while p.isRunning && Date() < end { Thread.sleep(forTimeInterval: 0.05) }
            let expired = p.isRunning
            if expired {
                p.terminate()
                Thread.sleep(forTimeInterval: 0.15)
                if p.isRunning { kill(p.processIdentifier, SIGKILL) }
            }
            p.waitUntilExit()
            let reader = try FileHandle(forReadingFrom: out)
            defer { try? reader.close() }
            let data = try reader.read(upToCount: 1048576) ?? Data()
            let size = (try? FileManager.default.attributesOfItem(atPath: out.path)[.size] as? NSNumber)?.intValue ?? data.count
            return Evidence(id: id, command: ([path] + args).joined(separator: " "), output: String(decoding: data, as: UTF8.self), exitCode: p.terminationStatus, timedOut: expired, started: start, duration: Date().timeIntervalSince(start), truncated: size > data.count)
        } catch {
            return Evidence(id: id, command: path, output: error.localizedDescription, exitCode: -1, timedOut: false, started: start, duration: Date().timeIntervalSince(start))
        }
    }
}

