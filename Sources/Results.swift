import Foundation

// MARK: - Persisting module outcomes
//
// The journal records only *that* a primitive ran — a phase and a short detail string. The
// outcome itself (headline, the per-line detail, evidence, artifacts) lives in memory and is
// gone on relaunch, which is exactly the moment it is needed: four primitives in this build
// terminate the process. A container backup that carries only the journal therefore proves
// *where* the process died but not what the primitive reported before it did.
//
// Every completed module writes its outcome to the work directory instead, so a single backup
// is a self-contained record of the run.

enum Results {

    static func record(_ outcome: ModuleOutcome, module: ExploitModule, workdir: URL) {
        let dir = workdir.appendingPathComponent("results", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)

        var artifacts: [String] = []
        for url in outcome.artifacts { artifacts.append(url.lastPathComponent) }

        var payload: [String: Any] = [:]
        payload["id"] = module.id
        payload["cve"] = module.cve
        payload["component"] = module.component
        payload["title"] = module.title
        payload["primitive"] = module.primitive.rawValue
        payload["reach"] = module.reach.rawValue
        payload["tier"] = module.tier
        payload["headline"] = outcome.headline
        payload["detail"] = outcome.detail
        payload["evidence"] = outcome.evidence
        payload["artifacts"] = artifacts
        payload["elapsedMs"] = outcome.elapsedMs
        payload["failed"] = outcome.failed
        payload["recordedAt"] = ISO8601DateFormatter().string(from: Date())

        if let data = try? JSONSerialization.data(withJSONObject: payload,
                                                  options: [.prettyPrinted, .sortedKeys]) {
            // dots are legal in a filename but awkward to read and to glob
            let name = module.id.replacingOccurrences(of: ".", with: "-") + ".json"
            try? data.write(to: dir.appendingPathComponent(name), options: .atomic)
        }
        writeDevice(into: dir)
    }

    /// Device and build identity, so a bare backup explains itself without the app.
    static func writeDevice(into dir: URL) {
        let device = DeviceModel.current()
        var manifest: [String: Any] = [:]
        manifest["model"] = device.marketingName
        manifest["machine"] = device.machine
        manifest["hwModel"] = device.hwModel
        manifest["osVersion"] = device.osVersion
        manifest["osBuild"] = device.osBuild
        manifest["kernel"] = device.kernel
        manifest["cpuCount"] = device.cpuCount
        manifest["physicalMemory"] = Int(device.physicalMemory)
        manifest["vulnerabilityClass"] = device.vulnerabilityClass
        manifest["bundle"] = (Bundle.main.infoDictionary?["CFBundleIdentifier"] as? String) ?? "?"
        manifest["buildStamp"] = GuardJournal.buildStamp
        manifest["moduleCount"] = Catalog.all.count
        manifest["writtenAt"] = ISO8601DateFormatter().string(from: Date())
        if let data = try? JSONSerialization.data(withJSONObject: manifest,
                                                  options: [.prettyPrinted, .sortedKeys]) {
            try? data.write(to: dir.appendingPathComponent("_device.json"), options: .atomic)
        }
    }
}
