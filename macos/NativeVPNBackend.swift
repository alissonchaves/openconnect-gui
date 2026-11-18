import Foundation
import Security
import Network
import OpenConnectCoreC

enum VPNConnectionState: Equatable {
    case disconnected
    case connecting
    case connected
    case disconnecting

    var title: String {
        switch self {
        case .disconnected: return "Disconnected"
        case .connecting: return "Connecting…"
        case .connected: return "Connected"
        case .disconnecting: return "Disconnecting…"
        }
    }
}

struct VPNDetails: Equatable {
    var ipv4 = ""
    var ipv6 = ""
    var dns = ""
    var dnsSearch = ""
    var cipher = ""
    var dtlsCipher = ""
    var upload = ""
    var download = ""
    var uploadSpeed = ""
    var downloadSpeed = ""
}

struct VPNProfile: Identifiable, Equatable {
    var id: String { name }
    var name: String
    var gateway: String
    var protocolName: String
    var username: String = ""
    var password: String = ""
    var openvpnConfigPath: String = ""
    var routeMode: String = "server"
    var customRoutes: String = ""
}

struct VPNProvider: Identifiable, Hashable {
    let id: String
    let title: String
}

enum CoreVPNProviders {
    static let fallback = [
        VPNProvider(id: "anyconnect", title: "Cisco AnyConnect or OpenConnect"),
        VPNProvider(id: "juniper", title: "Juniper Network Connect"),
        VPNProvider(id: "gp", title: "Palo Alto Networks GlobalProtect"),
        VPNProvider(id: "pulse", title: "Pulse Connect Secure"),
        VPNProvider(id: "f5", title: "F5 BIG-IP SSL VPN"),
        VPNProvider(id: "fortinet", title: "Fortinet SSL VPN"),
        VPNProvider(id: "array", title: "Array SSL VPN")
    ]

    static func load() -> [VPNProvider] {
        var buffer = Array(repeating: CChar(0), count: 4096)
        openconnect_core_supported_protocols(&buffer, UInt32(buffer.count))
        let output = String(cString: buffer)
        var values = output.split(whereSeparator: \.isNewline).compactMap { line -> VPNProvider? in
            let fields = line.split(separator: "\t", maxSplits: 1).map(String.init)
            guard fields.count == 2 else { return nil }
            return VPNProvider(id: fields[0].lowercased(), title: fields[1])
        }
        if values.isEmpty { values = fallback }
        if !values.contains(where: { $0.id == "openvpn" }) {
            values.append(VPNProvider(id: "openvpn", title: "OpenVPN"))
        }
        return values
    }
}

protocol NativeVPNBackend: AnyObject {
    var profiles: [VPNProfile] { get }
    var state: VPNConnectionState { get }
    var selectedProfile: String? { get set }
    var details: VPNDetails { get }
    var connectionDetails: [String: VPNDetails] { get }
    var messages: [String] { get }
    var activeConnections: Set<String> { get }
    func state(profileName: String) -> VPNConnectionState

    func connect()
    func connect(profile: VPNProfile)
    func disconnect()
    func disconnect(profileName: String)
    func disconnectAll()
    func refresh()
    func clearLog()
    func save(profile: VPNProfile, replacing originalName: String?)
    func remove(profile: VPNProfile)
}

/// Temporary backend used only by SwiftUI previews and the native UI shell.
/// The real implementation will be supplied by the Objective-C++ bridge.
final class PreviewVPNBackend: NativeVPNBackend {
    var profiles = [
        VPNProfile(name: "vpn.example.com", gateway: "vpn.example.com", protocolName: "AnyConnect"),
        VPNProfile(name: "Work VPN", gateway: "vpn.work.example", protocolName: "OpenVPN")
    ]
    var state: VPNConnectionState = .disconnected
    var selectedProfile: String? = "vpn.example.com"
    var details = VPNDetails()
    var connectionDetails: [String: VPNDetails] = [:]
    var messages = ["Native macOS interface initialized"]
    var activeConnections: Set<String> = []
    func state(profileName: String) -> VPNConnectionState { state }

    func connect() {
        messages.append("Connection bridge is not enabled in this preview")
    }
    func connect(profile: VPNProfile) { connect() }

    func refresh() {}

    func clearLog() { messages.removeAll() }

    func disconnect() {
        messages.append("Connection bridge is not enabled in this preview")
    }
    func disconnect(profileName: String) { disconnect() }
    func disconnectAll() { disconnect() }

    func save(profile: VPNProfile, replacing originalName: String?) {
        if let index = profiles.firstIndex(where: { $0.id == profile.id }) {
            profiles[index] = profile
        } else {
            profiles.append(profile)
        }
        selectedProfile = profile.name
        messages.append("Profile \(profile.name) saved in preview")
    }

    func remove(profile: VPNProfile) {
        profiles.removeAll { $0.id == profile.id }
        if selectedProfile == profile.name {
            selectedProfile = profiles.first?.name
        }
        messages.append("Profile \(profile.name) removed in preview")
    }
}

private struct NativeStoredProfile: Codable {
    var name: String
    var gateway: String
    var protocolName: String
    var username: String
    var openvpnConfigPath: String
    var routeMode: String
    var customRoutes: String

    init(name: String, gateway: String, protocolName: String, username: String, openvpnConfigPath: String = "", routeMode: String = "server", customRoutes: String = "") {
        self.name = name
        self.gateway = gateway
        self.protocolName = protocolName
        self.username = username
        self.openvpnConfigPath = openvpnConfigPath
        self.routeMode = routeMode
        self.customRoutes = customRoutes
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        name = try container.decode(String.self, forKey: .name)
        gateway = try container.decode(String.self, forKey: .gateway)
        protocolName = try container.decode(String.self, forKey: .protocolName)
        username = try container.decode(String.self, forKey: .username)
        openvpnConfigPath = try container.decodeIfPresent(String.self, forKey: .openvpnConfigPath) ?? ""
        routeMode = try container.decodeIfPresent(String.self, forKey: .routeMode) ?? "server"
        customRoutes = try container.decodeIfPresent(String.self, forKey: .customRoutes) ?? ""
    }
}

private enum NativeCredentialStore {
    private static let service = "net.openconnect-vpn.gui"

    static func load(account: String) -> String {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data else { return "" }
        return String(data: data, encoding: .utf8) ?? ""
    }

    static func save(_ password: String, account: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        let data = Data(password.utf8)
        let status = SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if status == errSecItemNotFound {
            var item = query
            item[kSecValueData as String] = data
            SecItemAdd(item as CFDictionary, nil)
        }
    }

    static func remove(account: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        SecItemDelete(query as CFDictionary)
    }
}

/// Native backend used by the macOS application. Profiles are stored as
/// Codable data in UserDefaults and the VPN session is owned by C++ core.
final class CoreVPNBackend: NativeVPNBackend {
    private static let profilesKey = "native.vpn.profiles"
    private static let selectedProfileKey = "native.vpn.selectedProfile"
    private static let previousBundleDefaults = UserDefaults(suiteName: "net.openconnect-vpn.gui.native")

    private(set) var profiles: [VPNProfile] = []
    var state: VPNConnectionState = .disconnected
    var selectedProfile: String? {
        didSet {
            if let selectedProfile {
                UserDefaults.standard.set(selectedProfile, forKey: Self.selectedProfileKey)
            } else {
                UserDefaults.standard.removeObject(forKey: Self.selectedProfileKey)
            }
            details = selectedProfile.flatMap { connectionDetails[$0] } ?? VPNDetails()
            activeVPN = selectedProfile.map { connectionStates[$0] == .connected } ?? false
            if activeVPN { startCounterPolling() } else { stopCounterPolling() }
        }
    }
    var details = VPNDetails()
    private(set) var connectionDetails: [String: VPNDetails] = [:]
    private(set) var messages: [String] = []

    private var sessions: [String: CoreNativeSession] = [:]
    private var connectionStates: [String: VPNConnectionState] = [:]
    var activeConnections: Set<String> { Set(sessions.keys) }
    func state(profileName: String) -> VPNConnectionState { connectionStates[profileName] ?? .disconnected }
    private var activeVPN = false
    private var counterTimer: Timer?
    private var healthTimer: Timer?
    private let probeQueue = DispatchQueue(label: "net.openconnect-vpn.server-probes")
    private var probesInFlight: Set<String> = []
    private var failedProbes: [String: Int] = [:]
    private var routeFingerprints: [String: String] = [:]
    private var recoveryTimers: [String: DispatchWorkItem] = [:]
    private struct TrafficSample {
        let date: Date
        let uploaded: UInt64
        let downloaded: UInt64
    }
    private var trafficSamples: [String: TrafficSample] = [:]

    private func formatBitRate(_ bitsPerSecond: Double) -> String {
        guard bitsPerSecond > 0 else { return "0 bit/s" }
        if bitsPerSecond >= 1_000_000_000 { return String(format: "%.2f Gbit/s", bitsPerSecond / 1_000_000_000) }
        if bitsPerSecond >= 1_000_000 { return String(format: "%.2f Mbit/s", bitsPerSecond / 1_000_000) }
        if bitsPerSecond >= 1_000 { return String(format: "%.2f kbit/s", bitsPerSecond / 1_000) }
        return String(format: "%.0f bit/s", bitsPerSecond)
    }

    private func formatByteCount(_ bytes: UInt64) -> String {
        let units = ["B", "KB", "MB", "GB", "TB"]
        var value = Double(bytes)
        var unit = 0
        while value >= 1024.0 && unit < units.count - 1 {
            value /= 1024.0
            unit += 1
        }
        if unit == 0 { return "\(bytes) B" }
        return String(format: "%.3f %@", value, units[unit])
    }

    private func startCounterPolling() {
        guard activeVPN, counterTimer == nil else { return }
        counterTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            self?.pollTunnelCounters()
        }
    }

    private func stopCounterPolling() {
        counterTimer?.invalidate()
        counterTimer = nil
    }

    private func pollTunnelCounters() {
        guard activeVPN, let profileName = selectedProfile,
              connectionStates[profileName] == .connected else { return }
        let address = connectionDetails[profileName]?.ipv4 ?? details.ipv4
        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let self, !address.isEmpty else { return }
            var interfaceBuffer = Array(repeating: CChar(0), count: 32)
            var received: UInt64 = 0
            var sent: UInt64 = 0
            let found = address.withCString { ipv4 in
                native_find_interface_for_ipv4(ipv4, &interfaceBuffer, UInt32(interfaceBuffer.count))
            }
            guard found != 0,
                  native_interface_counters(&interfaceBuffer, &received, &sent) != 0 else { return }
            DispatchQueue.main.async {
                guard self.connectionStates[profileName] == .connected else { return }
                self.updateTrafficDetails(profileName: profileName, uploaded: sent, downloaded: received)
            }
        }
    }

    init() {
        profiles = Self.loadProfiles()
        let savedSelection = UserDefaults.standard.string(forKey: Self.selectedProfileKey)
            ?? Self.previousBundleDefaults?.string(forKey: Self.selectedProfileKey)
        selectedProfile = profiles.contains(where: { $0.name == savedSelection })
            ? savedSelection
            : profiles.first?.name
        if profiles.isEmpty {
            messages = ["Create a VPN profile to connect"]
        }
        healthTimer = Timer.scheduledTimer(withTimeInterval: 10, repeats: true) { [weak self] _ in
            self?.checkActiveServers()
        }
    }

    private func makeSession(for profile: VPNProfile) -> CoreNativeSession {
        let session = CoreNativeSession()
        session.onStatus = { [weak self] status in
            DispatchQueue.main.async { [weak self] in
                guard let self else { return }
                let previousState = self.connectionStates[profile.name]
                self.connectionStates[profile.name] = status.state
                self.updateConnectionDetails(profileName: profile.name, status: status)
                if status.state == .connecting && previousState == .connected {
                    let recovery = DispatchWorkItem { [weak self] in
                        guard let self, self.connectionStates[profile.name] == .connecting else { return }
                        self.messages.append("[\(profile.name)] VPN did not recover after the network interruption; disconnecting to restore routes and DNS")
                        self.disconnect(profileName: profile.name)
                    }
                    self.recoveryTimers[profile.name]?.cancel()
                    self.recoveryTimers[profile.name] = recovery
                    DispatchQueue.main.asyncAfter(deadline: .now() + 30, execute: recovery)
                } else if status.state == .connected || status.state == .disconnected {
                    self.recoveryTimers[profile.name]?.cancel()
                    self.recoveryTimers.removeValue(forKey: profile.name)
                }
                if self.selectedProfile == profile.name {
                    self.details = self.connectionDetails[profile.name] ?? VPNDetails()
                }
                self.state = self.connectionStates.values.contains(.connecting) ? .connecting :
                    (self.connectionStates.values.contains(.connected) ? .connected :
                    (self.connectionStates.values.contains(.disconnecting) ? .disconnecting : .disconnected))
                if status.state == .connected, self.selectedProfile == profile.name { self.activeVPN = true; self.startCounterPolling() }
                if status.state == .connected {
                    self.routeFingerprints[profile.name] = self.physicalRouteFingerprint(for: profile)
                }
                if status.state == .disconnected {
                    self.sessions.removeValue(forKey: profile.name)
                    self.connectionStates.removeValue(forKey: profile.name)
                    self.connectionDetails.removeValue(forKey: profile.name)
                    self.trafficSamples.removeValue(forKey: profile.name)
                    self.failedProbes.removeValue(forKey: profile.name)
                    self.routeFingerprints.removeValue(forKey: profile.name)
                    self.recoveryTimers[profile.name]?.cancel()
                    self.recoveryTimers.removeValue(forKey: profile.name)
                    if self.selectedProfile == profile.name {
                        self.details = VPNDetails()
                        self.activeVPN = false
                        self.stopCounterPolling()
                    }
                }
            }
        }
        session.onLog = { [weak self] message in
            DispatchQueue.main.async { self?.messages.append("[\(profile.name)] \(message)") }
        }
        return session
    }

    private func updateConnectionDetails(profileName: String, status: CoreSessionStatus) {
        var value = connectionDetails[profileName] ?? VPNDetails()
        value.ipv4 = status.ipv4
        value.ipv6 = status.ipv6
        value.dns = status.dns
        value.dnsSearch = status.dnsSearch
        value.cipher = status.cipher
        value.dtlsCipher = status.dtlsCipher
        value.upload = formatByteCount(status.uploaded)
        value.download = formatByteCount(status.downloaded)

        let now = Date()
        if status.state == .connected, let previous = trafficSamples[profileName] {
            let elapsed = now.timeIntervalSince(previous.date)
            if elapsed > 0.05 {
                let uploadedDelta = status.uploaded >= previous.uploaded ? status.uploaded - previous.uploaded : 0
                let downloadedDelta = status.downloaded >= previous.downloaded ? status.downloaded - previous.downloaded : 0
                value.uploadSpeed = formatBitRate(Double(uploadedDelta) * 8.0 / elapsed)
                value.downloadSpeed = formatBitRate(Double(downloadedDelta) * 8.0 / elapsed)
            }
        } else {
            value.uploadSpeed = ""
            value.downloadSpeed = ""
        }
        trafficSamples[profileName] = TrafficSample(date: now, uploaded: status.uploaded, downloaded: status.downloaded)
        connectionDetails[profileName] = value
    }

    private func updateTrafficDetails(profileName: String, uploaded: UInt64, downloaded: UInt64) {
        var value = connectionDetails[profileName] ?? VPNDetails()
        value.upload = formatByteCount(uploaded)
        value.download = formatByteCount(downloaded)
        let now = Date()
        if let previous = trafficSamples[profileName], connectionStates[profileName] == .connected {
            let elapsed = now.timeIntervalSince(previous.date)
            if elapsed > 0.05 {
                let uploadedDelta = uploaded >= previous.uploaded ? uploaded - previous.uploaded : 0
                let downloadedDelta = downloaded >= previous.downloaded ? downloaded - previous.downloaded : 0
                value.uploadSpeed = formatBitRate(Double(uploadedDelta) * 8.0 / elapsed)
                value.downloadSpeed = formatBitRate(Double(downloadedDelta) * 8.0 / elapsed)
            }
        }
        trafficSamples[profileName] = TrafficSample(date: now, uploaded: uploaded, downloaded: downloaded)
        connectionDetails[profileName] = value
        if selectedProfile == profileName { details = value }
    }

    func connect() {
        guard let selectedProfile, let profile = profiles.first(where: { $0.name == selectedProfile }) else {
            messages.append("Select a VPN profile first")
            return
        }
        connect(profile: profile)
    }

    func connect(profile sourceProfile: VPNProfile) {
        guard sessions[sourceProfile.name] == nil else { return }
        var profile = sourceProfile
        // Do not unlock every Keychain item while the app is starting. Load
        // only the credentials needed by the profile the user connects to.
        if !profile.username.isEmpty && profile.password.isEmpty {
            profile.password = NativeCredentialStore.load(account: profile.name)
            if let index = profiles.firstIndex(where: { $0.name == profile.name }) {
                profiles[index].password = profile.password
            }
        }
        state = .connecting
        let session = makeSession(for: profile)
        sessions[profile.name] = session
        connectionStates[profile.name] = .connecting
        connectionDetails[profile.name] = VPNDetails()
        trafficSamples.removeValue(forKey: profile.name)
        failedProbes[profile.name] = 0
        activeVPN = true
        DispatchQueue.global(qos: .userInitiated).async { [session] in
            guard session.connect(profile: profile) else { return }
            session.run()
        }
    }

    func disconnect() {
        guard let selectedProfile else { return }
        disconnect(profileName: selectedProfile)
    }

    func disconnect(profileName: String) {
        state = .disconnecting
        connectionStates[profileName] = .disconnecting
        recoveryTimers[profileName]?.cancel()
        recoveryTimers.removeValue(forKey: profileName)
        if selectedProfile == profileName { stopCounterPolling() }
        sessions[profileName]?.disconnect()
    }

    func disconnectAll() {
        stopCounterPolling()
        for session in sessions.values { session.disconnect() }
        state = .disconnecting
    }

    private func checkActiveServers() {
        for profile in profiles where sessions[profile.name] != nil && connectionStates[profile.name] == .connected {
            if let fingerprint = physicalRouteFingerprint(for: profile) {
                if let previous = routeFingerprints[profile.name], previous != fingerprint {
                    messages.append("[\(profile.name)] Network route changed; disconnecting to clean up the old tunnel")
                    disconnect(profileName: profile.name)
                    continue
                }
                routeFingerprints[profile.name] = fingerprint
            }
            guard !probesInFlight.contains(profile.name),
                  let endpoint = serverEndpoint(for: profile, requireTCP: true),
                  let port = NWEndpoint.Port(rawValue: endpoint.port) else { continue }
            probesInFlight.insert(profile.name)
            let connection = NWConnection(host: NWEndpoint.Host(endpoint.host), port: port, using: .tcp)
            var completed = false
            func finish(_ reachable: Bool) {
                guard !completed else { return }
                completed = true
                connection.cancel()
                DispatchQueue.main.async { [weak self] in
                    guard let self else { return }
                    self.probesInFlight.remove(profile.name)
                    guard self.sessions[profile.name] != nil else { return }
                    if reachable {
                        self.failedProbes[profile.name] = 0
                    } else {
                        let failures = (self.failedProbes[profile.name] ?? 0) + 1
                        self.failedProbes[profile.name] = failures
                        self.messages.append("[\(profile.name)] VPN server probe failed (\(failures)/3)")
                        if failures >= 3 {
                            self.messages.append("[\(profile.name)] Server is unreachable; disconnecting to restore network routes and DNS")
                            self.disconnect(profileName: profile.name)
                        }
                    }
                }
            }
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready: finish(true)
                case .failed, .cancelled: finish(false)
                default: break
                }
            }
            connection.start(queue: probeQueue)
            probeQueue.asyncAfter(deadline: .now() + 5) { finish(false) }
        }
    }

    private func physicalRouteFingerprint(for profile: VPNProfile) -> String? {
        guard let endpoint = serverEndpoint(for: profile) else { return nil }
        let process = Process()
        let output = Pipe()
        process.executableURL = URL(fileURLWithPath: "/sbin/route")
        process.arguments = ["-n", "get", endpoint.host]
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        guard (try? process.run()) != nil else { return nil }
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0,
              let text = String(data: data, encoding: .utf8) else { return nil }
        let route = text.split(whereSeparator: \.isNewline).compactMap { line -> String? in
            let fields = line.split(separator: ":", maxSplits: 1).map(String.init)
            guard fields.count == 2 else { return nil }
            let key = fields[0].trimmingCharacters(in: .whitespaces)
            guard key == "gateway" || key == "interface" else { return nil }
            return "\(key)=\(fields[1].trimmingCharacters(in: .whitespaces))"
        }
        return route.count == 2 ? route.joined(separator: ";") : nil
    }

    private func serverEndpoint(for profile: VPNProfile, requireTCP: Bool = false) -> (host: String, port: UInt16)? {
        if profile.protocolName.caseInsensitiveCompare("openvpn") == .orderedSame {
            guard let config = try? String(contentsOfFile: profile.openvpnConfigPath, encoding: .utf8) else { return nil }
            var usesTCP = false
            var remote: (String, UInt16)?
            for rawLine in config.split(whereSeparator: \.isNewline) {
                let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !line.isEmpty, !line.hasPrefix("#"), !line.hasPrefix(";") else { continue }
                let fields = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
                if fields.first?.lowercased() == "proto", fields.count > 1 {
                    usesTCP = fields[1].lowercased().contains("tcp")
                } else if fields.count >= 2, fields[0].lowercased() == "remote", remote == nil {
                    let port = fields.count > 2 ? UInt16(fields[2]) ?? 1194 : 1194
                    remote = (fields[1].trimmingCharacters(in: CharacterSet(charactersIn: "[]")), port)
                }
            }
            return requireTCP && !usesTCP ? nil : remote
        }
        let raw = profile.gateway.contains("://") ? profile.gateway : "https://\(profile.gateway)"
        guard let components = URLComponents(string: raw), let host = components.host else { return nil }
        return (host, UInt16(components.port ?? 443))
    }

    func refresh() {
        // Status callbacks are delivered by the core session. This method is
        // intentionally cheap because the UI calls it once per second.
    }

    func clearLog() { messages.removeAll() }

    func save(profile: VPNProfile, replacing originalName: String?) {
        let cleaned = VPNProfile(
            name: profile.name.trimmingCharacters(in: .whitespacesAndNewlines),
            gateway: profile.gateway.trimmingCharacters(in: .whitespacesAndNewlines),
            protocolName: profile.protocolName,
            username: profile.username,
            password: profile.password,
            openvpnConfigPath: profile.openvpnConfigPath,
            routeMode: profile.routeMode, customRoutes: profile.customRoutes
        )
        profiles.removeAll { $0.name == originalName || $0.name == cleaned.name }
        profiles.append(cleaned)
        profiles.sort { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
        selectedProfile = cleaned.name
        if let originalName, originalName != cleaned.name {
            NativeCredentialStore.remove(account: originalName)
        }
        Self.saveProfiles(profiles)
        NativeCredentialStore.save(cleaned.password, account: cleaned.name)
        messages.append("Profile \(cleaned.name) saved")
    }

    func remove(profile: VPNProfile) {
        profiles.removeAll { $0.name == profile.name }
        selectedProfile = profiles.first?.name
        NativeCredentialStore.remove(account: profile.name)
        Self.saveProfiles(profiles)
        messages.append("Profile \(profile.name) removed")
    }

    private static func loadProfiles() -> [VPNProfile] {
        let currentData = UserDefaults.standard.data(forKey: profilesKey)
        let data = currentData ?? previousBundleDefaults?.data(forKey: profilesKey)
        if currentData == nil, let data {
            // Migrate profiles created by the native builds that used the
            // temporary .native bundle identifier.
            UserDefaults.standard.set(data, forKey: profilesKey)
        }
        guard let data,
              let values = try? JSONDecoder().decode([NativeStoredProfile].self, from: data) else {
            return []
        }
        return values.map {
            VPNProfile(name: $0.name, gateway: $0.gateway, protocolName: $0.protocolName.lowercased(),
                        username: $0.username, password: "",
                        openvpnConfigPath: $0.openvpnConfigPath, routeMode: $0.routeMode, customRoutes: $0.customRoutes)
        }
    }

    private static func saveProfiles(_ profiles: [VPNProfile]) {
        let values = profiles.map {
            NativeStoredProfile(name: $0.name, gateway: $0.gateway, protocolName: $0.protocolName,
                                username: $0.username, openvpnConfigPath: $0.openvpnConfigPath, routeMode: $0.routeMode, customRoutes: $0.customRoutes)
        }
        guard let data = try? JSONEncoder().encode(values) else { return }
        UserDefaults.standard.set(data, forKey: profilesKey)
    }
}
