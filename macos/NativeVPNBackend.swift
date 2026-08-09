import Foundation
import Security
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
    var messages: [String] { get }

    func connect()
    func disconnect()
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
    var messages = ["Native macOS interface initialized"]

    func connect() {
        messages.append("Connection bridge is not enabled in this preview")
    }

    func refresh() {}

    func clearLog() { messages.removeAll() }

    func disconnect() {
        messages.append("Connection bridge is not enabled in this preview")
    }

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

    init(name: String, gateway: String, protocolName: String, username: String, openvpnConfigPath: String = "") {
        self.name = name
        self.gateway = gateway
        self.protocolName = protocolName
        self.username = username
        self.openvpnConfigPath = openvpnConfigPath
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        name = try container.decode(String.self, forKey: .name)
        gateway = try container.decode(String.self, forKey: .gateway)
        protocolName = try container.decode(String.self, forKey: .protocolName)
        username = try container.decode(String.self, forKey: .username)
        openvpnConfigPath = try container.decodeIfPresent(String.self, forKey: .openvpnConfigPath) ?? ""
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
        }
    }
    var details = VPNDetails()
    private(set) var messages: [String] = []

    private let session = CoreNativeSession()
    private var previousCounterDate: Date?
    private var previousUploaded: UInt64 = 0
    private var previousDownloaded: UInt64 = 0
    private var displayedUploaded: UInt64 = 0
    private var displayedDownloaded: UInt64 = 0
    private var activeVPN = false
    private var counterTimer: Timer?

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

    private func updateDisplayedCounters(uploaded: UInt64, downloaded: UInt64, state: VPNConnectionState) {
        let effectiveUploaded = max(displayedUploaded, uploaded)
        let effectiveDownloaded = max(displayedDownloaded, downloaded)
        displayedUploaded = effectiveUploaded
        displayedDownloaded = effectiveDownloaded
        details.upload = formatByteCount(effectiveUploaded)
        details.download = formatByteCount(effectiveDownloaded)
        let now = Date()
        if let previousDate = previousCounterDate, state == .connected {
            let elapsed = now.timeIntervalSince(previousDate)
            if elapsed > 0.05 {
                let uploadedDelta = effectiveUploaded >= previousUploaded ? effectiveUploaded - previousUploaded : 0
                let downloadedDelta = effectiveDownloaded >= previousDownloaded ? effectiveDownloaded - previousDownloaded : 0
                details.uploadSpeed = formatBitRate(Double(uploadedDelta) * 8.0 / elapsed)
                details.downloadSpeed = formatBitRate(Double(downloadedDelta) * 8.0 / elapsed)
            }
        } else if state != .connected {
            details.uploadSpeed = ""
            details.downloadSpeed = ""
        }
        previousCounterDate = now
        previousUploaded = effectiveUploaded
        previousDownloaded = effectiveDownloaded
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
        guard activeVPN, state == .connected else { return }
        let address = details.ipv4
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
                guard self.state == .connected else { return }
                self.updateDisplayedCounters(uploaded: sent, downloaded: received, state: .connected)
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
        session.onStatus = { [weak self] status in
            guard let self else { return }
            DispatchQueue.main.async {
                self.state = status.state
                self.details.ipv4 = status.ipv4
                self.details.ipv6 = status.ipv6
                self.details.dns = status.dns
                self.details.dnsSearch = status.dnsSearch
                self.details.cipher = status.cipher
                self.details.dtlsCipher = status.dtlsCipher
                if status.state == .connected { self.startCounterPolling() }
                if status.state != .connected { self.stopCounterPolling() }
                self.updateDisplayedCounters(uploaded: status.uploaded, downloaded: status.downloaded, state: status.state)
            }
        }
        session.onLog = { [weak self] message in
            DispatchQueue.main.async { self?.messages.append(message) }
        }
        if profiles.isEmpty {
            messages = ["Create a VPN profile to connect"]
        }
    }

    func connect() {
        guard let selectedProfile,
              var profile = profiles.first(where: { $0.name == selectedProfile }) else {
            messages.append("Select a VPN profile first")
            return
        }
        // Do not unlock every Keychain item while the app is starting. Load
        // only the credentials needed by the profile the user connects to.
        if !profile.username.isEmpty && profile.password.isEmpty {
            profile.password = NativeCredentialStore.load(account: profile.name)
            if let index = profiles.firstIndex(where: { $0.name == profile.name }) {
                profiles[index].password = profile.password
            }
        }
        state = .connecting
        activeVPN = true
        displayedUploaded = 0
        displayedDownloaded = 0
        previousCounterDate = nil
        DispatchQueue.global(qos: .userInitiated).async { [session] in
            guard session.connect(profile: profile) else { return }
            session.run()
        }
    }

    func disconnect() {
        state = .disconnecting
        stopCounterPolling()
        session.disconnect()
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
            openvpnConfigPath: profile.openvpnConfigPath
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
                        openvpnConfigPath: $0.openvpnConfigPath)
        }
    }

    private static func saveProfiles(_ profiles: [VPNProfile]) {
        let values = profiles.map {
            NativeStoredProfile(name: $0.name, gateway: $0.gateway, protocolName: $0.protocolName,
                                username: $0.username, openvpnConfigPath: $0.openvpnConfigPath)
        }
        guard let data = try? JSONEncoder().encode(values) else { return }
        UserDefaults.standard.set(data, forKey: profilesKey)
    }
}
