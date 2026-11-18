import SwiftUI
import AppKit
import UserNotifications
import Foundation

private enum UpdateChecker {
    private static let releaseURL = URL(string: "https://api.github.com/repos/alissonchaves/openconnect-gui/releases/latest")!

    static func checkAndNotify() {
        guard let current = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String,
              current != "Development build" else { return }

        var request = URLRequest(url: releaseURL)
        request.timeoutInterval = 8
        request.setValue("OpenConnect-for-Mac", forHTTPHeaderField: "User-Agent")
        URLSession.shared.dataTask(with: request) { data, _, _ in
            guard let data,
                  let payload = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let tag = payload["tag_name"] as? String,
                  let latest = Version(tag),
                  let installed = Version(current),
                  latest > installed else { return }

            DispatchQueue.main.async {
                let alert = NSAlert()
                alert.messageText = "New OpenConnect for Mac version available"
                alert.informativeText = "Version \(latest.string) is available. You are using version \(installed.string)."
                alert.alertStyle = .informational
                alert.addButton(withTitle: "Open Releases")
                alert.addButton(withTitle: "Later")
                NSApp.activate(ignoringOtherApps: true)
                if alert.runModal() == .alertFirstButtonReturn,
                   let releases = URL(string: "https://github.com/alissonchaves/openconnect-gui/releases") {
                    NSWorkspace.shared.open(releases)
                }
            }
        }.resume()
    }

    private struct Version: Comparable {
        let components: [Int]
        let string: String

        init?(_ raw: String) {
            let normalized = raw.trimmingCharacters(in: CharacterSet(charactersIn: "vV"))
                .split(separator: "-")
                .first.map(String.init) ?? ""
            let values = normalized.split(separator: ".").compactMap { Int($0) }
            guard !values.isEmpty else { return nil }
            components = values
            string = normalized
        }

        static func < (lhs: Version, rhs: Version) -> Bool {
            let count = max(lhs.components.count, rhs.components.count)
            for index in 0..<count {
                let left = index < lhs.components.count ? lhs.components[index] : 0
                let right = index < rhs.components.count ? rhs.components[index] : 0
                if left != right { return left < right }
            }
            return false
        }
    }
}

private final class AppNotificationDelegate: NSObject, UNUserNotificationCenterDelegate {
    static let shared = AppNotificationDelegate()

    func userNotificationCenter(_ center: UNUserNotificationCenter,
                                willPresent notification: UNNotification,
                                withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.banner, .sound, .badge])
    }
}

private final class AppLifecycleDelegate: NSObject, NSApplicationDelegate {
    func applicationWillFinishLaunching(_ notification: Notification) {
        let center = UNUserNotificationCenter.current()
        center.delegate = AppNotificationDelegate.shared
    }
}

@main
struct OpenConnectMac: App {
    @NSApplicationDelegateAdaptor(AppLifecycleDelegate.self) private var appDelegate
    @StateObject private var model = VPNModel(backend: CoreVPNBackend())

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(model)
                .frame(minWidth: 640, minHeight: 420)
                .task { UpdateChecker.checkAndNotify() }
                .onReceive(NotificationCenter.default.publisher(for: NSApplication.willTerminateNotification)) { _ in
                    // Give the privileged helper a chance to tear down the
                    // tunnel and restore DNS before the UI process exits.
                    model.disconnectAll()
                }
        }
        .windowResizability(.contentSize)

        MenuBarExtra {
            MenuBarStatusView()
                .environmentObject(model)
        } label: {
            TrayShieldIcon(activeCount: model.activeProfiles.count)
        }
        .menuBarExtraStyle(.menu)

        .commands {
            OpenConnectCommands(model: model)
        }
    }
}

private enum OpenConnectMetadata {
    static let name = "OpenConnect for Mac"
    static let projectName = "OpenConnect for Mac"
    static let author = "Alisson Chaves"
    static let credits = "Developed and maintained by Alisson Chaves.\n\nBased on the OpenConnect project and its contributors.\nLicensed under GNU GPL v2."
    static let projectURL = URL(string: "https://github.com/alissonchaves/openconnect-gui")!
    static let issuesURL = URL(string: "https://github.com/alissonchaves/openconnect-gui/issues")!
}

private struct TrayShieldIcon: View {
    let activeCount: Int

    var body: some View {
        HStack(spacing: 2) {
            Image(systemName: activeCount == 0 ? "shield.slash" : "shield.fill")
                .font(.system(size: 17, weight: .semibold))
            if activeCount > 1 {
                Text("\(activeCount)")
                    .font(.system(size: 10, weight: .bold, design: .rounded))
            }
        }
        .foregroundStyle(.primary)
        .accessibilityLabel(activeCount == 0 ? "VPN disconnected" : "\(activeCount) VPN connections active")
    }
}

private struct OpenConnectCommands: Commands {
    @ObservedObject var model: VPNModel

    var body: some Commands {
        CommandMenu("VPN Profile") {
            if model.profiles.isEmpty {
                Text("No profiles registered")
            } else {
                ForEach(model.profiles) { profile in
                    Menu(profile.name) {
                        Button("Use This Profile") {
                            model.select(profile: profile)
                        }
                        .disabled(model.selectedProfile == profile.name)

                        Button("Edit Profile…") {
                            model.requestEdit(profile: profile)
                        }

                        Divider()

                        Button("Remove Profile", role: .destructive) {
                            model.remove(profile: profile)
                        }
                        .disabled(!model.canRemove(profile: profile))
                    }
                }
            }
        }

        CommandGroup(replacing: .help) {
            Button("OpenConnectMac Help") {
                NSWorkspace.shared.open(OpenConnectMetadata.projectURL)
            }
            Button("About OpenConnect for Mac") {
                let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "Development build"
                let credits = NSAttributedString(string: OpenConnectMetadata.credits)
                NSApp.orderFrontStandardAboutPanel(options: [
                    .applicationName: "OpenConnect for Mac",
                    .applicationVersion: version,
                    .credits: credits
                ])
            }
            Divider()
#if DEBUG
            Button("Enable Notifications") { model.requestNotificationPermission() }
            Button("Test Notification") { model.sendTestNotification() }
            Button("Notification Status") { model.readNotificationStatus() }
#endif
            Button("Open Documentation") { NSWorkspace.shared.open(OpenConnectMetadata.projectURL) }
            Button("Report an Issue…") { NSWorkspace.shared.open(OpenConnectMetadata.issuesURL) }
        }

        CommandGroup(replacing: .appInfo) {
            Button("About \(OpenConnectMetadata.name)") {
                let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "Development build"
                let credits = NSAttributedString(string: OpenConnectMetadata.credits)
                NSApp.orderFrontStandardAboutPanel(options: [
                    .applicationName: OpenConnectMetadata.name,
                    .applicationVersion: version,
                    .credits: credits
                ])
            }
        }
    }
}

private struct MenuBarStatusView: View {
    @EnvironmentObject private var model: VPNModel

    var body: some View {
        Text(model.activeProfiles.isEmpty ? model.state.title : "\(model.activeProfiles.count) Active VPN Connection\(model.activeProfiles.count == 1 ? "" : "s")")
            .font(.headline)

        if model.activeProfiles.isEmpty, let profile = model.selectedProfile {
            Text(profile)
                .foregroundStyle(.secondary)
        }

        if !model.activeProfiles.isEmpty {
            Menu("Active Connections") {
                ForEach(model.activeProfiles) { profile in
                    Menu(profile.name) {
                        Text(model.state(for: profile.name).title)
                        Button("Disconnect") { model.disconnect(profileName: profile.name) }
                    }
                }
                if model.activeProfiles.count > 1 {
                    Divider()
                    Button("Disconnect All") { model.disconnectAll() }
                }
            }
        }

        Menu("VPN Profile") {
            if model.profiles.isEmpty {
                Text("No profiles registered")
            } else {
                ForEach(model.profiles) { profile in
                    Menu {
                        Button("Use This Profile") {
                            model.select(profile: profile)
                        }
                        .disabled(model.isConnected(profile))

                        Button("Connect") {
                            model.connect(profile: profile)
                        }
                        .disabled(model.isConnected(profile))
                        if model.isConnected(profile) {
                            Button("Disconnect") { model.disconnect(profileName: profile.name) }
                        }

                        Button("Edit Profile…") {
                            model.requestEdit(profile: profile)
                        }

                        Divider()

                        Button("Remove Profile", role: .destructive) {
                            model.remove(profile: profile)
                        }
                        .disabled(!model.canRemove(profile: profile))
                    } label: {
                        HStack {
                            Image(systemName: model.selectedProfile == profile.name ? "checkmark.circle.fill" : "circle")
                            Text(profile.name)
                        }
                    }
                }
            }
        }

        Divider()

        Button("About \(OpenConnectMetadata.name)") {
            NSApp.orderFrontStandardAboutPanel()
        }

        Menu("Help") {
            Button("Open Documentation") { NSWorkspace.shared.open(OpenConnectMetadata.projectURL) }
            Button("Report an Issue…") { NSWorkspace.shared.open(OpenConnectMetadata.issuesURL) }
        }

        Divider()

        Button("Connect") {
            model.connect()
        }
        .disabled(!model.canConnect)

        Button("Disconnect") {
            model.disconnect()
        }
        .disabled(!model.canDisconnect)

        Divider()

        Button("Open OpenConnect") {
            NSApp.activate(ignoringOtherApps: true)
        }
        .keyboardShortcut("o")

        Button("Quit") {
            NSApp.terminate(nil)
        }
        .keyboardShortcut("q")
    }
}

final class VPNModel: ObservableObject {
    private let backend: NativeVPNBackend

    @Published private(set) var state: VPNConnectionState
    @Published private(set) var profiles: [VPNProfile]
    @Published var selectedProfile: String?
    @Published private(set) var details: VPNDetails
    @Published private(set) var messages: [String]
    @Published var requestedProfileEdit: VPNProfile? = nil
    private var lastNotificationState: VPNConnectionState
    private var sleepObserver: NSObjectProtocol?

    init(backend: NativeVPNBackend) {
        self.backend = backend
        self.state = backend.state
        self.profiles = backend.profiles
        self.selectedProfile = backend.selectedProfile
        self.details = backend.details
        self.messages = backend.messages
        self.lastNotificationState = backend.state
        sleepObserver = NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.willSleepNotification, object: nil, queue: .main
        ) { [weak self] _ in
            // Clean up tunnel state before the physical network goes away.
            self?.disconnectAll()
        }
    }

    deinit {
        if let sleepObserver {
            NSWorkspace.shared.notificationCenter.removeObserver(sleepObserver)
        }
    }

    var canConnect: Bool {
        guard let selectedProfile,
              profiles.contains(where: { $0.name == selectedProfile }) else {
            return false
        }
        return !backend.activeConnections.contains(selectedProfile)
    }

    var canDisconnect: Bool {
        guard let selectedProfile else { return false }
        return backend.activeConnections.contains(selectedProfile)
    }

    func profile(named name: String) -> VPNProfile? {
        profiles.first { $0.name == name }
    }

    func select(profile: VPNProfile) {
        selectedProfile = profile.name
        backend.selectedProfile = profile.name
    }

    func select(named name: String?) {
        guard let name, let profile = profile(named: name) else {
            selectedProfile = nil
            backend.selectedProfile = nil
            return
        }
        select(profile: profile)
    }

    func canRemove(profile: VPNProfile) -> Bool {
        !backend.activeConnections.contains(profile.name)
    }

    func requestEdit(profile: VPNProfile) {
        requestedProfileEdit = profile
    }

    func save(profile: VPNProfile, replacing originalName: String? = nil) {
        backend.save(profile: profile, replacing: originalName)
        refresh()
    }

    func remove(profile: VPNProfile) {
        guard canRemove(profile: profile) else { return }
        backend.remove(profile: profile)
        refresh()
    }

    func connect() {
        backend.selectedProfile = selectedProfile
        backend.connect()
        refresh()
    }

    func connect(profile: VPNProfile) {
        select(profile: profile)
        backend.connect(profile: profile)
        refresh()
    }

    func disconnect() {
        backend.disconnect()
        refresh()
    }

    func disconnect(profileName: String) {
        backend.disconnect(profileName: profileName)
        refresh()
    }

    func disconnectAll() { backend.disconnectAll(); refresh() }

    func isConnected(_ profile: VPNProfile) -> Bool { backend.activeConnections.contains(profile.name) }
    var activeProfiles: [VPNProfile] {
        profiles.filter { backend.activeConnections.contains($0.name) }
    }
    func details(for profileName: String) -> VPNDetails {
        backend.connectionDetails[profileName] ?? VPNDetails()
    }
    func state(for profileName: String?) -> VPNConnectionState {
        guard let profileName else { return .disconnected }
        return backend.state(profileName: profileName)
    }
    func canRemove(_ profile: VPNProfile) -> Bool { !backend.activeConnections.contains(profile.name) }

    func clearLog() {
        backend.clearLog()
        messages = backend.messages
    }

    func sendTestNotification() {
        messages.append("Test notification requested")
        postNotification(body: "This is a test notification from OpenConnect VPN")
    }

    func requestNotificationPermission() {
        messages.append("Notification permission request started")
        let center = UNUserNotificationCenter.current()
        center.requestAuthorization(options: [.alert, .sound, .badge]) { granted, error in
            DispatchQueue.main.async {
                if let error {
                    self.messages.append("Notification permission error: \(error.localizedDescription)")
                } else if granted {
                    self.messages.append("macOS notifications enabled for OpenConnect VPN")
                    self.postNotification(body: "Notifications are enabled for OpenConnect VPN")
                } else {
                    self.messages.append("macOS notification permission was denied")
                }
            }
        }
    }

    func readNotificationStatus() {
        messages.append("Reading notification status")
        UNUserNotificationCenter.current().getNotificationSettings { settings in
            let status: String
            switch settings.authorizationStatus {
            case .notDetermined: status = "notDetermined"
            case .denied: status = "denied"
            case .authorized: status = "authorized"
            case .provisional: status = "provisional"
            case .ephemeral: status = "ephemeral"
            @unknown default: status = "unknown"
            }
            let alert = String(describing: settings.alertSetting)
            let center = String(describing: settings.notificationCenterSetting)
            DispatchQueue.main.async {
                self.messages.append("Notification status: authorization=\(status), alert=\(alert), notificationCenter=\(center)")
            }
        }
    }

    func refresh() {
        let oldState = state
        backend.refresh()
        state = backend.state
        profiles = backend.profiles
        selectedProfile = backend.selectedProfile
        details = backend.details
        messages = backend.messages
        if state != oldState, state != lastNotificationState {
            lastNotificationState = state
            switch state {
            case .connecting:
                postNotification(body: "Connecting to \(selectedProfile ?? "VPN profile")…")
            case .connected:
                postNotification(body: "VPN connected: \(selectedProfile ?? "profile")")
            case .disconnecting:
                if oldState == .connected || oldState == .connecting {
                    postNotification(body: "Disconnecting from \(selectedProfile ?? "VPN profile")…")
                }
            case .disconnected:
                if oldState == .connected || oldState == .connecting || oldState == .disconnecting {
                    postNotification(body: "VPN disconnected")
                }
            }
        }
    }

    private func postNotification(body: String) {
        let center = UNUserNotificationCenter.current()
        let content = UNMutableNotificationContent()
        content.title = "OpenConnect VPN"
        content.body = body
        content.sound = .default
        content.badge = 1
        let request = UNNotificationRequest(
            identifier: UUID().uuidString,
            content: content,
            trigger: nil
        )
        center.add(request) { error in
            DispatchQueue.main.async {
                if let error {
                    self.messages.append("Notification error: \(error.localizedDescription)")
                } else {
                    self.messages.append("Notification request accepted by macOS")
                }
            }
        }
    }
}
