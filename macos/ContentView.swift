import SwiftUI
import UniformTypeIdentifiers
import AppKit

struct ContentView: View {
    @EnvironmentObject private var model: VPNModel
    @State private var selection: Section = .connection

    enum Section: Hashable {
        case connection
        case vpnInfo
        case log
        case vpnProfile
        case about
        case help
    }

    var body: some View {
        NavigationSplitView {
            List(selection: $selection) {
                Label("Connection", systemImage: "network")
                    .tag(Section.connection)
                Label("VPN Info", systemImage: "info.circle")
                    .tag(Section.vpnInfo)
                Label("Log", systemImage: "doc.text.magnifyingglass")
                    .tag(Section.log)
                Label("VPN Profile", systemImage: "list.bullet.indent")
                    .tag(Section.vpnProfile)
                Label("About", systemImage: "info.circle.fill")
                    .tag(Section.about)
                Label("Help", systemImage: "questionmark.circle")
                    .tag(Section.help)
            }
            .navigationTitle("OpenConnect")
            .listStyle(.sidebar)
        } detail: {
            Group {
                switch selection {
                case .connection:
                    ConnectionView()
                case .vpnInfo:
                    VPNInfoView()
                case .log:
                    LogView()
                case .vpnProfile:
                    VPNProfileTreeView()
                case .about:
                    AboutView()
                case .help:
                    HelpView()
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .padding(28)
        }
        .sheet(item: $model.requestedProfileEdit) { profile in
            ProfileEditorView(profile: profile) { updated in
                model.save(profile: updated, replacing: profile.name)
            }
        }
        // Keep the model synchronized regardless of which sidebar section is
        // selected. Previously this timer lived only in ConnectionView, so
        // VPN Info stopped receiving live counters when it was opened.
        .onReceive(Timer.publish(every: 1, on: .main, in: .common).autoconnect()) { _ in
            model.refresh()
        }
    }
}

private struct VPNProfileTreeView: View {
    @EnvironmentObject private var model: VPNModel
    @State private var showingNewProfile = false

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("VPN Profile")
                .font(.largeTitle.weight(.semibold))
            Button("New Profile") { showingNewProfile = true }
                .buttonStyle(.borderedProminent)
            if model.profiles.isEmpty {
                VStack(spacing: 10) {
                    Image(systemName: "folder")
                        .font(.system(size: 42))
                    Text("No VPN profiles")
                        .font(.headline)
                    Text("Create a profile in Connection.")
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List {
                    ForEach(model.profiles) { profile in
                        DisclosureGroup {
                            HStack {
                                Button("Use") { model.select(profile: profile) }
                                    .disabled(model.state != .disconnected)
                                Button("Connect") { model.connect(profile: profile) }
                                    .disabled(model.state != .disconnected)
                                Button("Edit") { model.requestEdit(profile: profile) }
                                Button("Remove", role: .destructive) { model.remove(profile: profile) }
                                    .disabled(!model.canRemove(profile: profile))
                            }
                            .padding(.vertical, 5)
                        } label: {
                            Label(profile.name, systemImage: model.selectedProfile == profile.name ? "checkmark.circle.fill" : "circle")
                        }
                    }
                }
                .listStyle(.inset)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .navigationTitle("VPN Profile")
        .sheet(isPresented: $showingNewProfile) {
            ProfileEditorView(profile: VPNProfile(name: "", gateway: "", protocolName: "anyconnect")) { profile in
                model.save(profile: profile)
            }
        }
    }
}

private struct AboutView: View {
    var body: some View {
        VStack(spacing: 16) {
            AppIconView(size: 96)
            Text("OpenConnect for Mac")
                .font(.largeTitle.weight(.semibold))
            Text("Native macOS VPN client")
                .foregroundStyle(.secondary)
            Text("Developed and maintained by Alisson Chaves\nNative OpenConnect and OpenVPN backends\nBased on the OpenConnect project and its contributors\nLicensed under GNU GPL v2.")
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .navigationTitle("About")
    }
}

private struct HelpView: View {
    @EnvironmentObject private var model: VPNModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Help")
                    .font(.largeTitle.weight(.semibold))
                Group {
                    Text("Getting started").font(.title2.weight(.semibold))
                    Text("Create a VPN profile, choose the provider, fill in the gateway and credentials, then select Connect. You can also connect directly from the tray menu.")
                }
                Group {
                    Text("VPN profiles").font(.title2.weight(.semibold))
                    Text("The VPN Profile section lists registered profiles. Expand a profile to use, connect, edit or remove it. New Profile creates a new connection.")
                }
                Group {
                    Text("Provider compatibility").font(.title2.weight(.semibold))
                    Label("Some VPN providers and profile combinations have not yet been fully tested. If one fails, check the complete Log and report the provider, protocol and error details.", systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.secondary)
                }
                Group {
                    Text("OpenVPN").font(.title2.weight(.semibold))
                    Text("Select the .ovpn bundle when creating the profile. Certificates, private keys, TLS settings, routes, DNS and search domains are read from the configuration. The username and password are requested separately when needed.")
                }
                Group {
                    Text("VPN Info and Log").font(.title2.weight(.semibold))
                    Text("VPN Info shows tunnel addresses, DNS, cipher, total traffic and current transfer speed. Log lines can be selected and copied individually or as a group.")
                }
                Group {
                    Text("Troubleshooting").font(.title2.weight(.semibold))
                    Text("If a connection fails, check the Log tab first. Confirm that the server name resolves on the current network, that the .ovpn paths are valid, and that the VPN profile uses the correct provider.")
                }
#if DEBUG
                Group {
                    Text("Notifications").font(.title2.weight(.semibold))
                    Text("Notifications report connection changes. Use the buttons below to request permission and send a test message. The result is recorded in Log.")
                    HStack {
                        Button("Enable Notifications") { model.requestNotificationPermission() }
                        Button("Test Notification") { model.sendTestNotification() }
                        Button("Check Status") { model.readNotificationStatus() }
                    }
                }
#endif
            }
            .frame(maxWidth: 720, alignment: .leading)
            .padding()
        }
        .navigationTitle("Help")
    }
}

private struct ConnectionView: View {
    @EnvironmentObject private var model: VPNModel
    @State private var editingProfile: VPNProfile?
    @State private var showingNewProfile = false

    var body: some View {
        VStack(alignment: .leading, spacing: 24) {
            HStack(spacing: 14) {
                AppIconView(size: 48, state: model.state)
                VStack(alignment: .leading, spacing: 4) {
                    Text(model.state.title)
                        .font(.title2.weight(.semibold))
                    Text(model.selectedProfile ?? "No VPN profile selected")
                        .foregroundStyle(.secondary)
                }
            }

            Picker("VPN Profile", selection: Binding<String?>(
                get: { model.selectedProfile },
                set: { model.select(named: $0) }
            )) {
                Text("Select a profile").tag(String?.none)
                ForEach(model.profiles) { profile in
                    Text(profile.name).tag(Optional(profile.name))
                }
            }
            .pickerStyle(.menu)

            HStack {
                Button("New Profile") {
                    showingNewProfile = true
                }

                Button("Edit Profile") {
                    if let selected = model.selectedProfile,
                       let profile = model.profile(named: selected) {
                        editingProfile = profile
                    }
                }
                .disabled(model.selectedProfile == nil)

                Button("Remove Profile", role: .destructive) {
                    if let selected = model.selectedProfile,
                       let profile = model.profile(named: selected) {
                        model.remove(profile: profile)
                    }
                }
                .disabled(model.selectedProfile == nil ||
                          (model.selectedProfile.flatMap { name in model.profile(named: name) }.map { !model.canRemove(profile: $0) } ?? true))
            }

            HStack {
                Button(model.state == .connecting ? "Cancel" : "Connect") {
                    model.connect()
                }
                .buttonStyle(.borderedProminent)
                .disabled(!model.canConnect)

                Button("Disconnect") {
                    model.disconnect()
                }
                .buttonStyle(.bordered)
                .disabled(!model.canDisconnect)
            }

            Spacer()
        }
        .navigationTitle("Connection")
        .sheet(item: $editingProfile) { profile in
            ProfileEditorView(profile: profile) { updated in
                model.save(profile: updated, replacing: profile.name)
            }
        }
        .sheet(isPresented: $showingNewProfile) {
            ProfileEditorView(profile: VPNProfile(name: "", gateway: "", protocolName: "anyconnect")) { profile in
                model.save(profile: profile)
            }
        }
    }
}

private struct ProfileEditorView: View {
    @Environment(\.dismiss) private var dismiss
    @State private var profile: VPNProfile
    @State private var showingConfigPicker = false
    @State private var openVPNDetails = OpenVPNConfigDetails()
    let onSave: (VPNProfile) -> Void

    init(profile: VPNProfile, onSave: @escaping (VPNProfile) -> Void) {
        _profile = State(initialValue: profile)
        self.onSave = onSave
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            Text(profile.name.isEmpty ? "New VPN Profile" : "Edit VPN Profile")
                .font(.title2.weight(.semibold))

            Form {
                TextField("Profile name", text: $profile.name)
                Picker("VPN provider", selection: $profile.protocolName) {
                    ForEach(CoreVPNProviders.load()) { provider in
                        Text(provider.title).tag(provider.id)
                    }
                }
                if profile.protocolName.caseInsensitiveCompare("openvpn") == .orderedSame {
                    HStack {
                        TextField("OpenVPN configuration", text: $profile.openvpnConfigPath)
                        Button("Choose…") { showingConfigPicker = true }
                        Button("Open Configuration") {
                            let url = URL(fileURLWithPath: profile.openvpnConfigPath)
                            let textEdit = URL(fileURLWithPath: "/System/Applications/TextEdit.app")
                            NSWorkspace.shared.open([url],
                                                     withApplicationAt: textEdit,
                                                     configuration: NSWorkspace.OpenConfiguration())
                        }
                        .disabled(profile.openvpnConfigPath.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ||
                                  !FileManager.default.fileExists(atPath: profile.openvpnConfigPath))
                    }
                    TextField("OpenVPN username", text: $profile.username)
                    SecureField("OpenVPN password", text: $profile.password)
                    if !openVPNDetails.isEmpty {
                        Section("Loaded OpenVPN configuration") {
                            LabeledContent("Remote", value: openVPNDetails.remote)
                            LabeledContent("Protocol", value: openVPNDetails.protocolName)
                            LabeledContent("Device", value: openVPNDetails.device)
                            LabeledContent("CA", value: openVPNDetails.ca)
                            LabeledContent("Client certificate", value: openVPNDetails.certificate)
                            LabeledContent("Private key", value: openVPNDetails.privateKey)
                            LabeledContent("TLS authentication", value: openVPNDetails.tlsAuth)
                            LabeledContent("TLS crypt", value: openVPNDetails.tlsCrypt)
                            LabeledContent("Authentication", value: openVPNDetails.authentication)
                        }
                    }
                } else {
                    TextField("Gateway", text: $profile.gateway)
                    TextField("Username", text: $profile.username)
                    SecureField("Password", text: $profile.password)
                }
            }
            .formStyle(.grouped)

            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                Button("Save") {
                    onSave(profile)
                    dismiss()
                }
                .buttonStyle(.borderedProminent)
                .disabled(profile.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ||
                          (profile.protocolName.caseInsensitiveCompare("openvpn") != .orderedSame &&
                           profile.gateway.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty) ||
                          (profile.protocolName.caseInsensitiveCompare("openvpn") == .orderedSame &&
                           profile.openvpnConfigPath.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty))
            }
        }
        .padding(24)
        .frame(width: 420)
        .onAppear { openVPNDetails = OpenVPNConfigDetails.load(path: profile.openvpnConfigPath) }
        .onChange(of: profile.openvpnConfigPath) { path in
            openVPNDetails = OpenVPNConfigDetails.load(path: path)
        }
        .fileImporter(
            isPresented: $showingConfigPicker,
            allowedContentTypes: [.data],
            allowsMultipleSelection: false
        ) { result in
            if case .success(let urls) = result, let url = urls.first {
                profile.openvpnConfigPath = url.path
                if profile.name.isEmpty {
                    profile.name = url.deletingPathExtension().lastPathComponent
                }
            }
        }
    }
}

private struct OpenVPNConfigDetails {
    var remote = "Not specified"
    var protocolName = "Not specified"
    var device = "Not specified"
    var ca = "Not specified"
    var certificate = "Not specified"
    var privateKey = "Not specified"
    var tlsAuth = "Not specified"
    var tlsCrypt = "Not specified"
    var authentication = "Not specified"

    var isEmpty: Bool { remote == "Not specified" && protocolName == "Not specified" && device == "Not specified" }

    static func load(path: String) -> OpenVPNConfigDetails {
        guard !path.isEmpty, let contents = try? String(contentsOfFile: path, encoding: .utf8) else {
            return OpenVPNConfigDetails()
        }

        var details = OpenVPNConfigDetails()
        var embedded: Set<String> = []
        for rawLine in contents.split(whereSeparator: \.isNewline) {
            let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            if line.hasPrefix("<"), line.hasSuffix(">") {
                embedded.insert(line.trimmingCharacters(in: CharacterSet(charactersIn: "<>" )).lowercased())
                continue
            }
            guard !line.isEmpty, !line.hasPrefix("#"), !line.hasPrefix(";") else { continue }
            let fields = line.split(maxSplits: 1, whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
            guard let key = fields.first else { continue }
            let value = fields.count > 1 ? fields[1] : ""
            switch key.lowercased() {
            case "remote": details.remote = value
            case "proto": details.protocolName = value
            case "dev": details.device = value
            case "ca": details.ca = value
            case "cert": details.certificate = value
            case "key": details.privateKey = value
            case "tls-auth": details.tlsAuth = value
            case "tls-crypt": details.tlsCrypt = value
            case "auth-user-pass": details.authentication = value.isEmpty ? "Username/password required" : value
            default: break
            }
        }
        if embedded.contains("ca") { details.ca = "Embedded in .ovpn" }
        if embedded.contains("cert") { details.certificate = "Embedded in .ovpn" }
        if embedded.contains("key") { details.privateKey = "Embedded in .ovpn" }
        if embedded.contains("tls-auth") { details.tlsAuth = "Embedded in .ovpn" }
        if embedded.contains("tls-crypt") { details.tlsCrypt = "Embedded in .ovpn" }
        return details
    }
}

private struct VPNInfoView: View {
    @EnvironmentObject private var model: VPNModel

    var body: some View {
        Form {
            LabeledContent("IPv4", value: model.details.ipv4.isEmpty ? "—" : model.details.ipv4)
            LabeledContent("IPv6", value: model.details.ipv6.isEmpty ? "—" : model.details.ipv6)
            LabeledContent("DNS", value: model.details.dns.isEmpty ? "—" : model.details.dns)
            LabeledContent("DNS Search", value: model.details.dnsSearch.isEmpty ? "—" : model.details.dnsSearch)
            LabeledContent("Cipher", value: model.details.cipher.isEmpty ? "—" : model.details.cipher)
            LabeledContent("DTLS Cipher", value: model.details.dtlsCipher.isEmpty ? "—" : model.details.dtlsCipher)
            LabeledContent("Download", value: model.details.download.isEmpty ? "—" : model.details.download)
            LabeledContent("Upload", value: model.details.upload.isEmpty ? "—" : model.details.upload)
            LabeledContent("Download Speed", value: model.details.downloadSpeed.isEmpty ? "—" : model.details.downloadSpeed)
            LabeledContent("Upload Speed", value: model.details.uploadSpeed.isEmpty ? "—" : model.details.uploadSpeed)
        }
        .formStyle(.grouped)
        .navigationTitle("VPN Info")
    }
}

private struct LogView: View {
    @EnvironmentObject private var model: VPNModel

    var body: some View {
        SelectableLogTextView(text: model.messages.joined(separator: "\n"))
            .background(.quaternary.opacity(0.35), in: RoundedRectangle(cornerRadius: 10))
            .toolbar {
                ToolbarItem(placement: .automatic) {
                    Button("Clean Log") {
                        model.clearLog()
                    }
                    .labelStyle(.titleOnly)
                }
            }
        .navigationTitle("Log")
    }
}

private struct SelectableLogTextView: NSViewRepresentable {
    let text: String

    func makeNSView(context: Context) -> NSScrollView {
        let textView = NSTextView()
        textView.isEditable = false
        textView.isSelectable = true
        textView.allowsUndo = false
        textView.drawsBackground = false
        textView.font = NSFont.monospacedSystemFont(ofSize: NSFont.systemFontSize, weight: .regular)
        textView.textColor = .labelColor
        textView.textContainerInset = NSSize(width: 14, height: 14)
        textView.isAutomaticQuoteSubstitutionEnabled = false
        textView.isAutomaticDashSubstitutionEnabled = false
        textView.menu = NSMenu(title: "Log")
        textView.menu?.addItem(withTitle: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")

        let scrollView = NSScrollView()
        scrollView.hasVerticalScroller = true
        scrollView.hasHorizontalScroller = true
        scrollView.autohidesScrollers = true
        scrollView.drawsBackground = false
        scrollView.documentView = textView
        textView.minSize = NSSize(width: 0, height: 0)
        textView.maxSize = NSSize(width: CGFloat.greatestFiniteMagnitude, height: CGFloat.greatestFiniteMagnitude)
        textView.isVerticallyResizable = true
        textView.isHorizontallyResizable = true
        textView.autoresizingMask = [.width]
        textView.string = text
        return scrollView
    }

    func updateNSView(_ scrollView: NSScrollView, context: Context) {
        guard let textView = scrollView.documentView as? NSTextView else { return }
        guard textView.string != text else { return }
        textView.string = text
        textView.scrollToEndOfDocument(nil)
    }
}
