import Foundation
import AppKit
import Darwin
import OpenConnectCoreC

/// Small ownership wrapper around the native C++ session.
/// Connection orchestration and authentication UI will be moved here next;
/// keeping ownership in Swift first makes the backend transition incremental.
final class CoreNativeSession {
    private var handle: OpaquePointer?
    private var privilegedPipe: FileHandle?
    private var privilegedPID: pid_t = 0
    private var privilegedBuffer = ""
    var onStatus: ((CoreSessionStatus) -> Void)?
    var onLog: ((String) -> Void)?

    init() {
        handle = openconnect_core_session_create()
    }

    deinit {
        disconnect()
        if let handle {
            openconnect_core_session_destroy(handle)
        }
    }

    func disconnect() {
        if privilegedPipe != nil {
            // The helper is root-owned; send the request through its pipe
            // instead of trying to signal it from the unprivileged UI.
            privilegedPipe?.write(Data("DISCONNECT\n".utf8))
        } else if privilegedPID > 0 {
            kill(privilegedPID, SIGTERM)
        }
        if let handle {
            openconnect_core_session_disconnect(handle)
        }
    }

    func connect(profile: VPNProfile) -> Bool {
        if profile.protocolName.caseInsensitiveCompare("openvpn") == .orderedSame {
            return connectOpenVPN(profile: profile)
        }
        if let helper = Self.locatePrivilegedHelper() {
            return connectPrivileged(profile: profile, helper: helper)
        }

        guard let handle else { return false }
        var error = Array(repeating: CChar(0), count: 1024)
        var result = false
        let script = Self.locateVPNCScript()

        script.withCString { scriptPath in
            profile.gateway.withCString { gateway in
                profile.protocolName.withCString { protocolName in
                    profile.username.withCString { username in
                        profile.password.withCString { password in
                        var value = openconnect_core_profile(
                            gateway: gateway,
                            protocol: protocolName,
                            username: username,
                            password: password,
                            group: nil,
                            token: nil,
                            vpnc_script: scriptPath,
                            disable_udp: 0,
                            dtls_reconnect_timeout: 25,
                            reconnect_timeout: 300,
                            log_level: -1
                        )
                        var callbacks = openconnect_core_callbacks(
                            context: Unmanaged.passUnretained(self).toOpaque(),
                            auth: coreAuthCallback,
                            status: coreStatusCallback,
                            log: coreLogCallback
                        )
                        result = openconnect_core_session_connect(
                            handle, &value, &callbacks, &error, UInt32(error.count)) != 0
                        }
                    }
                }
            }
        }

        if !result {
            let message = String(cString: error)
            if !message.isEmpty { onLog?(message) }
        }
        return result
    }

    private func connectPrivileged(profile: VPNProfile, helper: String) -> Bool {
        let script = Self.locateVPNCScript()
        var descriptor: Int32 = -1
        var status: Int32 = 0

        helper.withCString { tool in
            profile.gateway.withCString { gateway in
                profile.protocolName.withCString { protocolName in
                    profile.username.withCString { username in
                        profile.password.withCString { password in
                            script.withCString { scriptPath in
                                status = native_privilege_launch(
                                    tool, gateway, protocolName, scriptPath, &descriptor
                                )
                            }
                        }
                    }
                }
            }
        }

        guard status == 0, descriptor >= 0 else {
            onLog?("Administrator authorization was cancelled or failed (status \(status))")
            return false
        }

        attachPrivilegedPipe(FileHandle(fileDescriptor: descriptor, closeOnDealloc: true),
            initialInput: profile.username + "\n" + profile.password + "\n")
        return true
    }

    private func connectOpenVPN(profile: VPNProfile) -> Bool {
        guard !profile.openvpnConfigPath.isEmpty,
              let helper = Self.locateHelper(named: "openvpn-core-helper") else {
            onLog?("OpenVPN helper or configuration file is unavailable")
            return false
        }

        var descriptor: Int32 = -1
        var status: Int32 = 0
        helper.withCString { tool in
            profile.openvpnConfigPath.withCString { config in
                status = native_privilege_launch_openvpn(tool, config, &descriptor)
            }
        }
        guard status == 0, descriptor >= 0 else {
            onLog?("Administrator authorization for OpenVPN failed (status \(status))")
            return false
        }
        attachPrivilegedPipe(FileHandle(fileDescriptor: descriptor, closeOnDealloc: true),
            initialInput: profile.username + "\n" + profile.password + "\n")
        return true
    }

    private func attachPrivilegedPipe(_ pipe: FileHandle, initialInput: String) {
        privilegedPipe = pipe
        pipe.write(Data(initialInput.utf8))
        pipe.readabilityHandler = { [weak self, weak pipe] handle in
            guard let self else { return }
            let data = handle.availableData
            if data.isEmpty {
                pipe?.readabilityHandler = nil
                self.privilegedPipe = nil
                self.privilegedPID = 0
                DispatchQueue.main.async {
                    self.onStatus?(CoreSessionStatus(state: .disconnected, ipv4: "", ipv6: "", dns: "", dnsSearch: "", cipher: "", dtlsCipher: "", uploaded: 0, downloaded: 0))
                }
                return
            }
            self.consumePrivilegedOutput(data)
        }
    }

    private func consumePrivilegedOutput(_ data: Data) {
        privilegedBuffer += String(decoding: data, as: UTF8.self)
        while let newline = privilegedBuffer.firstIndex(of: "\n") {
            let line = String(privilegedBuffer[..<newline])
            privilegedBuffer.removeSubrange(...newline)
            handlePrivilegedLine(line)
        }
    }

    private func handlePrivilegedLine(_ line: String) {
        let fields = line.split(separator: "\t", omittingEmptySubsequences: false).map(String.init)
        guard let kind = fields.first else { return }
        switch kind {
        case "PID":
            if fields.count > 1 { privilegedPID = pid_t(fields[1]) ?? 0 }
        case "LOG":
            if fields.count > 1 { DispatchQueue.main.async { self.onLog?(fields.dropFirst().joined(separator: "\t")) } }
        case "ERROR":
            if fields.count > 1 { DispatchQueue.main.async { self.onLog?(fields.dropFirst().joined(separator: "\t")) } }
        case "AUTH":
            let secret = fields.count > 1 && fields[1] == "1"
            let prompt = fields.count > 2 ? fields.dropFirst(2).joined(separator: "\t") : "VPN authentication"
            let response = requestAuthentication(prompt: prompt, secret: secret) ?? ""
            if let privilegedPipe {
                privilegedPipe.write(Data((response + "\n").utf8))
            }
        case "STATUS":
            guard fields.count >= 10, let rawState = Int32(fields[1]) else { return }
            let state: VPNConnectionState
            switch rawState {
            case 0: state = .disconnecting
            case 2: state = .connecting
            case 3: state = .connected
            default: state = .disconnected
            }
            let status = CoreSessionStatus(
                state: state,
                ipv4: fields[2], ipv6: fields[3], dns: fields[4],
                dnsSearch: fields[5], cipher: fields[6], dtlsCipher: fields[7],
                uploaded: UInt64(fields[8]) ?? 0,
                downloaded: UInt64(fields[9]) ?? 0
            )
            DispatchQueue.main.async { self.onStatus?(status) }
        default:
            break
        }
    }

    private static func locatePrivilegedHelper() -> String? {
        locateHelper(named: "openconnect-core-helper")
    }

    private static func locateHelper(named name: String) -> String? {
        let environment = ProcessInfo.processInfo.environment
        var candidates: [String] = []
        if name == "openconnect-core-helper", let configured = environment["OPENCONNECT_CORE_HELPER"] { candidates.append(configured) }
        if name == "openvpn-core-helper", let configured = environment["OPENVPN_CORE_HELPER"] { candidates.append(configured) }
        if let bundled = Bundle.main.path(forResource: name, ofType: nil) { candidates.append(bundled) }
        candidates.append(Bundle.main.bundleURL.appendingPathComponent("Contents/MacOS/\(name)").path)
        return candidates.first(where: { FileManager.default.isExecutableFile(atPath: $0) })
    }

    private static func locateVPNCScript() -> String {
        let environment = ProcessInfo.processInfo.environment
        if let configured = environment["OPENCONNECT_VPNC_SCRIPT"],
           FileManager.default.isExecutableFile(atPath: configured) {
            return configured
        }

        if let bundled = Bundle.main.path(forResource: "vpnc-script", ofType: nil),
           FileManager.default.isExecutableFile(atPath: bundled) {
            return bundled
        }

        let candidates = [
            "/opt/homebrew/etc/vpnc/vpnc-script",
            "/usr/local/etc/vpnc/vpnc-script",
            "/usr/share/vpnc-scripts/vpnc-script"
        ]
        return candidates.first(where: {
            FileManager.default.isExecutableFile(atPath: $0)
        }) ?? "vpnc-script"
    }

    func run() {
        if privilegedPipe != nil { return }
        if let handle { openconnect_core_session_run(handle) }
    }

    fileprivate func requestAuthentication(prompt: String, secret: Bool) -> String? {
        let present: () -> String? = {
            let alert = NSAlert()
            alert.messageText = prompt.isEmpty ? "VPN authentication" : prompt
            alert.informativeText = "Enter the value requested by the VPN server."
            alert.addButton(withTitle: "Continue")
            alert.addButton(withTitle: "Cancel")

            let field: NSTextField = secret ? NSSecureTextField() : NSTextField()
            field.frame = NSRect(x: 0, y: 0, width: 280, height: 24)
            alert.accessoryView = field

            guard alert.runModal() == .alertFirstButtonReturn else { return nil }
            return field.stringValue
        }

        if Thread.isMainThread {
            return present()
        }
        var result: String?
        DispatchQueue.main.sync {
            result = present()
        }
        return result
    }
}

struct CoreSessionStatus {
    let state: VPNConnectionState
    let ipv4: String
    let ipv6: String
    let dns: String
    let dnsSearch: String
    let cipher: String
    let dtlsCipher: String
    let uploaded: UInt64
    let downloaded: UInt64
}

private func coreAuthCallback(_ context: UnsafeMutableRawPointer?,
                              _ prompt: UnsafePointer<CChar>?,
                              _ secret: Int32,
                              _ value: UnsafeMutablePointer<CChar>?,
                              _ valueSize: UInt32) -> Int32 {
    guard let context, let prompt, let value, valueSize > 0 else { return 0 }
    let session = Unmanaged<CoreNativeSession>.fromOpaque(context).takeUnretainedValue()
    guard let response = session.requestAuthentication(prompt: String(cString: prompt), secret: secret != 0) else {
        return 0
    }
    let bytes = Array(response.utf8)
    let count = min(bytes.count, Int(valueSize) - 1)
    for (index, byte) in bytes.prefix(count).enumerated() {
        value[index] = CChar(byte)
    }
    value[count] = 0
    return 1
}

private func coreStatusCallback(_ context: UnsafeMutableRawPointer?,
                                _ status: UnsafePointer<openconnect_core_status>?) {
    guard let context, let status else { return }
    let value = status.pointee
    let state: VPNConnectionState
    switch value.state {
    case OPENCONNECT_CORE_CONNECTING: state = .connecting
    case OPENCONNECT_CORE_CONNECTED: state = .connected
    case OPENCONNECT_CORE_DISCONNECTING: state = .disconnecting
    default: state = .disconnected
    }
    let result = CoreSessionStatus(
        state: state,
        ipv4: value.ipv4.map(String.init(cString:)) ?? "",
        ipv6: value.ipv6.map(String.init(cString:)) ?? "",
        dns: value.dns.map(String.init(cString:)) ?? "",
        dnsSearch: value.dns_search.map(String.init(cString:)) ?? "",
        cipher: value.cstp_cipher.map(String.init(cString:)) ?? "",
        dtlsCipher: value.dtls_cipher.map(String.init(cString:)) ?? "",
        uploaded: value.uploaded_bytes,
        downloaded: value.downloaded_bytes
    )
    Unmanaged<CoreNativeSession>.fromOpaque(context).takeUnretainedValue().onStatus?(result)
}

private func coreLogCallback(_ context: UnsafeMutableRawPointer?,
                             _ message: UnsafePointer<CChar>?) {
    guard let context, let message else { return }
    Unmanaged<CoreNativeSession>.fromOpaque(context).takeUnretainedValue().onLog?(String(cString: message))
}
