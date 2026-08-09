import SwiftUI
import AppKit

struct AppIconView: View {
    let size: CGFloat
    let state: VPNConnectionState?

    init(size: CGFloat, state: VPNConnectionState? = nil) {
        self.size = size
        self.state = state
    }

    var body: some View {
        ZStack(alignment: .bottomTrailing) {
            Image(nsImage: NSApp.applicationIconImage)
                .resizable()
                .interpolation(.high)
                .aspectRatio(contentMode: .fit)
                .frame(width: size, height: size)
            if let state {
                Circle()
                    .fill(state.iconColor)
                    .frame(width: max(7, size * 0.25), height: max(7, size * 0.25))
                    .overlay(Circle().stroke(.black.opacity(0.35), lineWidth: 1))
            }
        }
        .frame(width: size, height: size)
    }
}

private extension VPNConnectionState {
    var iconColor: Color {
        switch self {
        case .connected: return .green
        case .connecting: return .yellow
        case .disconnecting: return .orange
        case .disconnected: return .gray
        }
    }
}
