require "fileutils"

cask "openconnect-gui" do
  arch arm: "arm64"

  version "2.1.0"
  sha256 "540be342f2b5141a77c2bf3a928b65c6a3463a28be86fe2d3824c83507aa0a14"

  url "https://github.com/alissonchaves/openconnect-gui/releases/download/v#{version}/openconnect-gui-#{version}-macos-#{arch}.zip",
      verified: "github.com/alissonchaves/openconnect-gui/"
  name "OpenConnect for Mac"
  desc "Native macOS client for OpenConnect and OpenVPN"
  homepage "https://gui.openconnect-vpn.net/"

  depends_on arch: :arm64
  depends_on macos: :tahoe

  preflight do
    legacy_paths = [
      "/Applications/OpenConnect-GUI.app",
      "/Applications/OpenConnectMac.app",
      "#{Dir.home}/Applications/OpenConnect-GUI.app",
      "#{Dir.home}/Applications/OpenConnectMac.app",
      "#{Dir.home}/Library/Application Support/OpenConnect-GUI Team/OpenConnect-GUI",
      "#{Dir.home}/Library/Application Support/OpenConnect-GUI Team/OpenConnect VPN",
      "#{Dir.home}/Library/Preferences/gui.openconnect-vpn.net.OpenConnect-GUI.plist",
      "#{Dir.home}/Library/Preferences/OpenConnect-GUI Team.OpenConnect-GUI.plist",
    ]
    legacy_paths.each { |path| FileUtils.rm_rf(path) if File.exist?(path) }
  end

  app "OpenConnectMac.app", target: "OpenConnect for Mac.app"

  zap trash: [
    "~/Library/Application Support/OpenConnect VPN",
    "~/Library/Preferences/net.openconnect-vpn.gui.plist",
    "~/Library/Preferences/net.openconnect-vpn.gui.native.notifications.plist",
  ]
end
