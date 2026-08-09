require "fileutils"

cask "openconnect-gui" do
  arch arm: "arm64"

  version "2.0.0"
  sha256 "7203edce9f44105c3d5793d2d168d4767530a6220a19cfbf848bd846ba650b5a"

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
      "#{Dir.home}/Applications/OpenConnect-GUI.app",
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
