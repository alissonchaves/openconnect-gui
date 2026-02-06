cask "openconnect-gui" do
  arch arm: "arm64"

  version "1.6.3"
  sha256 :no_check

  url "https://github.com/alissonchaves/openconnect-gui/releases/download/v#{version}/openconnect-gui-#{version}-macos-#{arch}.zip",
      verified: "github.com/alissonchaves/openconnect-gui/"
  name "OpenConnect GUI"
  desc "OpenConnect VPN graphical client"
  homepage "https://gui.openconnect-vpn.net/"

  auto_updates true
  depends_on arch: :arm64
  depends_on macos: ">= :catalina"
  depends_on formula: "openconnect"
  depends_on formula: "openvpn"

  app "OpenConnect-GUI.app"

  zap trash: [
    "~/Library/Application Support/OpenConnect-GUI Team/OpenConnect VPN",
    "~/Library/Preferences/net.openconnect-vpn.gui.plist",
  ]
end
