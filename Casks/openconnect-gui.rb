cask "openconnect-gui" do
  arch arm: "arm64"

  version "1.6.3"
  sha256 :no_check

  url "https://gitlab.com/alissonchaves/openconnect-gui/-/jobs/artifacts/v#{version}/raw/build/openconnect-gui-#{version}-macos-#{arch}.zip?job=MacOSRelease",
      verified: "gitlab.com/alissonchaves/openconnect-gui/"
  name "OpenConnect GUI"
  desc "OpenConnect VPN graphical client"
  homepage "https://gui.openconnect-vpn.net/"

  auto_updates true
  depends_on arch: :arm64
  depends_on macos: ">= :catalina"

  app "OpenConnect-GUI.app"

  zap trash: [
    "~/Library/Application Support/OpenConnect-GUI Team/OpenConnect VPN",
    "~/Library/Preferences/net.openconnect-vpn.gui.plist",
  ]
end
