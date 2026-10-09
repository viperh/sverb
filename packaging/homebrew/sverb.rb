# M7-07: Homebrew formula for the `viperh/homebrew-sverb` tap (SPEC §20).
#
#   brew install viperh/sverb/sverb
#
# It installs the prebuilt release archives (macOS universal, Linux static musl).
# `scripts/update-packaging.py` sets the version and checksums on every release and the
# release workflow pushes the result to the tap repository as Formula/sverb.rb.
class Sverb < Formula
  desc "Terminal-native SSH client and server manager with an encrypted vault"
  homepage "https://github.com/viperh/sverb"
  version "0.1.0"
  license "MIT"

  on_macos do
    url "https://github.com/viperh/sverb/releases/download/v0.1.0/sverb-0.1.0-macos-universal.tar.gz"
    sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  end

  on_linux do
    on_intel do
      url "https://github.com/viperh/sverb/releases/download/v0.1.0/sverb-0.1.0-linux-x86_64.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
    on_arm do
      url "https://github.com/viperh/sverb/releases/download/v0.1.0/sverb-0.1.0-linux-aarch64.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  def install
    bin.install "sverb"
    man1.install "man/sverb.1"
    bash_completion.install "completions/sverb.bash" => "sverb"
    zsh_completion.install "completions/_sverb"
    fish_completion.install "completions/sverb.fish"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/sverb --version")
    ENV["SVERB_HOME"] = testpath.to_s
    ENV["SVERB_KEYRING"] = "off"
    assert_match "[general]", shell_output("#{bin}/sverb config --print-default")
  end
end
