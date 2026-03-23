class Querylens < Formula
  desc "Static SQL inspection and optional LLM-backed explanations"
  homepage "https://github.com/kraftaa/querylens"
  version "0.1.13"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/kraftaa/querylens/releases/download/v#{version}/querylens-macos-aarch64.tar.gz"
      sha256 "__SHA256_MACOS_AARCH64__"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/kraftaa/querylens/releases/download/v#{version}/querylens-linux-x86_64.tar.gz"
      sha256 "__SHA256_LINUX_X86_64__"
    end
  end

  def install
    bin.install "querylens"
  end

  test do
    output = shell_output("#{bin}/querylens --help")
    assert_match "querylens", output
  end
end
