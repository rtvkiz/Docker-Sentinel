# Example Homebrew formula for Docker Sentinel
#
# To use this formula:
# 1. Create a homebrew tap repository: github.com/YOUR_USERNAME/homebrew-tap
# 2. Copy this file to Formula/sentinel.rb in that repository
# 3. Update the url, sha256, and homepage with your actual values
# 4. Users can then install with: brew tap YOUR_USERNAME/tap && brew install sentinel
#
# For more info: https://docs.brew.sh/How-to-Create-and-Maintain-a-Tap

class Sentinel < Formula
  desc "Pre-runtime container security for Docker"
  homepage "https://github.com/rtvkiz/docker-sentinel"
  license "MIT"
  version "0.1.0"

  # Update these URLs and checksums for each release
  on_macos do
    on_arm do
      url "https://github.com/rtvkiz/docker-sentinel/releases/download/v#{version}/sentinel-darwin-arm64"
      sha256 "REPLACE_WITH_ACTUAL_SHA256"
    end
    on_intel do
      url "https://github.com/rtvkiz/docker-sentinel/releases/download/v#{version}/sentinel-darwin-amd64"
      sha256 "REPLACE_WITH_ACTUAL_SHA256"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/rtvkiz/docker-sentinel/releases/download/v#{version}/sentinel-linux-arm64"
      sha256 "REPLACE_WITH_ACTUAL_SHA256"
    end
    on_intel do
      url "https://github.com/rtvkiz/docker-sentinel/releases/download/v#{version}/sentinel-linux-amd64"
      sha256 "REPLACE_WITH_ACTUAL_SHA256"
    end
  end

  depends_on "docker" => :optional

  def install
    bin.install Dir["sentinel*"].first => "sentinel"
  end

  def caveats
    <<~EOS
      Docker Sentinel has been installed!

      Quick start:
        # Initialize (creates config and default policies)
        sudo sentinel init

        # Test a Docker command
        sudo sentinel validate -- docker run nginx

        # Run diagnostics
        sudo sentinel doctor

      For more information:
        sentinel --help
        https://github.com/rtvkiz/docker-sentinel
    EOS
  end

  test do
    assert_match "Docker Sentinel", shell_output("#{bin}/sentinel --help")
    assert_match version.to_s, shell_output("#{bin}/sentinel version")
  end
end


# Alternative: Build from source formula
# Use this if you want users to build from source instead of downloading binaries

class SentinelSource < Formula
  desc "Pre-runtime container security for Docker"
  homepage "https://github.com/rtvkiz/docker-sentinel"
  url "https://github.com/rtvkiz/docker-sentinel/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "REPLACE_WITH_ACTUAL_SHA256"
  license "MIT"

  depends_on "go" => :build
  depends_on "docker" => :optional

  def install
    ldflags = %W[
      -s -w
      -X main.version=#{version}
      -X main.gitCommit=#{tap.user}
      -X main.buildDate=#{time.iso8601}
    ]
    system "go", "build", *std_go_args(ldflags: ldflags), "./cmd/sentinel"

    # Generate shell completions
    generate_completions_from_executable(bin/"sentinel", "completion")
  end

  test do
    assert_match "Docker Sentinel", shell_output("#{bin}/sentinel --help")
  end
end
