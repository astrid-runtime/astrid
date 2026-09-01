import AppKit

/// The macOS-required container for Astrid's FSKit extension.
///
/// Storage lifecycle is controlled exclusively by `astrid storage`. The
/// containing process has no scenes, windows, menu-bar item, or Dock presence.
@main
enum AstridFSApp {
    static func main() {
        let application = NSApplication.shared
        application.setActivationPolicy(.prohibited)
        application.run()
    }
}
