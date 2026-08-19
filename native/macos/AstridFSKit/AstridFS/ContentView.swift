import SwiftUI

struct ContentView: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Astrid Filesystem")
                .font(.title)
            Text("This app hosts Astrid's native FSKit extension. Mounts are created and authorized by the Astrid CLI.")
            Text("Use `astrid storage mount` in Terminal. Opening this app does not provision or expose storage.")
                .foregroundStyle(.secondary)
        }
        .padding(24)
        .frame(minWidth: 520, minHeight: 180)
    }
}

#Preview {
    ContentView()
}
