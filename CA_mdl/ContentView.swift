import SwiftUI

// ContentView is no longer the root; HomeView is injected directly from CA_mdlApp.
// This file is kept as a stub to satisfy any storyboard or preview references.
struct ContentView: View {
    var body: some View {
        HomeView()
    }
}

#Preview {
    ContentView()
        .environment(MdlVerificationSession())
}
