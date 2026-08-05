import SwiftUI

@main
struct CA_mdlApp: App {
    @State private var session = MdlVerificationSession()

    var body: some Scene {
        WindowGroup {
            HomeView()
                .environment(session)
        }
    }
}
