import SwiftUI

@main
struct MasPasswordApp: App {
    @StateObject private var appState = AppState()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(appState)
                .onChange(of: scenePhase) { newPhase in
                    appState.handleScenePhase(newPhase)
                }
        }
    }
}

/// Phase switch: link wizard / master-password unlock / vault browser,
/// with the biometric curtain overlaid while re-gating.
struct RootView: View {
    @EnvironmentObject private var appState: AppState

    var body: some View {
        ZStack {
            switch appState.phase {
            case .unlinked:
                LinkView()
            case .locked:
                UnlockView()
            case .unlocked:
                VaultsView()
            }

            if appState.biometricallyCovered {
                BiometricCurtain()
            }
        }
        .animation(.default, value: appState.phase)
    }
}

/// Opaque cover shown over an unlocked app until Face ID / passcode succeeds.
struct BiometricCurtain: View {
    var body: some View {
        ZStack {
            Rectangle().fill(.ultraThinMaterial).ignoresSafeArea()
            VStack(spacing: 12) {
                Image(systemName: "lock.fill").font(.system(size: 42))
                Text("MasPassword is locked").font(.headline)
            }
        }
        .transition(.opacity)
    }
}
