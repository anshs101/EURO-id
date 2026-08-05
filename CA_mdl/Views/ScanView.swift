import SwiftUI
import AVFoundation

// MARK: - SessionFlowView
// Single view that hosts all post-idle states so there are no nested sheets.

struct SessionFlowView: View {
    @Environment(MdlVerificationSession.self) private var session

    var body: some View {
        switch session.state {
        case .idle:
            EmptyView()

        case .scanning:
            ScanView()

        case .connecting, .exchanging, .verifying:
            ConnectingView()

        case .verified(let doc):
            VerificationView(document: doc)

        case .failed(let msg):
            FailureView(message: msg)
        }
    }
}

// MARK: - ScanView

struct ScanView: View {
    @Environment(MdlVerificationSession.self) private var session

    var body: some View {
        ZStack {
            CameraPreview { code in
                session.handleQRCode(code)
            }
            .ignoresSafeArea()

            VStack {
                HStack {
                    Spacer()
                    Button {
                        session.cancel()
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                            .font(.title)
                            .foregroundStyle(.white)
                            .symbolRenderingMode(.hierarchical)
                    }
                    .padding()
                }

                Spacer()

                finderOverlay

                Spacer()

                VStack(spacing: 8) {
                    Text("Point at the holder's mDL QR code")
                        .font(.headline)
                        .foregroundStyle(.white)
                    Text("Shown in the CA DMV Wallet app under \"Share mDL\".")
                        .font(.caption)
                        .foregroundStyle(.white.opacity(0.8))
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 32)
                }
                .padding(.bottom, 48)
            }
        }
    }

    private var finderOverlay: some View {
        ZStack {
            Color.black.opacity(0.4).ignoresSafeArea()
                .mask(
                    Rectangle()
                        .overlay(
                            RoundedRectangle(cornerRadius: 14)
                                .frame(width: 250, height: 250)
                                .blendMode(.destinationOut)
                        )
                        .compositingGroup()
                )

            RoundedRectangle(cornerRadius: 14)
                .stroke(.white, lineWidth: 2)
                .frame(width: 250, height: 250)
        }
    }
}

// MARK: - ConnectingView

struct ConnectingView: View {
    @Environment(MdlVerificationSession.self) private var session

    var body: some View {
        VStack(spacing: 24) {
            Spacer()
            ProgressView()
                .controlSize(.large)
                .tint(.blue)
            Text(session.state.statusMessage)
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 32)
            Spacer()
            Button("Cancel") { session.cancel() }
                .foregroundStyle(.secondary)
                .padding(.bottom, 40)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(.background)
    }
}

// MARK: - FailureView

struct FailureView: View {
    let message: String
    @Environment(MdlVerificationSession.self) private var session

    var body: some View {
        VStack(spacing: 20) {
            Spacer()
            Image(systemName: "xmark.circle.fill")
                .font(.system(size: 64))
                .foregroundStyle(.red)
            Text("Verification Failed")
                .font(.title2.bold())
            Text(message)
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 32)
            Spacer()
            VStack(spacing: 12) {
                Button("Try Again") {
                    session.startScanning()
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .frame(maxWidth: .infinity)

                Button("Close") {
                    session.reset()
                }
                .foregroundStyle(.secondary)
            }
            .padding(.horizontal, 32)
            .padding(.bottom, 40)
        }
    }
}

// MARK: - Camera QR Preview (UIKit bridge)

struct CameraPreview: UIViewControllerRepresentable {
    var onCode: (String) -> Void

    func makeCoordinator() -> Coordinator { Coordinator(onCode: onCode) }

    func makeUIViewController(context: Context) -> CameraViewController {
        let vc = CameraViewController()
        vc.delegate = context.coordinator
        return vc
    }

    func updateUIViewController(_ vc: CameraViewController, context: Context) {}

    final class Coordinator: NSObject, CameraViewControllerDelegate {
        let onCode: (String) -> Void
        init(onCode: @escaping (String) -> Void) { self.onCode = onCode }
        nonisolated func didDetect(code: String) {
            Task { @MainActor in self.onCode(code) }
        }
    }
}

protocol CameraViewControllerDelegate: AnyObject {
    func didDetect(code: String)
}

final class CameraViewController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    weak var delegate: CameraViewControllerDelegate?

    private let captureSession = AVCaptureSession()
    private var previewLayer: AVCaptureVideoPreviewLayer?
    private var hasDetected = false

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        setupCapture()
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        hasDetected = false
        if !captureSession.isRunning {
            DispatchQueue.global(qos: .userInitiated).async { self.captureSession.startRunning() }
        }
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        if captureSession.isRunning { captureSession.stopRunning() }
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        previewLayer?.frame = view.layer.bounds
    }

    private func setupCapture() {
        guard let device = AVCaptureDevice.default(for: .video),
              let input = try? AVCaptureDeviceInput(device: device),
              captureSession.canAddInput(input) else { return }
        captureSession.addInput(input)

        let output = AVCaptureMetadataOutput()
        guard captureSession.canAddOutput(output) else { return }
        captureSession.addOutput(output)
        output.setMetadataObjectsDelegate(self, queue: .main)
        output.metadataObjectTypes = [.qr]

        let preview = AVCaptureVideoPreviewLayer(session: captureSession)
        preview.videoGravity = .resizeAspectFill
        preview.frame = view.layer.bounds
        view.layer.addSublayer(preview)
        previewLayer = preview
    }

    // AVCaptureMetadataOutputObjectsDelegate — called on main queue
    func metadataOutput(
        _ output: AVCaptureMetadataOutput,
        didOutput metadataObjects: [AVMetadataObject],
        from connection: AVCaptureConnection
    ) {
        guard !hasDetected,
              let code = (metadataObjects.first as? AVMetadataMachineReadableCodeObject)?.stringValue,
              code.hasPrefix("mdoc:") else { return }
        hasDetected = true
        captureSession.stopRunning()
        delegate?.didDetect(code: code)
    }
}
