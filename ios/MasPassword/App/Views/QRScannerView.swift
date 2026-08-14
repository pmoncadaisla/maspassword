import SwiftUI
import UIKit
import AVFoundation

/// AVFoundation-based QR scanner. Emits every decoded QR string through
/// `onCode`; the caller decides whether it parses as a pairing payload.
/// Camera permission is requested lazily; when denied the view shows a hint
/// (the Link screen always offers manual paste as the fallback).
struct QRScannerView: UIViewRepresentable {
    let onCode: (String) -> Void

    func makeUIView(context: Context) -> ScannerPreviewView {
        let view = ScannerPreviewView()
        view.coordinator = context.coordinator
        context.coordinator.startSession(on: view)
        return view
    }

    func updateUIView(_ uiView: ScannerPreviewView, context: Context) {}

    static func dismantleUIView(_ uiView: ScannerPreviewView, coordinator: Coordinator) {
        coordinator.stopSession()
    }

    func makeCoordinator() -> Coordinator {
        Coordinator(onCode: onCode)
    }

    final class Coordinator: NSObject, AVCaptureMetadataOutputObjectsDelegate {
        private let onCode: (String) -> Void
        private let session = AVCaptureSession()
        private let sessionQueue = DispatchQueue(label: "mp.qr.session")
        private var lastEmitted: String?

        init(onCode: @escaping (String) -> Void) {
            self.onCode = onCode
        }

        func startSession(on view: ScannerPreviewView) {
            AVCaptureDevice.requestAccess(for: .video) { [weak self] granted in
                guard let self, granted else {
                    DispatchQueue.main.async { view.showDeniedHint() }
                    return
                }
                self.sessionQueue.async {
                    self.configureSession()
                    DispatchQueue.main.async {
                        view.attach(session: self.session)
                    }
                    self.session.startRunning()
                }
            }
        }

        func stopSession() {
            sessionQueue.async { [session] in
                if session.isRunning { session.stopRunning() }
            }
        }

        private func configureSession() {
            guard session.inputs.isEmpty,
                  let device = AVCaptureDevice.default(for: .video),
                  let input = try? AVCaptureDeviceInput(device: device),
                  session.canAddInput(input) else { return }
            session.beginConfiguration()
            session.addInput(input)
            let output = AVCaptureMetadataOutput()
            if session.canAddOutput(output) {
                session.addOutput(output)
                output.setMetadataObjectsDelegate(self, queue: .main)
                if output.availableMetadataObjectTypes.contains(.qr) {
                    output.metadataObjectTypes = [.qr]
                }
            }
            session.commitConfiguration()
        }

        func metadataOutput(_ output: AVCaptureMetadataOutput,
                            didOutput metadataObjects: [AVMetadataObject],
                            from connection: AVCaptureConnection) {
            guard let object = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
                  object.type == .qr,
                  let value = object.stringValue, !value.isEmpty,
                  value != lastEmitted else { return }
            lastEmitted = value
            onCode(value)
        }
    }

    /// UIView hosting the camera preview layer.
    final class ScannerPreviewView: UIView {
        weak var coordinator: Coordinator?
        private var previewLayer: AVCaptureVideoPreviewLayer?
        private let hintLabel = UILabel()

        override init(frame: CGRect) {
            super.init(frame: frame)
            backgroundColor = .black
            hintLabel.text = "Camera access denied.\nPaste the code below instead."
            hintLabel.textColor = .white
            hintLabel.numberOfLines = 0
            hintLabel.textAlignment = .center
            hintLabel.isHidden = true
            hintLabel.translatesAutoresizingMaskIntoConstraints = false
            addSubview(hintLabel)
            NSLayoutConstraint.activate([
                hintLabel.centerXAnchor.constraint(equalTo: centerXAnchor),
                hintLabel.centerYAnchor.constraint(equalTo: centerYAnchor),
                hintLabel.leadingAnchor.constraint(greaterThanOrEqualTo: leadingAnchor, constant: 16),
            ])
        }

        required init?(coder: NSCoder) { fatalError("init(coder:) is not used") }

        func attach(session: AVCaptureSession) {
            let layer = AVCaptureVideoPreviewLayer(session: session)
            layer.videoGravity = .resizeAspectFill
            layer.frame = bounds
            self.layer.addSublayer(layer)
            previewLayer = layer
        }

        func showDeniedHint() {
            hintLabel.isHidden = false
        }

        override func layoutSubviews() {
            super.layoutSubviews()
            previewLayer?.frame = bounds
        }
    }
}
