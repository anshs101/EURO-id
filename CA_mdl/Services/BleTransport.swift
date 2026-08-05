import Foundation
import CoreBluetooth

// ISO 18013-5 Annex B — BLE Central Client mode transport
// The verifier is the BLE central; the mDL holder's device is the peripheral.
@MainActor
final class BleTransport: NSObject {

    // Resolved when the full exchange is complete or fails
    private var continuation: CheckedContinuation<Data, Error>?

    private var central: CBCentralManager!
    private var peripheral: CBPeripheral?

    // BLE characteristics discovered on the holder's peripheral
    private var stateChar: CBCharacteristic?
    private var client2Server: CBCharacteristic?
    private var server2Client: CBCharacteristic?
    private var identChar: CBCharacteristic?

    // Data to send once the channel is ready
    private var pendingRequest = Data()
    private var mtuPayload = 20   // conservative; updated after connection

    // Reassembly buffer for incoming chunks
    private var receiveBuffer = Data()

    // Timeout watchdog
    private var timeoutTask: Task<Void, Never>?

    static let sessionTimeout: TimeInterval = 30

    override init() {
        super.init()
        central = CBCentralManager(delegate: self, queue: DispatchQueue.main)
    }

    // Perform the full BLE exchange: send request, receive response.
    func exchange(
        request: Data,
        engagement: DeviceEngagement
    ) async throws -> Data {
        guard engagement.retrievalMethods.contains(where: {
            if case .ble(let o) = $0 { return o.peripheralServerMode }
            return false
        }) else {
            throw MdlError.unsupportedTransport
        }

        pendingRequest = request

        return try await withCheckedThrowingContinuation { [weak self] cont in
            self?.continuation = cont
            self?.armTimeout()
            if self?.central.state == .poweredOn {
                self?.startScan()
            }
            // If BT is not yet ready, startScan() will be called from centralManagerDidUpdateState
        }
    }

    // MARK: - Internal helpers

    private func startScan() {
        central.scanForPeripherals(
            withServices: [IsoMdl.BLE.peripheralServerService],
            options: [CBCentralManagerScanOptionAllowDuplicatesKey: false]
        )
    }

    private func sendChunked(_ data: Data) {
        guard let peripheral, let char = client2Server else { return }
        // maximumWriteValueLength already strips the ATT header; subtract 1 for our frame byte
        let maxPayload = max(20, mtuPayload)
        var offset = 0
        let bytes = [UInt8](data)
        while offset < bytes.count {
            let remaining = bytes.count - offset
            let chunkSize = min(maxPayload - 1, remaining)  // –1 for frame byte
            let isLast = (offset + chunkSize >= bytes.count)
            var frame = Data([isLast ? IsoMdl.BLE.frameLast : IsoMdl.BLE.frameMore])
            frame.append(contentsOf: bytes[offset ..< offset + chunkSize])
            peripheral.writeValue(frame, for: char, type: .withoutResponse)
            offset += chunkSize
        }
    }

    private func appendReceived(_ frame: Data) {
        guard !frame.isEmpty else { return }
        let flag = frame[0]
        receiveBuffer.append(frame.dropFirst())
        if flag == IsoMdl.BLE.frameLast {
            // Full message assembled
            let response = receiveBuffer
            receiveBuffer = Data()
            cancelTimeout()
            // Signal end of session before resolving
            if let char = stateChar {
                peripheral?.writeValue(Data([IsoMdl.BLE.stateEnd]), for: char, type: .withResponse)
            }
            central.stopScan()
            if let p = peripheral { central.cancelPeripheralConnection(p) }
            continuation?.resume(returning: response)
            continuation = nil
        }
    }

    private func fail(_ error: Error) {
        cancelTimeout()
        central.stopScan()
        if let p = peripheral { central.cancelPeripheralConnection(p) }
        continuation?.resume(throwing: error)
        continuation = nil
    }

    private func armTimeout() {
        timeoutTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(BleTransport.sessionTimeout))
            if !Task.isCancelled {
                await self?.fail(MdlError.connectionTimeout)
            }
        }
    }

    private func cancelTimeout() {
        timeoutTask?.cancel()
        timeoutTask = nil
    }
}

// MARK: - CBCentralManagerDelegate

extension BleTransport: CBCentralManagerDelegate {
    nonisolated func centralManagerDidUpdateState(_ central: CBCentralManager) {
        Task { @MainActor [weak self] in
            guard let self else { return }
            if central.state == .poweredOn, self.continuation != nil {
                self.startScan()
            } else if central.state != .poweredOn, self.continuation != nil {
                self.fail(MdlError.bluetoothUnavailable)
            }
        }
    }

    nonisolated func centralManager(
        _ central: CBCentralManager,
        didDiscover peripheral: CBPeripheral,
        advertisementData: [String: Any],
        rssi RSSI: NSNumber
    ) {
        Task { @MainActor [weak self] in
            guard let self, self.continuation != nil, self.peripheral == nil else { return }
            central.stopScan()
            self.peripheral = peripheral
            peripheral.delegate = self
            central.connect(peripheral, options: nil)
        }
    }

    nonisolated func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        Task { @MainActor [weak self] in
            guard let self else { return }
            // Negotiate MTU (iOS automatically negotiates; read the result)
            self.mtuPayload = peripheral.maximumWriteValueLength(for: .withoutResponse)
            peripheral.discoverServices([IsoMdl.BLE.peripheralServerService])
        }
    }

    nonisolated func centralManager(
        _ central: CBCentralManager,
        didFailToConnect peripheral: CBPeripheral,
        error: Error?
    ) {
        Task { @MainActor [weak self] in
            self?.fail(MdlError.connectionFailed(error?.localizedDescription ?? "Unknown"))
        }
    }

    nonisolated func centralManager(
        _ central: CBCentralManager,
        didDisconnectPeripheral peripheral: CBPeripheral,
        error: Error?
    ) {
        Task { @MainActor [weak self] in
            guard let self, self.continuation != nil else { return }
            if let error {
                self.fail(MdlError.connectionFailed(error.localizedDescription))
            }
        }
    }
}

// MARK: - CBPeripheralDelegate

extension BleTransport: CBPeripheralDelegate {
    nonisolated func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        Task { @MainActor [weak self] in
            guard let self else { return }
            if let error {
                self.fail(MdlError.connectionFailed(error.localizedDescription)); return
            }
            guard let service = peripheral.services?.first(where: {
                $0.uuid == IsoMdl.BLE.peripheralServerService
            }) else {
                self.fail(MdlError.connectionFailed("mDL service not found")); return
            }
            peripheral.discoverCharacteristics([
                IsoMdl.BLE.stateChar,
                IsoMdl.BLE.client2ServerChar,
                IsoMdl.BLE.server2ClientChar,
                IsoMdl.BLE.identChar,
            ], for: service)
        }
    }

    nonisolated func peripheral(
        _ peripheral: CBPeripheral,
        didDiscoverCharacteristicsFor service: CBService,
        error: Error?
    ) {
        Task { @MainActor [weak self] in
            guard let self else { return }
            if let error { self.fail(MdlError.connectionFailed(error.localizedDescription)); return }

            for char in service.characteristics ?? [] {
                switch char.uuid {
                case IsoMdl.BLE.stateChar:        self.stateChar = char
                case IsoMdl.BLE.client2ServerChar: self.client2Server = char
                case IsoMdl.BLE.server2ClientChar: self.server2Client = char
                case IsoMdl.BLE.identChar:         self.identChar = char
                default: break
                }
            }

            guard self.stateChar != nil, self.client2Server != nil, self.server2Client != nil else {
                self.fail(MdlError.connectionFailed("Required BLE characteristics not found")); return
            }

            // Subscribe to Server2Client notifications
            peripheral.setNotifyValue(true, for: self.server2Client!)
        }
    }

    nonisolated func peripheral(
        _ peripheral: CBPeripheral,
        didUpdateNotificationStateFor characteristic: CBCharacteristic,
        error: Error?
    ) {
        Task { @MainActor [weak self] in
            guard let self else { return }
            if let error { self.fail(MdlError.connectionFailed(error.localizedDescription)); return }
            if characteristic.uuid == IsoMdl.BLE.server2ClientChar, characteristic.isNotifying {
                // Write state = 0x01 (start), then send the session establishment
                if let stateChar = self.stateChar {
                    peripheral.writeValue(Data([IsoMdl.BLE.stateStart]), for: stateChar, type: .withResponse)
                }
                self.sendChunked(self.pendingRequest)
            }
        }
    }

    nonisolated func peripheral(
        _ peripheral: CBPeripheral,
        didUpdateValueFor characteristic: CBCharacteristic,
        error: Error?
    ) {
        Task { @MainActor [weak self] in
            guard let self else { return }
            if let error { self.fail(MdlError.transferFailed(error.localizedDescription)); return }
            if characteristic.uuid == IsoMdl.BLE.server2ClientChar,
               let value = characteristic.value {
                self.appendReceived(value)
            }
        }
    }

    nonisolated func peripheral(
        _ peripheral: CBPeripheral,
        didWriteValueFor characteristic: CBCharacteristic,
        error: Error?
    ) {
        Task { @MainActor [weak self] in
            if let error {
                self?.fail(MdlError.transferFailed(error.localizedDescription))
            }
        }
    }
}
