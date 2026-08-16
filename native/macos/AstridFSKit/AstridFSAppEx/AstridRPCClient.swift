/*
Adapted from Apple's Building a passthrough file system sample.
See LICENSE.txt for the scaffold licensing information.
*/

import Darwin
import Foundation

struct AstridLease: Decodable {
    let mount_id: String
    let lease_token: String
    let resource_path: String
    let callback_path: String
}

struct AstridEntry: Decodable {
    let name: String
    let kind: String
    let logical_bytes: UInt64
}

enum AstridRPCSuccess {
    case done
    case entry(AstridEntry)
    case entries([AstridEntry])
    case data(Data)
    case written(UInt64)
}

private struct RPCFailure: Decodable {
    let code: String
    let message: String
}

final class AstridRPCClient {
    private let lease: AstridLease
    private let socketPath: String
    private let queue = DispatchQueue(label: "org.astrid.runtime.fskit.rpc")

    init(resourcePath: String) throws {
        let manifest = URL(fileURLWithPath: resourcePath).appendingPathComponent("lease.json")
        self.lease = try JSONDecoder().decode(AstridLease.self, from: Data(contentsOf: manifest))
        self.socketPath = lease.callback_path
    }

    func stat(path: String) throws -> AstridEntry {
        guard case let .entry(value) = try call(["operation": "stat", "path": path]) else {
            throw POSIXError(.EIO)
        }
        return value
    }

    func readDirectory(path: String) throws -> [AstridEntry] {
        guard case let .entries(value) = try call(["operation": "read-directory", "path": path]) else {
            throw POSIXError(.EIO)
        }
        return value
    }

    func read(path: String, offset: UInt64, length: Int) throws -> Data {
        guard case let .data(value) = try call([
            "operation": "read", "path": path, "offset": offset, "length": length
        ]) else {
            throw POSIXError(.EIO)
        }
        return value
    }

    func write(path: String, offset: UInt64, data: Data) throws -> Int {
        guard case .written = try call([
            "operation": "write",
            "path": path,
            "offset": offset,
            "data_base64": data.base64EncodedString()
        ]) else {
            throw POSIXError(.EIO)
        }
        return data.count
    }

    func setLength(path: String, length: UInt64) throws {
        guard case .written = try call([
            "operation": "set-length", "path": path, "length": length
        ]) else {
            throw POSIXError(.EIO)
        }
    }

    func create(path: String, kind: String) throws {
        guard case .done = try call(["operation": "create", "path": path, "kind": kind]) else {
            throw POSIXError(.EIO)
        }
    }

    func remove(path: String) throws {
        guard case .done = try call(["operation": "remove", "path": path]) else {
            throw POSIXError(.EIO)
        }
    }

    func rename(from: String, to: String, replace: Bool) throws {
        guard case .done = try call([
            "operation": "rename", "from": from, "to": to, "replace": replace
        ]) else {
            throw POSIXError(.EIO)
        }
    }

    func sync() throws {
        guard case .done = try call(["operation": "sync"]) else {
            throw POSIXError(.EIO)
        }
    }

    private func call(_ operation: [String: Any]) throws -> AstridRPCSuccess {
        try queue.sync {
            let request: [String: Any] = [
                "protocol_version": 2,
                "request_id": UUID().uuidString,
                "lease_token": lease.lease_token,
                "operation": operation,
            ]
            let requestData = try JSONSerialization.data(withJSONObject: request)
            guard requestData.count <= 8 * 1024 * 1024 else { throw POSIXError(.EFBIG) }
            let descriptor = try connectSocket()
            defer { Darwin.close(descriptor) }
            var length = UInt32(requestData.count).bigEndian
            try withUnsafeBytes(of: &length) { try writeAll(descriptor, bytes: $0) }
            try requestData.withUnsafeBytes { try writeAll(descriptor, bytes: $0) }
            var responseLength: UInt32 = 0
            try withUnsafeMutableBytes(of: &responseLength) { try readAll(descriptor, bytes: $0) }
            let count = Int(UInt32(bigEndian: responseLength))
            guard count <= 8 * 1024 * 1024 else { throw POSIXError(.EFBIG) }
            var responseData = Data(count: count)
            _ = try responseData.withUnsafeMutableBytes { try readAll(descriptor, bytes: $0) }
            return try decodeResponse(responseData)
        }
    }

    private func connectSocket() throws -> Int32 {
        let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else { throw currentPOSIXError() }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(socketPath.utf8CString)
        let capacity = MemoryLayout.size(ofValue: address.sun_path)
        guard pathBytes.count <= capacity else {
            Darwin.close(descriptor)
            throw POSIXError(.ENAMETOOLONG)
        }
        withUnsafeMutablePointer(to: &address.sun_path) { tuple in
            tuple.withMemoryRebound(to: CChar.self, capacity: capacity) { target in
                pathBytes.withUnsafeBufferPointer { source in
                    target.initialize(from: source.baseAddress!, count: pathBytes.count)
                }
            }
        }
        let result = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard result == 0 else {
            let error = currentPOSIXError()
            Darwin.close(descriptor)
            throw error
        }
        return descriptor
    }

    private func writeAll(_ descriptor: Int32, bytes: UnsafeRawBufferPointer) throws {
        var written = 0
        while written < bytes.count {
            let count = Darwin.write(descriptor, bytes.baseAddress! + written, bytes.count - written)
            guard count > 0 else { throw currentPOSIXError() }
            written += count
        }
    }

    private func readAll(_ descriptor: Int32, bytes: UnsafeMutableRawBufferPointer) throws {
        var readCount = 0
        while readCount < bytes.count {
            let count = Darwin.read(descriptor, bytes.baseAddress! + readCount, bytes.count - readCount)
            guard count > 0 else { throw POSIXError(.ECONNRESET) }
            readCount += count
        }
    }

    private func decodeResponse(_ data: Data) throws -> AstridRPCSuccess {
        guard let envelope = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let outcome = envelope["outcome"] as? [String: Any],
              let status = outcome["status"] as? String,
              let detail = outcome["detail"] as? [String: Any] else {
            throw POSIXError(.EIO)
        }
        if status == "failure" {
            let failureData = try JSONSerialization.data(withJSONObject: detail)
            let failure = try JSONDecoder().decode(RPCFailure.self, from: failureData)
            throw mapFailure(failure)
        }
        guard status == "success", let result = detail["result"] as? String else {
            throw POSIXError(.EIO)
        }
        let value = detail["value"]
        switch result {
        case "done": return .done
        case "entry":
            return .entry(try decodeValue(AstridEntry.self, value))
        case "entries":
            return .entries(try decodeValue([AstridEntry].self, value))
        case "data":
            guard let dictionary = value as? [String: Any],
                  let encoded = dictionary["data_base64"] as? String,
                  let decoded = Data(base64Encoded: encoded) else {
                throw POSIXError(.EIO)
            }
            return .data(decoded)
        case "written":
            guard let number = value as? NSNumber else { throw POSIXError(.EIO) }
            return .written(number.uint64Value)
        default: throw POSIXError(.EIO)
        }
    }

    private func decodeValue<T: Decodable>(_ type: T.Type, _ value: Any?) throws -> T {
        guard let value else { throw POSIXError(.EIO) }
        return try JSONDecoder().decode(type, from: JSONSerialization.data(withJSONObject: value))
    }

    private func mapFailure(_ failure: RPCFailure) -> POSIXError {
        let code: POSIXErrorCode
        switch failure.code {
        case "not-found": code = .ENOENT
        case "already-exists": code = .EEXIST
        case "is-directory": code = .EISDIR
        case "not-directory": code = .ENOTDIR
        case "directory-not-empty": code = .ENOTEMPTY
        case "read-only": code = .EROFS
        case "invalid-path": code = .EINVAL
        case "unauthorized", "stale-lease": code = .EACCES
        default: code = .EIO
        }
        return POSIXError(code, userInfo: [NSLocalizedDescriptionKey: failure.message])
    }
}

func currentPOSIXError() -> POSIXError {
    POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
}
