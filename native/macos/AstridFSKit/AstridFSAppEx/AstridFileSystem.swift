/* See LICENSE.txt. */

import Foundation
import FSKit
import OSLog

extension Logger {
    static let astridfs = Logger(subsystem: "org.astrid.runtime.fskit", category: "filesystem")
}

func volumeName(_ path: String) -> FSFileName {
    FSFileName(string: "Astrid")
}

@objc
final class AstridFileSystem: FSUnaryFileSystem & FSUnaryFileSystemOperations {
    private let resourcesLock = NSLock()
    private var resources: [URL: FSPathURLResource] = [:]

    func loadResource(
        resource: FSResource,
        options: FSTaskOptions,
        replyHandler: @escaping (FSVolume?, (any Error)?) -> Void
    ) {
        guard let urlResource = resource as? FSPathURLResource else {
            return replyHandler(nil, POSIXError(.EINVAL))
        }
        guard !options.taskOptions.contains(where: { $0.contains("-f") }) else {
            return replyHandler(nil, POSIXError(.ENOTSUP))
        }
        guard urlResource.url.startAccessingSecurityScopedResource() else {
            Logger.astridfs.error("Resource security-scope acquisition failed")
            return replyHandler(nil, POSIXError(.EACCES))
        }
        Logger.astridfs.info("Resource security scope acquired; writable=\(urlResource.isWritable)")
        do {
            let client = try AstridRPCClient(resourcePath: urlResource.url.path)
            Logger.astridfs.info("Resource lease decoded")
            _ = try client.stat(path: "")
            Logger.astridfs.info("Resource root stat succeeded")
            resourcesLock.lock()
            let existing = resources[urlResource.url] != nil
            if !existing { resources[urlResource.url] = urlResource }
            resourcesLock.unlock()
            guard !existing else {
                urlResource.url.stopAccessingSecurityScopedResource()
                return replyHandler(nil, POSIXError(.EBUSY))
            }
            self.containerStatus = .ready
            replyHandler(try AstridFSVolume(client: client), nil)
        } catch {
            let failure = error as NSError
            Logger.astridfs.error("Resource load failed: \(failure.domain, privacy: .public) code=\(failure.code)")
            urlResource.url.stopAccessingSecurityScopedResource()
            replyHandler(nil, error)
        }
    }

    func unloadResource(
        resource: FSResource,
        options: FSTaskOptions,
        replyHandler: @escaping ((any Error)?) -> Void
    ) {
        guard let urlResource = resource as? FSPathURLResource else {
            return replyHandler(POSIXError(.EINVAL))
        }
        resourcesLock.lock()
        let loaded = resources.removeValue(forKey: urlResource.url)
        resourcesLock.unlock()
        guard let loaded else { return replyHandler(POSIXError(.EINVAL)) }
        loaded.url.stopAccessingSecurityScopedResource()
        replyHandler(nil)
    }

    func probeResource(
        resource: FSResource,
        replyHandler: @escaping (FSProbeResult?, (any Error)?) -> Void
    ) {
        guard let urlResource = resource as? FSPathURLResource,
              FileManager.default.fileExists(atPath: urlResource.url.appendingPathComponent("lease.json").path)
        else {
            return replyHandler(nil, POSIXError(.ENODEV))
        }
        guard urlResource.url.startAccessingSecurityScopedResource() else {
            return replyHandler(nil, POSIXError(.EACCES))
        }
        defer { urlResource.url.stopAccessingSecurityScopedResource() }
        do {
            let info = try AstridRPCClient(resourcePath: urlResource.url.path).volumeInfo()
            replyHandler(FSProbeResult.usable(
                name: info.volume_name,
                containerID: FSContainerIdentifier(uuid: UUID())
            ), nil)
        } catch {
            replyHandler(nil, error)
        }
    }
}
