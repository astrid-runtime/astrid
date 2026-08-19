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
            return replyHandler(nil, POSIXError(.EACCES))
        }
        do {
            let client = try AstridRPCClient(resourcePath: urlResource.url.path)
            _ = try client.stat(path: "")
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
        let result = FSProbeResult.usable(
            name: "Astrid",
            containerID: FSContainerIdentifier(uuid: UUID())
        )
        replyHandler(result, nil)
    }
}
