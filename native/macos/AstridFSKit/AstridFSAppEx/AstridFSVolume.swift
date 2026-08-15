/*
Adapted from Apple's Building a passthrough file system sample.
See LICENSE.txt for the scaffold licensing information.
*/

import Foundation
import FSKit

final class AstridFSVolume: FSVolume,
                            FSVolume.ReadWriteOperations,
                            FSVolume.RenameOperations,
                            FSVolume.PreallocateOperations,
                            FSVolume.OpenCloseOperations {
    let client: AstridRPCClient
    let rootItem: AstridFSItem
    private var itemCache: [String: AstridFSItem] = [:]
    private let itemCacheQueue = DispatchQueue(label: "org.astrid.runtime.fskit.items")

    init(client: AstridRPCClient) throws {
        self.client = client
        self.rootItem = AstridFSItem(path: "", name: "", type: .directory, parent: nil)
        super.init(volumeID: FSVolume.Identifier(uuid: UUID()), volumeName: FSFileName(string: "Astrid"))
        self.itemCache[""] = rootItem
    }

    func cachedItem(path: String, name: String, type: FSItem.ItemType, parent: AstridFSItem?) -> AstridFSItem {
        itemCacheQueue.sync {
            if let existing = itemCache[path] { return existing }
            let item = AstridFSItem(path: path, name: name, type: type, parent: parent)
            itemCache[path] = item
            return item
        }
    }

    func discard(path: String) {
        itemCacheQueue.sync {
            for key in itemCache.keys where key == path || key.hasPrefix(path + "/") {
                itemCache.removeValue(forKey: key)
            }
        }
    }

    func setVolumeName(_ name: FSFileName, replyHandler: @escaping (FSFileName?, (any Error)?) -> Void) {
        replyHandler(FSFileName(string: "Astrid"), nil)
    }

    func preallocateSpace(
        for item: FSItem,
        at offset: off_t,
        length: Int,
        flags: FSVolume.PreallocateFlags,
        replyHandler: @escaping (Int, (any Error)?) -> Void
    ) {
        replyHandler(length, nil)
    }

    func read(
        from item: FSItem,
        at offset: off_t,
        length: Int,
        into buffer: FSMutableFileDataBuffer,
        replyHandler: @escaping (Int, Error?) -> Void
    ) {
        guard let item = item as? AstridFSItem, item.itemType == .file, offset >= 0 else {
            return replyHandler(0, POSIXError(.EINVAL))
        }
        do {
            let data = try client.read(path: item.path, offset: UInt64(offset), length: length)
            _ = buffer.withUnsafeMutableBytes { target in
                data.copyBytes(to: target.bindMemory(to: UInt8.self))
            }
            replyHandler(data.count, nil)
        } catch {
            replyHandler(0, error)
        }
    }

    func write(
        contents: Data,
        to item: FSItem,
        at offset: off_t,
        replyHandler: @escaping (Int, (any Error)?) -> Void
    ) {
        guard let item = item as? AstridFSItem, item.itemType == .file, offset >= 0 else {
            return replyHandler(0, POSIXError(.EINVAL))
        }
        do {
            replyHandler(try client.write(path: item.path, offset: UInt64(offset), data: contents), nil)
        } catch {
            replyHandler(0, error)
        }
    }

    func openItem(_ item: FSItem, modes: FSVolume.OpenModes, replyHandler: @escaping ((any Error)?) -> Void) {
        replyHandler(nil)
    }

    func closeItem(_ item: FSItem, modes: FSVolume.OpenModes, replyHandler: @escaping ((any Error)?) -> Void) {
        replyHandler(nil)
    }

    var maximumLinkCount: Int { 1 }
    var maximumNameLength: Int { 255 }
    var restrictsOwnershipChanges: Bool { true }
    var truncatesLongNames: Bool { false }
    var maximumFileSizeInBits: Int { 63 }
    var maximumXattrSizeInBits: Int { 0 }
}
