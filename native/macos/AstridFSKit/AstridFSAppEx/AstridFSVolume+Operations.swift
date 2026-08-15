/*
Adapted from Apple's Building a passthrough file system sample.
See LICENSE.txt for the scaffold licensing information.
*/

import Darwin
import Foundation
import FSKit

extension AstridFSVolume: FSVolume.Operations {
    var volumeStatistics: FSStatFSResult {
        let result = FSStatFSResult(fileSystemTypeName: "astridfs")
        result.blockSize = 4096
        result.ioSize = 4 * 1024 * 1024
        return result
    }

    func activate(options: FSTaskOptions, replyHandler: @escaping (FSItem?, (any Error)?) -> Void) {
        replyHandler(rootItem, nil)
    }

    func deactivate(options: FSDeactivateOptions = [], replyHandler: @escaping ((any Error)?) -> Void) {
        replyHandler(nil)
    }

    func mount(options: FSTaskOptions, replyHandler: @escaping (Error?) -> Void) {
        replyHandler(nil)
    }

    func unmount(replyHandler: @escaping () -> Void) {
        try? client.sync()
        replyHandler()
    }

    func synchronize(flags: FSSyncFlags, replyHandler: @escaping ((any Error)?) -> Void) {
        do {
            try client.sync()
            replyHandler(nil)
        } catch {
            replyHandler(error)
        }
    }

    func getAttributes(
        _ desiredAttributes: FSItem.GetAttributesRequest,
        of item: FSItem,
        replyHandler: @escaping (FSItem.Attributes?, Error?) -> Void
    ) {
        guard let item = item as? AstridFSItem else {
            return replyHandler(nil, POSIXError(.EINVAL))
        }
        do {
            let entry = try client.stat(path: item.path)
            replyHandler(attributes(for: item, entry: entry, wanted: desiredAttributes), nil)
        } catch {
            replyHandler(nil, error)
        }
    }

    private func attributes(
        for item: AstridFSItem,
        entry: AstridEntry,
        wanted: FSItem.GetAttributesRequest?
    ) -> FSItem.Attributes {
        let result = FSItem.Attributes()
        if wanted?.isAttributeWanted(.uid) ?? true { result.uid = getuid() }
        if wanted?.isAttributeWanted(.gid) ?? true { result.gid = getgid() }
        if wanted?.isAttributeWanted(.mode) ?? true {
            result.mode = entry.kind == "directory" ? 0o755 : 0o644
        }
        if wanted?.isAttributeWanted(.linkCount) ?? true { result.linkCount = 1 }
        if wanted?.isAttributeWanted(.flags) ?? true { result.flags = 0 }
        if wanted?.isAttributeWanted(.size) ?? true { result.size = entry.logical_bytes }
        if wanted?.isAttributeWanted(.allocSize) ?? true { result.allocSize = entry.logical_bytes }
        if wanted?.isAttributeWanted(.fileID) ?? true {
            result.fileID = FSItem.Identifier(rawValue: item.inode) ?? .invalid
        }
        if wanted?.isAttributeWanted(.parentID) ?? true {
            result.parentID = FSItem.Identifier(rawValue: item.parent?.inode ?? rootItem.inode) ?? .invalid
        }
        if wanted?.isAttributeWanted(.type) ?? true { result.type = item.itemType }
        return result
    }

    func setAttributes(
        _ newAttributes: FSItem.SetAttributesRequest,
        on item: FSItem,
        replyHandler: @escaping (FSItem.Attributes?, Error?) -> Void
    ) {
        guard let item = item as? AstridFSItem else {
            return replyHandler(nil, POSIXError(.EINVAL))
        }
        do {
            if newAttributes.isValid(.size) {
                try client.setLength(path: item.path, length: newAttributes.size)
            }
            let entry = try client.stat(path: item.path)
            replyHandler(attributes(for: item, entry: entry, wanted: nil), nil)
        } catch {
            replyHandler(nil, error)
        }
    }

    func lookupItem(
        named name: FSFileName,
        inDirectory directory: FSItem,
        replyHandler: @escaping (FSItem?, FSFileName?, Error?) -> Void
    ) {
        guard let directory = directory as? AstridFSItem,
              directory.itemType == .directory,
              let nameString = name.string else {
            return replyHandler(nil, nil, POSIXError(.EINVAL))
        }
        let path = joinedPath(directory, nameString)
        do {
            let value = try client.stat(path: path)
            let type: FSItem.ItemType = value.kind == "directory" ? .directory : .file
            replyHandler(cachedItem(path: path, name: nameString, type: type, parent: directory), name, nil)
        } catch {
            replyHandler(nil, nil, error)
        }
    }

    func reclaimItem(_ item: FSItem, replyHandler: @escaping (Error?) -> Void) {
        if let item = item as? AstridFSItem, !item.path.isEmpty { discard(path: item.path) }
        replyHandler(nil)
    }

    func readSymbolicLink(_ item: FSItem, replyHandler: @escaping (FSFileName?, Error?) -> Void) {
        replyHandler(nil, POSIXError(.ENOTSUP))
    }

    func createItem(
        named name: FSFileName,
        type: FSItem.ItemType,
        inDirectory directory: FSItem,
        attributes newAttributes: FSItem.SetAttributesRequest,
        replyHandler: @escaping (FSItem?, FSFileName?, Error?) -> Void
    ) {
        guard let directory = directory as? AstridFSItem,
              directory.itemType == .directory,
              let nameString = name.string,
              type == .file || type == .directory else {
            return replyHandler(nil, nil, POSIXError(.EINVAL))
        }
        let path = joinedPath(directory, nameString)
        do {
            try client.create(path: path, kind: type == .directory ? "directory" : "file")
            let item = cachedItem(path: path, name: nameString, type: type, parent: directory)
            if type == .file && newAttributes.isValid(.size) && newAttributes.size != 0 {
                try client.setLength(path: path, length: newAttributes.size)
            }
            replyHandler(item, name, nil)
        } catch {
            replyHandler(nil, nil, error)
        }
    }

    func createSymbolicLink(
        named name: FSFileName,
        inDirectory directory: FSItem,
        attributes newAttributes: FSItem.SetAttributesRequest,
        linkContents contents: FSFileName,
        replyHandler: @escaping (FSItem?, FSFileName?, Error?) -> Void
    ) {
        replyHandler(nil, nil, POSIXError(.ENOTSUP))
    }

    func createLink(
        to item: FSItem,
        named name: FSFileName,
        inDirectory directory: FSItem,
        replyHandler: @escaping (FSFileName?, Error?) -> Void
    ) {
        replyHandler(nil, POSIXError(.ENOTSUP))
    }

    func removeItem(
        _ item: FSItem,
        named name: FSFileName,
        fromDirectory directory: FSItem,
        replyHandler: @escaping (Error?) -> Void
    ) {
        guard let item = item as? AstridFSItem else {
            return replyHandler(POSIXError(.EINVAL))
        }
        do {
            try client.remove(path: item.path)
            discard(path: item.path)
            replyHandler(nil)
        } catch {
            replyHandler(error)
        }
    }

    func renameItem(
        _ item: FSItem,
        inDirectory sourceDirectory: FSItem,
        named sourceName: FSFileName,
        to destinationName: FSFileName,
        inDirectory destinationDirectory: FSItem,
        overItem: FSItem?,
        replyHandler: @escaping (FSFileName?, Error?) -> Void
    ) {
        guard let item = item as? AstridFSItem,
              let destinationDirectory = destinationDirectory as? AstridFSItem,
              let destination = destinationName.string else {
            return replyHandler(nil, POSIXError(.EINVAL))
        }
        let oldPath = item.path
        let newPath = joinedPath(destinationDirectory, destination)
        do {
            try client.rename(from: oldPath, to: newPath, replace: overItem != nil)
            discard(path: oldPath)
            if let replaced = overItem as? AstridFSItem { discard(path: replaced.path) }
            item.path = newPath
            item.name = destination
            item.parent = destinationDirectory
            _ = cachedItem(path: newPath, name: destination, type: item.itemType, parent: destinationDirectory)
            replyHandler(destinationName, nil)
        } catch {
            replyHandler(nil, error)
        }
    }

    func enumerateDirectory(
        _ directory: FSItem,
        startingAt cookie: FSDirectoryCookie,
        verifier: FSDirectoryVerifier,
        attributes requested: FSItem.GetAttributesRequest?,
        packer: FSDirectoryEntryPacker,
        replyHandler: @escaping (FSDirectoryVerifier, Error?) -> Void
    ) {
        guard let directory = directory as? AstridFSItem, directory.itemType == .directory else {
            return replyHandler(FSDirectoryVerifier(0), POSIXError(.ENOTDIR))
        }
        do {
            let entries = try client.readDirectory(path: directory.path)
            var index = Int(cookie.rawValue)
            while index < entries.count {
                let value = entries[index]
                let type: FSItem.ItemType = value.kind == "directory" ? .directory : .file
                let path = joinedPath(directory, value.name)
                let item = cachedItem(path: path, name: value.name, type: type, parent: directory)
                let attrs = requested.map { attributes(for: item, entry: value, wanted: $0) }
                let packed = packer.packEntry(
                    name: FSFileName(string: value.name),
                    itemType: type,
                    itemID: FSItem.Identifier(rawValue: item.inode) ?? .invalid,
                    nextCookie: FSDirectoryCookie(UInt64(index + 1)),
                    attributes: attrs
                )
                if !packed { break }
                index += 1
            }
            replyHandler(FSDirectoryVerifier(0), nil)
        } catch {
            replyHandler(FSDirectoryVerifier(0), error)
        }
    }

    var supportedVolumeCapabilities: FSVolume.SupportedCapabilities {
        let capabilities = FSVolume.SupportedCapabilities()
        capabilities.supportsPersistentObjectIDs = false
        capabilities.supportsSymbolicLinks = false
        capabilities.supportsHardLinks = false
        capabilities.supportsJournal = true
        capabilities.supportsActiveJournal = true
        capabilities.supportsSparseFiles = false
        capabilities.supportsFastStatFS = true
        capabilities.supports2TBFiles = true
        capabilities.supports64BitObjectIDs = true
        capabilities.doesNotSupportImmutableFiles = true
        capabilities.doesNotSupportSettingFilePermissions = true
        capabilities.caseFormat = .sensitive
        return capabilities
    }
}
