/* See LICENSE.txt. */

import Foundation
import FSKit

final class AstridFSItem: FSItem {
    var path: String
    var name: String
    var itemType: FSItem.ItemType
    weak var parent: AstridFSItem?
    var inode: UInt64 { stableInode(path) }

    init(path: String, name: String, type: FSItem.ItemType, parent: AstridFSItem?) {
        self.path = path
        self.name = name
        self.itemType = type
        self.parent = parent
        super.init()
    }
}

func stableInode(_ path: String) -> UInt64 {
    if path.isEmpty { return FSItem.Identifier.rootDirectory.rawValue }
    var hash: UInt64 = 0xcbf29ce484222325
    for byte in path.utf8 {
        hash ^= UInt64(byte)
        hash &*= 0x100000001b3
    }
    return max(hash, 3)
}

func joinedPath(_ parent: AstridFSItem, _ name: String) -> String {
    parent.path.isEmpty ? name : "\(parent.path)/\(name)"
}

func populateUnknownTimestamps(_ attributes: FSItem.Attributes, wanted: FSItem.GetAttributesRequest?) {
    // The logical filesystem does not expose timestamps. Report a stable unknown
    // value, rather than omitting requested fields: getattrlist then returns
    // EINVAL and Finder cannot resolve an otherwise readable mounted directory.
    let unknown = timespec(tv_sec: 0, tv_nsec: 0)
    if wanted?.isAttributeWanted(.birthTime) ?? true { attributes.birthTime = unknown }
    if wanted?.isAttributeWanted(.modifyTime) ?? true { attributes.modifyTime = unknown }
    if wanted?.isAttributeWanted(.changeTime) ?? true { attributes.changeTime = unknown }
    if wanted?.isAttributeWanted(.accessTime) ?? true { attributes.accessTime = unknown }
    if wanted?.isAttributeWanted(.backupTime) ?? true { attributes.backupTime = unknown }
    if wanted?.isAttributeWanted(.addedTime) ?? true { attributes.addedTime = unknown }
}
