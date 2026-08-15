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
