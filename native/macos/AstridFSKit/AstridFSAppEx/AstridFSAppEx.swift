/*
See the LICENSE.txt file for this sample’s licensing information.

Abstract:
The app extension's conformance to the unary file system exension protocol,
 which declares the custom class that provides the file system implementation.
*/

import Foundation
import FSKit

@main
struct AstridFSAppEx: UnaryFileSystemExtension {

    typealias FileSystem = FSUnaryFileSystem & FSUnaryFileSystemOperations

    var fileSystem: FSUnaryFileSystem & FSUnaryFileSystemOperations {
        AstridFileSystem()
    }
}
