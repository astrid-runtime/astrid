import Foundation
import FSKit

@main
struct MetadataTests {
    static func main() {
        let request = FSItem.GetAttributesRequest()
        request.wantedAttributes = [.birthTime, .modifyTime, .changeTime,
                                    .accessTime, .backupTime, .addedTime]
        let attrs = FSItem.Attributes()
        populateUnknownTimestamps(attrs, wanted: request)
        precondition(attrs.isValid(.birthTime) && attrs.isValid(.modifyTime))
        precondition(attrs.isValid(.changeTime) && attrs.isValid(.accessTime))
        precondition(attrs.isValid(.backupTime) && attrs.isValid(.addedTime))
        precondition(attrs.birthTime.tv_sec == 0 && attrs.birthTime.tv_nsec == 0)
        precondition(attrs.modifyTime.tv_sec == 0 && attrs.modifyTime.tv_nsec == 0)
        precondition(attrs.changeTime.tv_sec == 0 && attrs.changeTime.tv_nsec == 0)
        precondition(attrs.accessTime.tv_sec == 0 && attrs.accessTime.tv_nsec == 0)
        precondition(attrs.backupTime.tv_sec == 0 && attrs.backupTime.tv_nsec == 0)
        precondition(attrs.addedTime.tv_sec == 0 && attrs.addedTime.tv_nsec == 0)

        request.wantedAttributes = [.modifyTime]
        let selected = FSItem.Attributes()
        populateUnknownTimestamps(selected, wanted: request)
        precondition(selected.isValid(.modifyTime) && !selected.isValid(.birthTime))

        let enumeration = FSItem.Attributes()
        populateUnknownTimestamps(enumeration, wanted: nil)
        precondition(enumeration.isValid(.birthTime) && enumeration.isValid(.addedTime))
        print("FSKit requested timestamp metadata: PASS")
    }
}
