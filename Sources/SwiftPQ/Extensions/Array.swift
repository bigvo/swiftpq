import Foundation

extension Array where Element == UInt8 {
    public func hexString() -> String {
        return self.map { String(format: "%02x", $0) }.joined()
    }

    public init?(hexString: String) {
        let len = hexString.count / 2
        var result = [UInt8]()
        result.reserveCapacity(len)

        for i in 0..<len {
            let start = hexString.index(hexString.startIndex, offsetBy: i * 2)
            let end = hexString.index(start, offsetBy: 2)
            let bytes = hexString[start..<end]
            if let value = UInt8(bytes, radix: 16) {
                result.append(value)
            } else {
                return nil
            }
        }
        self = result
    }
}

extension Array where Element == UInt8 {
    public func base64EncodedString() -> String {
        let data = Data(self)
        return data.base64EncodedString()
    }
}

extension Array where Element == UInt8 {
    public func toData() -> Data {
        return Data(self)
    }
}
