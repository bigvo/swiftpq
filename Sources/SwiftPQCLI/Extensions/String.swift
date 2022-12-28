import Foundation

extension String {
    static func random(length: Int) -> String {
        let characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        let charactersCount = characters.count
        var randomString = ""
        for _ in 0..<length {
            let randomIndex = Int.random(in: 0..<charactersCount)
            let randomCharacter = characters[characters.index(characters.startIndex, offsetBy: randomIndex)]
            randomString += String(randomCharacter)
        }
        return randomString
    }
}

extension String {
    func toUInt8Array() -> [UInt8] {
        return [UInt8](self.utf8)
    }
}
