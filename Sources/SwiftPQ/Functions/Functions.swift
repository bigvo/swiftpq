import Foundation
import Crypto

// MARK: Encode key to PEM-formatted string
public func encodeToPemKey(data: Data, label: String) -> String {
    let base64EncodedData = data.base64EncodedString()

    let lineLength = 64
    var pemKey = "-----BEGIN \(label)-----\n"
    for i in stride(from: 0, to: base64EncodedData.count, by: lineLength) {
        let lineEnd = base64EncodedData.index(base64EncodedData.startIndex, offsetBy: i + lineLength, limitedBy: base64EncodedData.endIndex) ?? base64EncodedData.endIndex
        let line = String(base64EncodedData[base64EncodedData.index(base64EncodedData.startIndex, offsetBy: i)..<lineEnd])
        pemKey += line + "\n"
    }
    pemKey += "-----END \(label)-----\n"

    return pemKey
}

// MARK: Encrypt private key using AES GCM encryption
@available(macOS 11.0, *)
func encryptDataWithPassword(data: Data, password: String) throws -> Data {
    let passwordData = Data(password.utf8)
    let key = SymmetricKey(data: passwordData)
    let derivedKey = HKDF<SHA256>.deriveKey(inputKeyMaterial: key, outputByteCount: 32)

    let sealedBox = try AES.GCM.seal(data, using: derivedKey)

    // return the encrypted data
    return Data(sealedBox.combined!)
}

// MARK: Decrypt AES GCM encrypted private key
@available(macOS 11.0, *)
func decryptDataWithPassword(encryptedData: Data, password: String) throws -> [UInt8]? {
    // Derive the key from the password
    let passwordData = Data(password.utf8)
    let key = SymmetricKey(data: passwordData)
    let derivedKey = HKDF<SHA256>.deriveKey(inputKeyMaterial: key, outputByteCount: 32)
    let sealedBox = try AES.GCM.SealedBox.init(combined: encryptedData)

    // Try to decrypt the data with the derived key
    do {
        let decryptedData = try AES.GCM.open(sealedBox, using: derivedKey)
        return [UInt8](decryptedData)
    } catch {
        print("Error decrypting data: \(error)")
        return nil
    }
}
