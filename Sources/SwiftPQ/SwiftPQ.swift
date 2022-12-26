import Foundation
import CPQ

let KYBER_SECRETKEYBYTES = (KYBER_INDCPA_SECRETKEYBYTES + KYBER_INDCPA_PUBLICKEYBYTES + 2*KYBER_SYMBYTES)

@available(macOS 11.0, *)
public final class PQCrypto {
    public init() {}
    
    public enum Error: Swift.Error {
      /// Invalid key format
      case invalidFormat
      /// The error thrown when Decryption fails
      case decryptionFailed
    }
    
    // MARK: Wrapped PQCLEAN_KYBER512_CLEAN_crypto_kem_keypair function
    public func kemKeypair() -> (publicKey: [UInt8], secretKey: [UInt8]) {
        let pk = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(KYBER_PUBLICKEYBYTES))
        let sk = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(KYBER_SECRETKEYBYTES))

        PQCLEAN_KYBER512_CLEAN_crypto_kem_keypair(pk, sk)

        let publicKey = Array(UnsafeBufferPointer(start: pk, count: Int(KYBER_PUBLICKEYBYTES)))
        let secretKey = Array(UnsafeBufferPointer(start: sk, count: Int(KYBER_SECRETKEYBYTES)))

        pk.deallocate()
        sk.deallocate()

        return (publicKey, secretKey)
    }
    
    // MARK: Generate keys and encode to PEM-format
    public func generateEncodeKeys(password: String) throws -> (publicKey: String, secretKey: String) {
        let keypair = PQCrypto().kemKeypair()
        print("UNCRYPTED SK: \(keypair.secretKey.base64EncodedString())")
        let publicKey = encodeToPemKey(data: keypair.publicKey.toData(), label: "PUBLIC KEY")
        let encryptedSK = try encryptDataWithPassword(data: keypair.secretKey.toData(), password: password)
        let secretKey = encodeToPemKey(data: encryptedSK, label: "ENCRYPTED SECRET KEY")
        return (publicKey, secretKey)
    }
    
    // MARK: Decrypt private key
    public func decryptPrivateKey(pemKey: String, password: String) throws -> Data {
        guard let encryptedKey = decodePemKey(pemKey: pemKey) else {
            print("Decoding failed.")
            throw PQCrypto.Error.invalidFormat
        }
        guard let decryptedKey = try decryptDataWithPassword(encryptedData: encryptedKey, password: password) else {
            print("Decryption failed.")
            throw PQCrypto.Error.decryptionFailed
        }
        return decryptedKey
    }
    
    // MARK: Generate cipher text and shared secret with public key
    public func kemEncrypt(publicKey: [UInt8]) -> (cipherText: [UInt8], sharedSecret: [UInt8]) {
        let cipherText = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(KYBER_CIPHERTEXTBYTES))
        let sharedSecret = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(KYBER_SSBYTES))

        PQCLEAN_KYBER512_CLEAN_crypto_kem_enc(cipherText, sharedSecret, publicKey)

        let cipherTextArray = Array(UnsafeBufferPointer(start: cipherText, count: Int(KYBER_CIPHERTEXTBYTES)))
        let sharedSecretArray = Array(UnsafeBufferPointer(start: sharedSecret, count: Int(KYBER_SSBYTES)))

        cipherText.deallocate()
        sharedSecret.deallocate()

        return (cipherTextArray, sharedSecretArray)
    }
    
    // MARK: Get shared secret with cipher text and secret key
    public func kemDecrypt(ciphertext: [UInt8], secretKey: [UInt8]) -> [UInt8] {
        let ct = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(KYBER_CIPHERTEXTBYTES))
        ct.initialize(from: ciphertext, count: Int(KYBER_CIPHERTEXTBYTES))
        let sk = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(KYBER_SECRETKEYBYTES))
        sk.initialize(from: secretKey, count: Int(KYBER_SECRETKEYBYTES))
        let ss = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(KYBER_SSBYTES))

        PQCLEAN_KYBER512_CLEAN_crypto_kem_dec(ss, ct, sk)

        let sharedSecret = Array(UnsafeBufferPointer(start: ss, count: Int(KYBER_SSBYTES)))

        ct.deallocate()
        sk.deallocate()
        ss.deallocate()

        return sharedSecret
    }
    
    // MARK: Sign any message with secret key and return signature
    public func sign(message: String, secretKey: Data) -> Data? {
        var sigLength: Int = Int(SEEDBYTES + L * POLYZ_PACKEDBYTES + POLYVECH_PACKEDBYTES)
        var sig = [UInt8](repeating: 0, count: sigLength)
        var messageBytes = [UInt8](message.utf8)
        var secretKeyBytes = [UInt8](secretKey)
        let status = PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_signature(&sig, &sigLength, &messageBytes, messageBytes.count, &secretKeyBytes)
        if status != 0 {
            return nil
        }
        return Data(sig)
    }
    
    // MARK: Verify signed message with public key
    public func verify(signature: Data, message: String, publicKey: Data) -> Bool {
        let sigBytes = [UInt8](signature)
        let messageBytes = [UInt8](message.utf8)
        let pkBytes = [UInt8](publicKey)
        let status = PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_verify(sigBytes, sigBytes.count, messageBytes, messageBytes.count, pkBytes)
        return status == 0
    }
}
