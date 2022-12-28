import Foundation
import CPQ

public protocol PQCryptoKEM {
    // MARK: Generate public and secret keys
    func kemKeypair() -> (publicKey: [UInt8], secretKey: [UInt8])
    
    // MARK: Encrypt random generated text to get cipher text and shared secret
    func kemEncrypt(publicKey: [UInt8]) -> (cipherText: [UInt8], sharedSecret: [UInt8])
    
    // MARK: Decrypt cipher text with secret key and return shared secret
    func kemDecrypt(ciphertext: [UInt8], secretKey: [UInt8]) -> [UInt8]
    
    // MARK: Generate keys, encrypt secret key using AES.GCM from CryptoKit and encode to PEM-format
    func generateEncodeKeys(password: String) throws -> (publicKey: String, secretKey: String)
}

public protocol PQCryptoSIGN {
    // MARK: Generate public and secret keys
    func signKeypair() -> (publicKey: [UInt8], secretKey: [UInt8])
    
    // MARK: Sign any message with conformable private key, return signature
    func signature(message: [UInt8], secretKey: [UInt8]) throws -> [UInt8]
    
    // MARK: Verify message with signature and public key
    func verify(signature: [UInt8], message: [UInt8], publicKey: [UInt8]) -> Bool
    
    // MARK: Return signed message
    func sign(message: [UInt8], secretKey: [UInt8]) throws -> [UInt8]
    
    // MARK: Open signed message, return decrypted message
    func open(signedMessage: [UInt8], publicKey: [UInt8]) throws -> [UInt8]
    
    // MARK: Generate keys, encrypt secret key using AES.GCM from CryptoKit and encode to PEM-format
    func generateEncodeKeys(password: String) throws -> (publicKey: String, secretKey: String)
}

@available(macOS 11.0, *)
public class PQCrypto {
    public init() {}
    
    public enum Error: Swift.Error {
        /// Invalid key format
        case invalidFormat
        /// The error thrown when Decryption fails
        case decryptionFailed
        /// Invalid encryption scheme
        case invalidScheme
        /// Generation failed
        case generationFailed
        /// Message signing failed
        case signFailed
        /// Message decryption
        case messageOpenFailed
        /// Unable to decode Base64 encoded string
        case decodingFailed
    }
    
    // MARK: Decrypt private key
    public func decryptPrivateKey(pemKey: String, password: String) throws -> [UInt8] {
        let encryptedKey = try decodePemKey(pemKey: pemKey)
        guard let decryptedKey = try decryptDataWithPassword(encryptedData: encryptedKey.toData(), password: password) else {
            print("Decryption failed.")
            throw PQCrypto.Error.decryptionFailed
        }
        return decryptedKey
    }
    
    // MARK: Decode from PEM-formatted string
    public func decodePemKey(pemKey: String) throws -> [UInt8] {
        let lines = pemKey.components(separatedBy: "\n")

        // Remove the BEGIN and END lines and any empty lines
        let base64EncodedLines = lines.filter { !$0.hasPrefix("-----") && !$0.isEmpty }

        // Concatenate the remaining lines
        let base64EncodedData = base64EncodedLines.joined()

        guard let data = Data(base64Encoded: base64EncodedData) else {
            throw PQCrypto.Error.decodingFailed
        }
        
        return [UInt8](data)
    }
}

@available(macOS 11.0, *)
extension PQCrypto {
    public struct KEM {
        // MARK: Kyber512 KEM scheme
        public struct Kyber512: PQCryptoKEM {
            public init() {}
            
            // MARK: Wrapped PQCLEAN_KYBER512_CLEAN_crypto_kem_keypair
            public func kemKeypair() -> (publicKey: [UInt8], secretKey: [UInt8]) {
                let pk = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PQCLEAN_KYBER512_CLEAN_CRYPTO_PUBLICKEYBYTES))
                let sk = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PQCLEAN_KYBER512_CLEAN_CRYPTO_SECRETKEYBYTES))
                
                PQCLEAN_KYBER512_CLEAN_crypto_kem_keypair(pk, sk)
                
                let publicKey = Array(UnsafeBufferPointer(start: pk, count: Int(PQCLEAN_KYBER512_CLEAN_CRYPTO_PUBLICKEYBYTES)))
                let secretKey = Array(UnsafeBufferPointer(start: sk, count: Int(PQCLEAN_KYBER512_CLEAN_CRYPTO_SECRETKEYBYTES)))
                
                pk.deallocate()
                sk.deallocate()
                
                return (publicKey, secretKey)
            }
            
            
            // MARK: Wrapped PQCLEAN_KYBER512_CLEAN_crypto_kem_enc
            public func kemEncrypt(publicKey: [UInt8]) -> (cipherText: [UInt8], sharedSecret: [UInt8]) {
                let cipherText = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PQCLEAN_KYBER512_CLEAN_CRYPTO_CIPHERTEXTBYTES))
                let sharedSecret = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PQCLEAN_KYBER512_CLEAN_CRYPTO_BYTES))
                
                PQCLEAN_KYBER512_CLEAN_crypto_kem_enc(cipherText, sharedSecret, publicKey)
                
                let cipherTextArray = Array(UnsafeBufferPointer(start: cipherText, count: Int(PQCLEAN_KYBER512_CLEAN_CRYPTO_CIPHERTEXTBYTES)))
                let sharedSecretArray = Array(UnsafeBufferPointer(start: sharedSecret, count: Int(PQCLEAN_KYBER512_CLEAN_CRYPTO_BYTES)))
                
                cipherText.deallocate()
                sharedSecret.deallocate()
                
                return (cipherTextArray, sharedSecretArray)
            }
            
            // MARK: Wrapped PQCLEAN_KYBER512_CLEAN_crypto_kem_dec
            public func kemDecrypt(ciphertext: [UInt8], secretKey: [UInt8]) -> [UInt8] {
                let ct = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PQCLEAN_KYBER512_CLEAN_CRYPTO_CIPHERTEXTBYTES))
                ct.initialize(from: ciphertext, count: Int(PQCLEAN_KYBER512_CLEAN_CRYPTO_CIPHERTEXTBYTES))
                let sk = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PQCLEAN_KYBER512_CLEAN_CRYPTO_SECRETKEYBYTES))
                sk.initialize(from: secretKey, count: Int(PQCLEAN_KYBER512_CLEAN_CRYPTO_SECRETKEYBYTES))
                let ss = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PQCLEAN_KYBER512_CLEAN_CRYPTO_BYTES))
                
                PQCLEAN_KYBER512_CLEAN_crypto_kem_dec(ss, ct, sk)
                
                let sharedSecret = Array(UnsafeBufferPointer(start: ss, count: Int(PQCLEAN_KYBER512_CLEAN_CRYPTO_BYTES)))
                
                ct.deallocate()
                sk.deallocate()
                ss.deallocate()
                
                return sharedSecret
            }
            
            public func generateEncodeKeys(password: String) throws -> (publicKey: String, secretKey: String) {
                let keypair = self.kemKeypair()
                let publicKey = encodeToPemKey(data: keypair.publicKey.toData(), label: "PUBLIC KEY")
                let encryptedSK = try encryptDataWithPassword(data: keypair.secretKey.toData(), password: password)
                let secretKey = encodeToPemKey(data: encryptedSK, label: "ENCRYPTED SECRET KEY")
                return (publicKey, secretKey)
            }
        }
        
        // MARK: Kyber768 KEM scheme
        public struct Kyber768: PQCryptoKEM {
            public init() {}
            
            // MARK: Wrapped PQCLEAN_KYBER768_CLEAN_crypto_kem_keypair
            public func kemKeypair() -> (publicKey: [UInt8], secretKey: [UInt8]) {
                let pk = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PQCLEAN_KYBER768_CLEAN_CRYPTO_PUBLICKEYBYTES))
                let sk = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PQCLEAN_KYBER768_CLEAN_CRYPTO_SECRETKEYBYTES))
                
                PQCLEAN_KYBER768_CLEAN_crypto_kem_keypair(pk, sk)
                
                let publicKey = Array(UnsafeBufferPointer(start: pk, count: Int(PQCLEAN_KYBER768_CLEAN_CRYPTO_PUBLICKEYBYTES)))
                let secretKey = Array(UnsafeBufferPointer(start: sk, count: Int(PQCLEAN_KYBER768_CLEAN_CRYPTO_SECRETKEYBYTES)))
                
                pk.deallocate()
                sk.deallocate()
                
                return (publicKey, secretKey)
            }
            
            // MARK: Wrapped PQCLEAN_KYBER768_CLEAN_crypto_kem_enc
            public func kemEncrypt(publicKey: [UInt8]) -> (cipherText: [UInt8], sharedSecret: [UInt8]) {
                let cipherText = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PQCLEAN_KYBER768_CLEAN_CRYPTO_CIPHERTEXTBYTES))
                let sharedSecret = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PQCLEAN_KYBER768_CLEAN_CRYPTO_BYTES))
                
                PQCLEAN_KYBER768_CLEAN_crypto_kem_enc(cipherText, sharedSecret, publicKey)
                
                let cipherTextArray = Array(UnsafeBufferPointer(start: cipherText, count: Int(PQCLEAN_KYBER768_CLEAN_CRYPTO_CIPHERTEXTBYTES)))
                let sharedSecretArray = Array(UnsafeBufferPointer(start: sharedSecret, count: Int(PQCLEAN_KYBER768_CLEAN_CRYPTO_BYTES)))
                
                cipherText.deallocate()
                sharedSecret.deallocate()
                
                return (cipherTextArray, sharedSecretArray)
            }
            
            // MARK: Wrapped PQCLEAN_KYBER768_CLEAN_crypto_kem_dec
            public func kemDecrypt(ciphertext: [UInt8], secretKey: [UInt8]) -> [UInt8] {
                let ct = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PQCLEAN_KYBER768_CLEAN_CRYPTO_CIPHERTEXTBYTES))
                ct.initialize(from: ciphertext, count: Int(PQCLEAN_KYBER768_CLEAN_CRYPTO_CIPHERTEXTBYTES))
                let sk = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PQCLEAN_KYBER768_CLEAN_CRYPTO_SECRETKEYBYTES))
                sk.initialize(from: secretKey, count: Int(PQCLEAN_KYBER768_CLEAN_CRYPTO_SECRETKEYBYTES))
                let ss = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PQCLEAN_KYBER768_CLEAN_CRYPTO_BYTES))
                
                PQCLEAN_KYBER768_CLEAN_crypto_kem_dec(ss, ct, sk)
                
                let sharedSecret = Array(UnsafeBufferPointer(start: ss, count: Int(PQCLEAN_KYBER768_CLEAN_CRYPTO_BYTES)))
                
                ct.deallocate()
                sk.deallocate()
                ss.deallocate()
                
                return sharedSecret
            }
            
            // MARK: Generate keys and encode to PEM-format
            public func generateEncodeKeys(password: String) throws -> (publicKey: String, secretKey: String) {
                let keypair = self.kemKeypair()
                let publicKey = encodeToPemKey(data: keypair.publicKey.toData(), label: "PUBLIC KEY")
                let encryptedSK = try encryptDataWithPassword(data: keypair.secretKey.toData(), password: password)
                let secretKey = encodeToPemKey(data: encryptedSK, label: "ENCRYPTED SECRET KEY")
                return (publicKey, secretKey)
            }
        }
        
        // MARK: Kyber1024 KEM scheme
        public struct Kyber1024: PQCryptoKEM {
            public init() {}
            
            // MARK: Wrapped PQCLEAN_KYBER1024_CLEAN_crypto_kem_keypair function
            public func kemKeypair() -> (publicKey: [UInt8], secretKey: [UInt8]) {
                let pk = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PQCLEAN_KYBER1024_CLEAN_CRYPTO_PUBLICKEYBYTES))
                let sk = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PQCLEAN_KYBER1024_CLEAN_CRYPTO_SECRETKEYBYTES))
                
                PQCLEAN_KYBER1024_CLEAN_crypto_kem_keypair(pk, sk)
                
                let publicKey = Array(UnsafeBufferPointer(start: pk, count: Int(PQCLEAN_KYBER1024_CLEAN_CRYPTO_PUBLICKEYBYTES)))
                let secretKey = Array(UnsafeBufferPointer(start: sk, count: Int(PQCLEAN_KYBER1024_CLEAN_CRYPTO_SECRETKEYBYTES)))
                
                pk.deallocate()
                sk.deallocate()
                
                return (publicKey, secretKey)
            }
            
            // MARK: Wrapped PQCLEAN_KYBER1024_CLEAN_crypto_kem_enc function
            public func kemEncrypt(publicKey: [UInt8]) -> (cipherText: [UInt8], sharedSecret: [UInt8]) {
                let cipherText = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PQCLEAN_KYBER1024_CLEAN_CRYPTO_CIPHERTEXTBYTES))
                let sharedSecret = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PQCLEAN_KYBER1024_CLEAN_CRYPTO_BYTES))
                
                PQCLEAN_KYBER1024_CLEAN_crypto_kem_enc(cipherText, sharedSecret, publicKey)
                
                let cipherTextArray = Array(UnsafeBufferPointer(start: cipherText, count: Int(PQCLEAN_KYBER1024_CLEAN_CRYPTO_CIPHERTEXTBYTES)))
                let sharedSecretArray = Array(UnsafeBufferPointer(start: sharedSecret, count: Int(PQCLEAN_KYBER1024_CLEAN_CRYPTO_BYTES)))
                
                cipherText.deallocate()
                sharedSecret.deallocate()
                
                return (cipherTextArray, sharedSecretArray)
            }
            
            // MARK: Wrapped PQCLEAN_KYBER1024_CLEAN_crypto_kem_dec function
            public func kemDecrypt(ciphertext: [UInt8], secretKey: [UInt8]) -> [UInt8] {
                let ct = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PQCLEAN_KYBER1024_CLEAN_CRYPTO_CIPHERTEXTBYTES))
                ct.initialize(from: ciphertext, count: Int(PQCLEAN_KYBER1024_CLEAN_CRYPTO_CIPHERTEXTBYTES))
                let sk = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PQCLEAN_KYBER1024_CLEAN_CRYPTO_SECRETKEYBYTES))
                sk.initialize(from: secretKey, count: Int(PQCLEAN_KYBER1024_CLEAN_CRYPTO_SECRETKEYBYTES))
                let ss = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PQCLEAN_KYBER1024_CLEAN_CRYPTO_BYTES))
                
                PQCLEAN_KYBER1024_CLEAN_crypto_kem_dec(ss, ct, sk)
                
                let sharedSecret = Array(UnsafeBufferPointer(start: ss, count: Int(PQCLEAN_KYBER1024_CLEAN_CRYPTO_BYTES)))
                
                ct.deallocate()
                sk.deallocate()
                ss.deallocate()
                
                return sharedSecret
            }
            
            // MARK: Generate keys and encode to PEM-format
            public func generateEncodeKeys(password: String) throws -> (publicKey: String, secretKey: String) {
                let keypair = self.kemKeypair()
                let publicKey = encodeToPemKey(data: keypair.publicKey.toData(), label: "PUBLIC KEY")
                let encryptedSK = try encryptDataWithPassword(data: keypair.secretKey.toData(), password: password)
                let secretKey = encodeToPemKey(data: encryptedSK, label: "ENCRYPTED SECRET KEY")
                return (publicKey, secretKey)
            }
        }
        
        // MARK: HQC-RMRS-128 KEM scheme
        public struct HQCRMRS128: PQCryptoKEM {
            public init() {}
            
            // MARK: Wrapped PQCLEAN_HQCRMRS128_CLEAN_crypto_kem_keypair function
            public func kemKeypair() -> (publicKey: [UInt8], secretKey: [UInt8]) {
                let pk = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PQCLEAN_HQCRMRS128_CLEAN_CRYPTO_PUBLICKEYBYTES))
                let sk = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PQCLEAN_HQCRMRS128_CLEAN_CRYPTO_SECRETKEYBYTES))
                
                PQCLEAN_HQCRMRS128_CLEAN_crypto_kem_keypair(pk, sk)
                
                let publicKey = Array(UnsafeBufferPointer(start: pk, count: Int(PQCLEAN_HQCRMRS128_CLEAN_CRYPTO_PUBLICKEYBYTES)))
                let secretKey = Array(UnsafeBufferPointer(start: sk, count: Int(PQCLEAN_HQCRMRS128_CLEAN_CRYPTO_SECRETKEYBYTES)))
                
                pk.deallocate()
                sk.deallocate()
                
                return (publicKey, secretKey)
            }
            
            // MARK: Wrapped PQCLEAN_HQCRMRS128_CLEAN_crypto_kem_enc function
            public func kemEncrypt(publicKey: [UInt8]) -> (cipherText: [UInt8], sharedSecret: [UInt8]) {
                let cipherText = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PQCLEAN_HQCRMRS128_CLEAN_CRYPTO_CIPHERTEXTBYTES))
                let sharedSecret = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PQCLEAN_HQCRMRS128_CLEAN_CRYPTO_BYTES))
                
                PQCLEAN_HQCRMRS128_CLEAN_crypto_kem_enc(cipherText, sharedSecret, publicKey)
                
                let cipherTextArray = Array(UnsafeBufferPointer(start: cipherText, count: Int(PQCLEAN_HQCRMRS128_CLEAN_CRYPTO_CIPHERTEXTBYTES)))
                let sharedSecretArray = Array(UnsafeBufferPointer(start: sharedSecret, count: Int(PQCLEAN_HQCRMRS128_CLEAN_CRYPTO_BYTES)))
                
                cipherText.deallocate()
                sharedSecret.deallocate()
                
                return (cipherTextArray, sharedSecretArray)
            }
            
            // MARK: Wrapped PQCLEAN_HQCRMRS128_CLEAN_crypto_kem_dec function
            public func kemDecrypt(ciphertext: [UInt8], secretKey: [UInt8]) -> [UInt8] {
                let ct = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PQCLEAN_HQCRMRS128_CLEAN_CRYPTO_CIPHERTEXTBYTES))
                ct.initialize(from: ciphertext, count: Int(PQCLEAN_HQCRMRS128_CLEAN_CRYPTO_CIPHERTEXTBYTES))
                let sk = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PQCLEAN_HQCRMRS128_CLEAN_CRYPTO_SECRETKEYBYTES))
                sk.initialize(from: secretKey, count: Int(PQCLEAN_HQCRMRS128_CLEAN_CRYPTO_SECRETKEYBYTES))
                let ss = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PQCLEAN_HQCRMRS128_CLEAN_CRYPTO_BYTES))
                
                PQCLEAN_HQCRMRS128_CLEAN_crypto_kem_dec(ss, ct, sk)
                
                let sharedSecret = Array(UnsafeBufferPointer(start: ss, count: Int(PQCLEAN_HQCRMRS128_CLEAN_CRYPTO_BYTES)))
                
                ct.deallocate()
                sk.deallocate()
                ss.deallocate()
                
                return sharedSecret
            }
            
            // MARK: Generate keys and encode to PEM-format
            public func generateEncodeKeys(password: String) throws -> (publicKey: String, secretKey: String) {
                let keypair = self.kemKeypair()
                let publicKey = encodeToPemKey(data: keypair.publicKey.toData(), label: "PUBLIC KEY")
                let encryptedSK = try encryptDataWithPassword(data: keypair.secretKey.toData(), password: password)
                let secretKey = encodeToPemKey(data: encryptedSK, label: "ENCRYPTED SECRET KEY")
                return (publicKey, secretKey)
            }
        }
        
        // MARK: HQC-RMRS-192 KEM scheme
        public struct HQCRMRS192: PQCryptoKEM {
            public init() {}
            
            // MARK: Wrapped PQCLEAN_HQCRMRS192_CLEAN_crypto_kem_keypair function
            public func kemKeypair() -> (publicKey: [UInt8], secretKey: [UInt8]) {
                let pk = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PQCLEAN_HQCRMRS192_CLEAN_CRYPTO_PUBLICKEYBYTES))
                let sk = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PQCLEAN_HQCRMRS192_CLEAN_CRYPTO_SECRETKEYBYTES))
                
                PQCLEAN_HQCRMRS192_CLEAN_crypto_kem_keypair(pk, sk)
                
                let publicKey = Array(UnsafeBufferPointer(start: pk, count: Int(PQCLEAN_HQCRMRS192_CLEAN_CRYPTO_PUBLICKEYBYTES)))
                let secretKey = Array(UnsafeBufferPointer(start: sk, count: Int(PQCLEAN_HQCRMRS192_CLEAN_CRYPTO_SECRETKEYBYTES)))
                
                pk.deallocate()
                sk.deallocate()
                
                return (publicKey, secretKey)
            }
            
            // MARK: Wrapped PQCLEAN_HQCRMRS192_CLEAN_crypto_kem_enc function
            public func kemEncrypt(publicKey: [UInt8]) -> (cipherText: [UInt8], sharedSecret: [UInt8]) {
                let cipherText = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PQCLEAN_HQCRMRS192_CLEAN_CRYPTO_CIPHERTEXTBYTES))
                let sharedSecret = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PQCLEAN_HQCRMRS192_CLEAN_CRYPTO_BYTES))
                
                PQCLEAN_HQCRMRS192_CLEAN_crypto_kem_enc(cipherText, sharedSecret, publicKey)
                
                let cipherTextArray = Array(UnsafeBufferPointer(start: cipherText, count: Int(PQCLEAN_HQCRMRS192_CLEAN_CRYPTO_CIPHERTEXTBYTES)))
                let sharedSecretArray = Array(UnsafeBufferPointer(start: sharedSecret, count: Int(PQCLEAN_HQCRMRS192_CLEAN_CRYPTO_BYTES)))
                
                cipherText.deallocate()
                sharedSecret.deallocate()
                
                return (cipherTextArray, sharedSecretArray)
            }
            
            // MARK: Wrapped PQCLEAN_HQCRMRS192_CLEAN_crypto_kem_dec function
            public func kemDecrypt(ciphertext: [UInt8], secretKey: [UInt8]) -> [UInt8] {
                let ct = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PQCLEAN_HQCRMRS192_CLEAN_CRYPTO_CIPHERTEXTBYTES))
                ct.initialize(from: ciphertext, count: Int(PQCLEAN_HQCRMRS192_CLEAN_CRYPTO_CIPHERTEXTBYTES))
                let sk = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PQCLEAN_HQCRMRS192_CLEAN_CRYPTO_SECRETKEYBYTES))
                sk.initialize(from: secretKey, count: Int(PQCLEAN_HQCRMRS192_CLEAN_CRYPTO_SECRETKEYBYTES))
                let ss = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PQCLEAN_HQCRMRS192_CLEAN_CRYPTO_BYTES))
                
                PQCLEAN_HQCRMRS192_CLEAN_crypto_kem_dec(ss, ct, sk)
                
                let sharedSecret = Array(UnsafeBufferPointer(start: ss, count: Int(PQCLEAN_HQCRMRS192_CLEAN_CRYPTO_BYTES)))
                
                ct.deallocate()
                sk.deallocate()
                ss.deallocate()
                
                return sharedSecret
            }
            
            // MARK: Generate keys and encode to PEM-format
            public func generateEncodeKeys(password: String) throws -> (publicKey: String, secretKey: String) {
                let keypair = self.kemKeypair()
                let publicKey = encodeToPemKey(data: keypair.publicKey.toData(), label: "PUBLIC KEY")
                let encryptedSK = try encryptDataWithPassword(data: keypair.secretKey.toData(), password: password)
                let secretKey = encodeToPemKey(data: encryptedSK, label: "ENCRYPTED SECRET KEY")
                return (publicKey, secretKey)
            }
        }
        
        // MARK: HQC-RMRS-192 KEM scheme
        public struct HQCRMRS256: PQCryptoKEM {
            public init() {}
            
            // MARK: Wrapped PQCLEAN_HQCRMRS256_CLEAN_crypto_kem_keypair function
            public func kemKeypair() -> (publicKey: [UInt8], secretKey: [UInt8]) {
                let pk = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PQCLEAN_HQCRMRS256_CLEAN_CRYPTO_PUBLICKEYBYTES))
                let sk = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PQCLEAN_HQCRMRS256_CLEAN_CRYPTO_SECRETKEYBYTES))
                
                PQCLEAN_HQCRMRS256_CLEAN_crypto_kem_keypair(pk, sk)
                
                let publicKey = Array(UnsafeBufferPointer(start: pk, count: Int(PQCLEAN_HQCRMRS256_CLEAN_CRYPTO_PUBLICKEYBYTES)))
                let secretKey = Array(UnsafeBufferPointer(start: sk, count: Int(PQCLEAN_HQCRMRS256_CLEAN_CRYPTO_SECRETKEYBYTES)))
                
                pk.deallocate()
                sk.deallocate()
                
                return (publicKey, secretKey)
            }
            
            // MARK: Wrapped PQCLEAN_HQCRMRS256_CLEAN_crypto_kem_enc function
            public func kemEncrypt(publicKey: [UInt8]) -> (cipherText: [UInt8], sharedSecret: [UInt8]) {
                let cipherText = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PQCLEAN_HQCRMRS256_CLEAN_CRYPTO_CIPHERTEXTBYTES))
                let sharedSecret = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PQCLEAN_HQCRMRS256_CLEAN_CRYPTO_BYTES))
                
                PQCLEAN_HQCRMRS256_CLEAN_crypto_kem_enc(cipherText, sharedSecret, publicKey)
                
                let cipherTextArray = Array(UnsafeBufferPointer(start: cipherText, count: Int(PQCLEAN_HQCRMRS256_CLEAN_CRYPTO_CIPHERTEXTBYTES)))
                let sharedSecretArray = Array(UnsafeBufferPointer(start: sharedSecret, count: Int(PQCLEAN_HQCRMRS256_CLEAN_CRYPTO_BYTES)))
                
                cipherText.deallocate()
                sharedSecret.deallocate()
                
                return (cipherTextArray, sharedSecretArray)
            }
            
            // MARK: Wrapped PQCLEAN_HQCRMRS192_CLEAN_crypto_kem_dec function
            public func kemDecrypt(ciphertext: [UInt8], secretKey: [UInt8]) -> [UInt8] {
                let ct = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PQCLEAN_HQCRMRS256_CLEAN_CRYPTO_CIPHERTEXTBYTES))
                ct.initialize(from: ciphertext, count: Int(PQCLEAN_HQCRMRS256_CLEAN_CRYPTO_CIPHERTEXTBYTES))
                let sk = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PQCLEAN_HQCRMRS256_CLEAN_CRYPTO_SECRETKEYBYTES))
                sk.initialize(from: secretKey, count: Int(PQCLEAN_HQCRMRS256_CLEAN_CRYPTO_SECRETKEYBYTES))
                let ss = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PQCLEAN_HQCRMRS256_CLEAN_CRYPTO_BYTES))
                
                PQCLEAN_HQCRMRS256_CLEAN_crypto_kem_dec(ss, ct, sk)
                
                let sharedSecret = Array(UnsafeBufferPointer(start: ss, count: Int(PQCLEAN_HQCRMRS256_CLEAN_CRYPTO_BYTES)))
                
                ct.deallocate()
                sk.deallocate()
                ss.deallocate()
                
                return sharedSecret
            }
            
            // MARK: Generate keys and encode to PEM-format
            public func generateEncodeKeys(password: String) throws -> (publicKey: String, secretKey: String) {
                let keypair = self.kemKeypair()
                let publicKey = encodeToPemKey(data: keypair.publicKey.toData(), label: "PUBLIC KEY")
                let encryptedSK = try encryptDataWithPassword(data: keypair.secretKey.toData(), password: password)
                let secretKey = encodeToPemKey(data: encryptedSK, label: "ENCRYPTED SECRET KEY")
                return (publicKey, secretKey)
            }
        }
    }
}

@available(macOS 11.0, *)
extension PQCrypto {
    public class SIGN {
        public struct Dilithium2: PQCryptoSIGN {
            
            public init() {}
            
            // MARK: Generate public and private key. Wrapped PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_keypair
            public func signKeypair() -> (publicKey: [UInt8], secretKey: [UInt8]) {
                let pk = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_PUBLICKEYBYTES))
                let sk = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_SECRETKEYBYTES))
                
                PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_keypair(pk, sk)
                
                let publicKey = Array(UnsafeBufferPointer(start: pk, count: Int(PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_PUBLICKEYBYTES)))
                let secretKey = Array(UnsafeBufferPointer(start: sk, count: Int(PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_SECRETKEYBYTES)))
                
                pk.deallocate()
                sk.deallocate()
                
                return (publicKey, secretKey)
            }
            
            // MARK: Wrapped PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_signature
            public func signature(message: [UInt8], secretKey: [UInt8]) throws -> [UInt8] {
                var sigLength: Int = Int(PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_BYTES)
                var sig = [UInt8](repeating: 0, count: sigLength)
                var messageBytes = message
                var secretKeyBytes = secretKey
                
                let status = PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_signature(&sig, &sigLength, &messageBytes, messageBytes.count, &secretKeyBytes)
                
                if status != 0 {
                    throw PQCrypto.Error.signFailed
                }
                return sig
            }
            
            // MARK: Wrapped PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_verify
            public func verify(signature: [UInt8], message: [UInt8], publicKey: [UInt8]) -> Bool {
                let status = PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_verify(signature, signature.count, message, message.count, publicKey)
                return status == 0
            }
            
            // MARK: Wrapped PQCLEAN_DILITHIUM2_CLEAN_crypto_sign
            public func sign(message: [UInt8], secretKey: [UInt8]) throws  -> [UInt8] {
                let sm = UnsafeMutablePointer<UInt8>.allocate(capacity: message.count + Int(PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_BYTES))
                
                let smlen = UnsafeMutablePointer<Int>.allocate(capacity: 1)
                
                let result = PQCLEAN_DILITHIUM2_CLEAN_crypto_sign(sm, smlen, message, message.count, secretKey)
                
                if result != 0 {
                    throw PQCrypto.Error.signFailed
                }
                
                // Convert the signed message to an array and deallocate memory
                let signedMessage = Array(UnsafeBufferPointer(start: sm, count: smlen.pointee))
                sm.deallocate()
                smlen.deallocate()
                
                return signedMessage
            }
            
            // MARK: Wrapped PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_open
            public func open(signedMessage: [UInt8], publicKey: [UInt8]) throws -> [UInt8] {
                var message = [UInt8](repeating: 0, count: signedMessage.count)
                var messageLen = signedMessage.count
                
                let result = PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_open(&message, &messageLen, signedMessage, signedMessage.count, publicKey)
                if result != 0 {
                    throw PQCrypto.Error.messageOpenFailed
                }
                
                return Array(message[..<messageLen])
            }
            
            // MARK: Generate keys and encode to PEM-format
            public func generateEncodeKeys(password: String) throws -> (publicKey: String, secretKey: String) {
                let keypair = self.signKeypair()
                let publicKey = encodeToPemKey(data: keypair.publicKey.toData(), label: "PUBLIC KEY")
                let encryptedSK = try encryptDataWithPassword(data: keypair.secretKey.toData(), password: password)
                let secretKey = encodeToPemKey(data: encryptedSK, label: "ENCRYPTED SECRET KEY")
                return (publicKey, secretKey)
            }
        }
        
        public struct Dilithium3: PQCryptoSIGN {
            public init() {}
            
            // MARK: Wrapped PQCLEAN_DILITHIUM3_CLEAN_crypto_sign_keypair
            public func signKeypair() -> (publicKey: [UInt8], secretKey: [UInt8]) {
                let pk = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_PUBLICKEYBYTES))
                let sk = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_SECRETKEYBYTES))
                
                PQCLEAN_DILITHIUM3_CLEAN_crypto_sign_keypair(pk, sk)
                
                let publicKey = Array(UnsafeBufferPointer(start: pk, count: Int(PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_PUBLICKEYBYTES)))
                let secretKey = Array(UnsafeBufferPointer(start: sk, count: Int(PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_SECRETKEYBYTES)))
                
                pk.deallocate()
                sk.deallocate()
                
                return (publicKey, secretKey)
            }
            
            // MARK: Wrapped PQCLEAN_DILITHIUM3_CLEAN_crypto_sign_signature
            public func signature(message: [UInt8], secretKey: [UInt8]) throws -> [UInt8] {
                var sigLength: Int = Int(PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_BYTES)
                var sig = [UInt8](repeating: 0, count: sigLength)
                var messageBytes = message
                var secretKeyBytes = secretKey
                
                let status = PQCLEAN_DILITHIUM3_CLEAN_crypto_sign_signature(&sig, &sigLength, &messageBytes, messageBytes.count, &secretKeyBytes)
                if status != 0 {
                    throw PQCrypto.Error.signFailed
                }
                return sig
            }
            
            // MARK: Wrapped PQCLEAN_DILITHIUM3_CLEAN_crypto_sign_verify
            public func verify(signature: [UInt8], message: [UInt8], publicKey: [UInt8]) -> Bool {
                let status = PQCLEAN_DILITHIUM3_CLEAN_crypto_sign_verify(signature, signature.count, message, message.count, publicKey)
                return status == 0
            }
            
            // MARK: Wrapped PQCLEAN_DILITHIUM3_CLEAN_crypto_sign
            public func sign(message: [UInt8], secretKey: [UInt8]) throws  -> [UInt8] {
                let sm = UnsafeMutablePointer<UInt8>.allocate(capacity: message.count + Int(PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_BYTES))
                
                let smlen = UnsafeMutablePointer<Int>.allocate(capacity: 1)
                
                let result = PQCLEAN_DILITHIUM3_CLEAN_crypto_sign(sm, smlen, message, message.count, secretKey)
                
                if result != 0 {
                    throw PQCrypto.Error.signFailed
                }
                
                // Convert the signed message to an array and deallocate memory
                let signedMessage = Array(UnsafeBufferPointer(start: sm, count: smlen.pointee))
                sm.deallocate()
                smlen.deallocate()
                
                return signedMessage
            }
            
            // MARK: Wrapped PQCLEAN_DILITHIUM3_CLEAN_crypto_sign_open
            public func open(signedMessage: [UInt8], publicKey: [UInt8]) throws -> [UInt8] {
                var message = [UInt8](repeating: 0, count: signedMessage.count)
                var messageLen = signedMessage.count
                
                let result = PQCLEAN_DILITHIUM3_CLEAN_crypto_sign_open(&message, &messageLen, signedMessage, signedMessage.count, publicKey)
                if result != 0 {
                    throw PQCrypto.Error.messageOpenFailed
                }
                
                return Array(message[..<messageLen])
            }
            
            // MARK: Generate keys and encode to PEM-format
            public func generateEncodeKeys(password: String) throws -> (publicKey: String, secretKey: String) {
                let keypair = self.signKeypair()
                let publicKey = encodeToPemKey(data: keypair.publicKey.toData(), label: "PUBLIC KEY")
                let encryptedSK = try encryptDataWithPassword(data: keypair.secretKey.toData(), password: password)
                let secretKey = encodeToPemKey(data: encryptedSK, label: "ENCRYPTED SECRET KEY")
                return (publicKey, secretKey)
            }
        }
        
        public struct Dilithium5: PQCryptoSIGN {
            public init() {}
            
            // MARK: Wrapped PQCLEAN_DILITHIUM5_CLEAN_crypto_sign_keypair
            public func signKeypair() -> (publicKey: [UInt8], secretKey: [UInt8]) {
                let pk = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_PUBLICKEYBYTES))
                let sk = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_SECRETKEYBYTES))
                
                PQCLEAN_DILITHIUM5_CLEAN_crypto_sign_keypair(pk, sk)
                
                let publicKey = Array(UnsafeBufferPointer(start: pk, count: Int(PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_PUBLICKEYBYTES)))
                let secretKey = Array(UnsafeBufferPointer(start: sk, count: Int(PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_SECRETKEYBYTES)))
                
                pk.deallocate()
                sk.deallocate()
                
                return (publicKey, secretKey)
            }
            
            // MARK: Wrapped PQCLEAN_DILITHIUM5_CLEAN_crypto_sign_signature
            public func signature(message: [UInt8], secretKey: [UInt8]) throws -> [UInt8] {
                var sigLength: Int = Int(PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_BYTES)
                var sig = [UInt8](repeating: 0, count: sigLength)
                var messageBytes = message
                var secretKeyBytes = secretKey
                let status = PQCLEAN_DILITHIUM5_CLEAN_crypto_sign_signature(&sig, &sigLength, &messageBytes, messageBytes.count, &secretKeyBytes)
                if status != 0 {
                    throw PQCrypto.Error.signFailed
                }
                return sig
            }
            
            // MARK: Wrapped PQCLEAN_DILITHIUM5_CLEAN_crypto_sign_verify
            public func verify(signature: [UInt8], message: [UInt8], publicKey: [UInt8]) -> Bool {
                let status = PQCLEAN_DILITHIUM5_CLEAN_crypto_sign_verify(signature, signature.count, message, message.count, publicKey)
                return status == 0
            }
            
            // MARK: Wrapped PQCLEAN_DILITHIUM5_CLEAN_crypto_sign
            public func sign(message: [UInt8], secretKey: [UInt8]) throws  -> [UInt8] {
                let sm = UnsafeMutablePointer<UInt8>.allocate(capacity: message.count + Int(PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_BYTES))
                
                let smlen = UnsafeMutablePointer<Int>.allocate(capacity: 1)
                
                let result = PQCLEAN_DILITHIUM5_CLEAN_crypto_sign(sm, smlen, message, message.count, secretKey)
                
                if result != 0 {
                    throw PQCrypto.Error.signFailed
                }
                
                // Convert the signed message to an array and deallocate memory
                let signedMessage = Array(UnsafeBufferPointer(start: sm, count: smlen.pointee))
                sm.deallocate()
                smlen.deallocate()
                
                return signedMessage
            }
            
            // MARK: Wrapped PQCLEAN_DILITHIUM5_CLEAN_crypto_sign_open
            public func open(signedMessage: [UInt8], publicKey: [UInt8]) throws -> [UInt8] {
                var message = [UInt8](repeating: 0, count: signedMessage.count)
                var messageLen = signedMessage.count
                
                let result = PQCLEAN_DILITHIUM5_CLEAN_crypto_sign_open(&message, &messageLen, signedMessage, signedMessage.count, publicKey)
                if result != 0 {
                    throw PQCrypto.Error.messageOpenFailed
                }
                
                return Array(message[..<messageLen])
            }
            
            // MARK: Generate keys and encode to PEM-format
            public func generateEncodeKeys(password: String) throws -> (publicKey: String, secretKey: String) {
                let keypair = self.signKeypair()
                let publicKey = encodeToPemKey(data: keypair.publicKey.toData(), label: "PUBLIC KEY")
                let encryptedSK = try encryptDataWithPassword(data: keypair.secretKey.toData(), password: password)
                let secretKey = encodeToPemKey(data: encryptedSK, label: "ENCRYPTED SECRET KEY")
                return (publicKey, secretKey)
            }
        }
        
        public struct Falcon512: PQCryptoSIGN {
            public init() {}
            
            // MARK: Wrapped PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair
            public func signKeypair() -> (publicKey: [UInt8], secretKey: [UInt8]) {
                let pk = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES))
                let sk = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES))
                
                PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(pk, sk)
                
                let publicKey = Array(UnsafeBufferPointer(start: pk, count: Int(PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES)))
                let secretKey = Array(UnsafeBufferPointer(start: sk, count: Int(PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES)))
                
                pk.deallocate()
                sk.deallocate()
                
                return (publicKey, secretKey)
            }
            
            // MARK: Wrapped PQCLEAN_FALCON512_CLEAN_crypto_sign_signature
            public func signature(message: [UInt8], secretKey: [UInt8]) throws -> [UInt8] {
                let sig = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES))
                var siglen: size_t = 0
                var messageBytes = message
                var secretKeyBytes = secretKey
                
                let status = PQCLEAN_FALCON512_CLEAN_crypto_sign_signature(sig, &siglen, &messageBytes, messageBytes.count, &secretKeyBytes)
                if status != 0 {
                    throw PQCrypto.Error.signFailed
                }
                let signature = Array(UnsafeBufferPointer(start: sig, count: siglen))
                return signature
            }
            
            // MARK: Wrapped PQCLEAN_FALCON512_CLEAN_crypto_sign_verify
            public func verify(signature: [UInt8], message: [UInt8], publicKey: [UInt8]) -> Bool {
                let status = PQCLEAN_FALCON512_CLEAN_crypto_sign_verify(signature, signature.count, message, message.count, publicKey)
                return status == 0
            }
            
            // MARK: Wrapped PQCLEAN_FALCON512_CLEAN_crypto_sign
            public func sign(message: [UInt8], secretKey: [UInt8]) throws  -> [UInt8] {
                let sm = UnsafeMutablePointer<UInt8>.allocate(capacity: message.count + Int(PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES))
                
                let smlen = UnsafeMutablePointer<Int>.allocate(capacity: 1)
                
                let result = PQCLEAN_FALCON512_CLEAN_crypto_sign(sm, smlen, message, message.count, secretKey)
                
                if result != 0 {
                    throw PQCrypto.Error.signFailed
                }
                
                let signedMessage = Array(UnsafeBufferPointer(start: sm, count: smlen.pointee))
                sm.deallocate()
                smlen.deallocate()
                
                return signedMessage
            }
            
            // MARK: Wrapped PQCLEAN_FALCON512_CLEAN_crypto_sign_open
            public func open(signedMessage: [UInt8], publicKey: [UInt8]) throws -> [UInt8] {
                var message = [UInt8](repeating: 0, count: signedMessage.count)
                var messageLen = signedMessage.count
                
                let result = PQCLEAN_FALCON512_CLEAN_crypto_sign_open(&message, &messageLen, signedMessage, signedMessage.count, publicKey)
                if result != 0 {
                    throw PQCrypto.Error.messageOpenFailed
                }
                
                return Array(message[..<messageLen])
            }
            
            // MARK: Generate keys and encode to PEM-format
            public func generateEncodeKeys(password: String) throws -> (publicKey: String, secretKey: String) {
                let keypair = self.signKeypair()
                let publicKey = encodeToPemKey(data: keypair.publicKey.toData(), label: "PUBLIC KEY")
                let encryptedSK = try encryptDataWithPassword(data: keypair.secretKey.toData(), password: password)
                let secretKey = encodeToPemKey(data: encryptedSK, label: "ENCRYPTED SECRET KEY")
                return (publicKey, secretKey)
            }
        }
        
        public struct Falcon1024: PQCryptoSIGN {
            public init() {}
            
            // MARK: Wrapped PQCLEAN_FALCON1024_CLEAN_crypto_sign_keypair
            public func signKeypair() -> (publicKey: [UInt8], secretKey: [UInt8]) {
                let pk = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES))
                let sk = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES))
                
                PQCLEAN_FALCON1024_CLEAN_crypto_sign_keypair(pk, sk)
                
                let publicKey = Array(UnsafeBufferPointer(start: pk, count: Int(PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES)))
                let secretKey = Array(UnsafeBufferPointer(start: sk, count: Int(PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES)))
                
                pk.deallocate()
                sk.deallocate()
                
                return (publicKey, secretKey)
            }
            
            // MARK: Wrapped PQCLEAN_FALCON1024_CLEAN_crypto_sign_signature
            public func signature(message: [UInt8], secretKey: [UInt8]) throws -> [UInt8] {
                let sig = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PQCLEAN_FALCON1024_CLEAN_CRYPTO_BYTES))
                var siglen: size_t = 0
        
                var messageBytes = message
                var secretKeyBytes = secretKey
                let status = PQCLEAN_FALCON1024_CLEAN_crypto_sign_signature(sig, &siglen, &messageBytes, messageBytes.count, &secretKeyBytes)
                if status != 0 {
                    throw PQCrypto.Error.signFailed
                }
                let signature = Array(UnsafeBufferPointer(start: sig, count: siglen))
                return signature
            }
            
            // MARK: Wrapped PQCLEAN_FALCON1024_CLEAN_crypto_sign_verify
            public func verify(signature: [UInt8], message: [UInt8], publicKey: [UInt8]) -> Bool {
                let status = PQCLEAN_FALCON1024_CLEAN_crypto_sign_verify(signature, signature.count, message, message.count, publicKey)
                return status == 0
            }
            
            // MARK: Wrapped PQCLEAN_FALCON1024_CLEAN_crypto_sign
            public func sign(message: [UInt8], secretKey: [UInt8]) throws  -> [UInt8] {
                let sm = UnsafeMutablePointer<UInt8>.allocate(capacity: message.count + Int(PQCLEAN_FALCON1024_CLEAN_CRYPTO_BYTES))
                
                let smlen = UnsafeMutablePointer<Int>.allocate(capacity: 1)
                
                let result = PQCLEAN_FALCON1024_CLEAN_crypto_sign(sm, smlen, message, message.count, secretKey)
                
                if result != 0 {
                    throw PQCrypto.Error.signFailed
                }
                
                let signedMessage = Array(UnsafeBufferPointer(start: sm, count: smlen.pointee))
                sm.deallocate()
                smlen.deallocate()
                
                return signedMessage
            }
            
            // MARK: Wrapped PQCLEAN_FALCON1024_CLEAN_crypto_sign_open
            public func open(signedMessage: [UInt8], publicKey: [UInt8]) throws -> [UInt8] {
                var message = [UInt8](repeating: 0, count: signedMessage.count)
                var messageLen = signedMessage.count
                
                let result = PQCLEAN_FALCON1024_CLEAN_crypto_sign_open(&message, &messageLen, signedMessage, signedMessage.count, publicKey)
                if result != 0 {
                    throw PQCrypto.Error.messageOpenFailed
                }
                
                return Array(message[..<messageLen])
            }
            
            // MARK: Generate keys and encode to PEM-format
            public func generateEncodeKeys(password: String) throws -> (publicKey: String, secretKey: String) {
                let keypair = self.signKeypair()
                let publicKey = encodeToPemKey(data: keypair.publicKey.toData(), label: "PUBLIC KEY")
                let encryptedSK = try encryptDataWithPassword(data: keypair.secretKey.toData(), password: password)
                let secretKey = encodeToPemKey(data: encryptedSK, label: "ENCRYPTED SECRET KEY")
                return (publicKey, secretKey)
            }
        }
    }
}
