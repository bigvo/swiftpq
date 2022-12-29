import Foundation
import Crypto
import ArgumentParser
import SwiftPQ

@available(macOS 11.0, *)
@main
struct SwiftPQCLI: ParsableCommand {
    @Flag(name: [.short, .long], help: "Generate new keys")
    var generate: Bool = false
    
    @Option(name: [.long], help: "Path to save generated keys")
    var save: String? = nil
    
    @Flag(name: [.short, .long], help: "Check if keys are valid")
    var check: Bool = false
    
    @Option(name: [.short, .long], help: "Path to <path>/private.key and/or public.key")
    var path: String? = nil
    
    @Flag(name: [.short, .long], help: "Sign a message with private key")
    var sign: Bool = false
    
    @Option(name: [.short, .long], help: "Message to sign or verify")
    var message: String? = nil
    
    @Option(name: [.long], help: "Verify signature to a message with public key.")
    var signature: String? = nil
    
    @Option(name: [.short, .long], help: "Encryption scheme to be used")
    var algorithm: String? = nil
    
    mutating func run() throws {
        let pqCrypto = PQCrypto()
        var pqCryptoKEM: PQCryptoKEM? = nil
        var pqCryptoSIGN: PQCryptoSIGN? = nil
        
        switch algorithm {
        case "kyber512":
            pqCryptoKEM = PQCrypto.KEM.Kyber512()
        case "kyber768":
            pqCryptoKEM = PQCrypto.KEM.Kyber768()
        case "kyber1024":
            pqCryptoKEM = PQCrypto.KEM.Kyber1024()
        case "hqcrmrs128":
            pqCryptoKEM = PQCrypto.KEM.HQCRMRS128()
        case "hqcrmrs192":
            pqCryptoKEM = PQCrypto.KEM.HQCRMRS192()
        case "hqcrmrs256":
            pqCryptoKEM = PQCrypto.KEM.HQCRMRS256()
        case "dilithium2":
            pqCryptoSIGN = PQCrypto.SIGN.Dilithium2()
        case "dilithium3":
            pqCryptoSIGN = PQCrypto.SIGN.Dilithium3()
        case "dilithium5":
            pqCryptoSIGN = PQCrypto.SIGN.Dilithium5()
        case "falcon512":
            pqCryptoSIGN = PQCrypto.SIGN.Falcon512()
        case "falcon1024":
            pqCryptoSIGN = PQCrypto.SIGN.Falcon1024()
        default:
            return
        }
        
        if generate {
            print("Please enter password to encrypt private key:\n")
            guard let password = getpass("Enter password: ") else {
                return print("Password is required.\n")
            }
            
            let pass = String(cString: password)
            
            guard confirmPassword(password: pass) else {
                print("Passwords don't match. Try again.\n")
                return
            }
            
            var keys: (publicKey: String, secretKey: String)? = nil
            
            if pqCryptoSIGN != nil {
                keys = try pqCryptoSIGN!.generateEncodeKeys(password: pass)
            } else {
                keys = try pqCryptoKEM!.generateEncodeKeys(password: pass)
            }
            
            
            guard keys != nil else {
                throw PQCrypto.Error.generationFailed
            }
            
            print(keys!.publicKey)
            print(keys!.secretKey)
            
                if let save = save {
                    do {
                        try saveKeys(publicKey: keys!.publicKey, privateKey: keys!.secretKey, to: save)
                        print("Key succesfully saved.\n")
                    } catch {
                        print("Keys weren't saved.")
                    }
                }
            return
        }
        
        if check {
            if let path = path {
                // Read keys from a file
                let secretKeyPath = "\(path)/private.key"
                let publicKeyPath = "\(path)/public.key"
                var secretKeyData: String = ""
                var publicKeyData: String = ""
                do {
                    secretKeyData = try String(contentsOf: URL(fileURLWithPath: secretKeyPath))
                    publicKeyData = try String(contentsOf: URL(fileURLWithPath: publicKeyPath))
                } catch {
                    print("Can't read keys from provided path.\n")
                    return
                }
                
                print("Please enter password to decrypt private key:\n")
                guard let password = getpass("Enter password: ") else {
                    return print("Password is required.\n")
                }
                
                let decryptedPrivateKey = try pqCrypto.decryptPrivateKey(pemKey: secretKeyData, password: String(cString: password))
                let decodedPublicKey = try pqCrypto.decodePemKey(pemKey: publicKeyData)
                
                if pqCryptoKEM != nil {
                    if validateKEMKeys(pqCryptoKEM: pqCryptoKEM!, publicKey: decodedPublicKey, secretKey: decryptedPrivateKey) {
                        print("Keys are valid.")
                        return
                    } else {
                        print("Keys are invalid.")
                        return
                    }
                }
                
                if pqCryptoSIGN != nil {
                    if try validateSIGNKeys(pqCryptoSign: pqCryptoSIGN!, publicKey: decodedPublicKey, secretKey: decryptedPrivateKey) {
                        print("Keys are valid.")
                        return
                    } else {
                        print("Keys are invalid.")
                        return
                    }
                }
                
                print("Please provide encryption algorithm. -a <algorithm>\n")
                return
            } else {
                print("Path to keys isn't provided. use -p {PATH}")
            }
        }
        
        if sign {
            if let message = message {
                if let path = path {
                    // Read the secret key from a file
                    let secretKeyPath = "\(path)/private.key"
                    var secretKeyData: String = ""
                    do {
                        secretKeyData = try String(contentsOf: URL(fileURLWithPath: secretKeyPath))
                    } catch {
                        print("Can't read keys from provided path.\n")
                        return
                    }
                    
                    print("Please enter password to decrypt private key:\n")
                    guard let password = getpass("Enter password: ") else {
                        return print("Password is required.\n")
                    }
                    
                    let decryptedPrivateKey = try pqCrypto.decryptPrivateKey(pemKey: secretKeyData, password: String(cString: password))
                    
                    let signature = try pqCryptoSIGN!.signature(message: message.toUInt8Array(), secretKey: decryptedPrivateKey)
                    
                    print("SIGNATURE: \(signature.base64EncodedString())")
                    return
                } else {
                    print("Path to keys isn't provided. use -p {PATH}")
                    return
                }
            } else {
                print("Please provide message to sign -m <message>")
                return
            }
        }
        
        if let signature = signature {
            if let message = message {
                if let path = path {
                    // Read public key from a file
                    let publicKeyPath = "\(path)/public.key"
                    var publicKeyData: String = ""
                    do {
                        publicKeyData = try String(contentsOf: URL(fileURLWithPath: publicKeyPath))
                    } catch {
                        print("Can't read key from provided path.\n")
                        return
                    }
                    
                    let decodedPublicKey = try pqCrypto.decodePemKey(pemKey: publicKeyData)
                    
                    print("SIGNATURE TO VERIFY: \(signature)\n")
                    print("MESSAGE: \(message)\n")
                    print("PUBLIC KEY: \(decodedPublicKey.base64EncodedString())\n")
                    
                    if pqCryptoSIGN!.verify(signature: Data(base64Encoded: signature)!.bytes, message: message.toUInt8Array(), publicKey: decodedPublicKey) {
                        print("Signature is valid.")
                        return
                    }
                    print("Signature is invalid")
                    return
                } else {
                    print("Path to keys isn't provided. use -p {PATH}")
                    return
                }
            } else {
                print("Please provide message to sign -m <message>")
                return
            }
        }
    }
}

func confirmPassword(password: String) -> Bool {
    guard let confirmedPassword = getpass("Confirm password: ") else {
        return false
    }
    return password == String(cString: confirmedPassword)
}

func saveKeys(publicKey: String, privateKey: String, to path: String) throws {
    let publicKeyPath = "\(path)/public.key"
    let privateKeyPath = "\(path)/private.key"
    
    // Create the directory if it doesn't exist
    try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: true, attributes: nil)
    
    try publicKey.write(toFile: publicKeyPath, atomically: true, encoding: .utf8)
    try privateKey.write(toFile: privateKeyPath, atomically: true, encoding: .utf8)
}

@available(macOS 11.0, *)
func validateKEMKeys(pqCryptoKEM: PQCryptoKEM, publicKey: [UInt8], secretKey: [UInt8]) -> Bool {
    let startTime = Date()
    
    let encrypt = pqCryptoKEM.kemEncrypt(publicKey: publicKey)
    let decrypt = pqCryptoKEM.kemDecrypt(ciphertext: encrypt.cipherText, secretKey: secretKey)
    
    let endTime = Date()
    let elapsedTime = endTime.timeIntervalSince(startTime)
    let formattedExecutionTime = String(format: "%.4f", elapsedTime)
    
    print("\nCIPHER TEXT: \(encrypt.cipherText.base64EncodedString())\n")
    print("SHARED SECRET: \(encrypt.sharedSecret.base64EncodedString())\n")
    print("DECRYPTED SHARED SECRET: \(decrypt.base64EncodedString())\n")
    print("ELAPSED TIME: \(formattedExecutionTime)\n")
    
    return encrypt.sharedSecret == decrypt
}

func validateSIGNKeys(pqCryptoSign: PQCryptoSIGN, publicKey: [UInt8], secretKey: [UInt8]) throws -> Bool {
    let startTime = Date()
    let message = String.random(length: 10)
    let messageBytes = [UInt8](message.utf8)
    let pkBytes = [UInt8](publicKey)
    
    let signature = try pqCryptoSign.signature(message: messageBytes, secretKey: secretKey)
    let verify = pqCryptoSign.verify(signature: signature, message: messageBytes, publicKey: publicKey)
    
    let signedMessage = try pqCryptoSign.sign(message: messageBytes, secretKey: secretKey)
    let openedMessage = try pqCryptoSign.open(signedMessage: signedMessage, publicKey: pkBytes)
    
    let openedMessageString = String(bytes: openedMessage, encoding: .utf8)
    
    let endTime = Date()
    let elapsedTime = endTime.timeIntervalSince(startTime)
    let formattedExecutionTime = String(format: "%.4f", elapsedTime)

    print("\nSIGNATURE: \(signature.base64EncodedString())\n")
    print("SIGNED MESSAGE: \(signedMessage.base64EncodedString())\n")
    print("MESSAGE: \(message)\n")
    print("OPENED MESSAGE: \(openedMessageString!)\n")
    print("ELAPSED TIME: \(formattedExecutionTime)\n")
    
    return verify && messageBytes == openedMessage
}
