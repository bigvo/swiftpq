import Foundation
import CryptoKit
import ArgumentParser
import SwiftPQ

@available(macOS 11.0, *)
@main
struct SwiftPQCLI: ParsableCommand {
    @Flag(name: [.short, .long], help: "Generate new keys")
    var generate: Bool = false
    
    @Option(name: [.short, .long], help: "Path to save generated keys")
    var savePath: String? = nil
    
    // MARK: Test delete later
    @Flag(name: [.short, .long], help: "Decrypt and print private key")
    var decrypt: Bool = false
    
    @Flag(name: [.short, .long], help: "Verify if keys are valid")
    var verify: Bool = false
    
    @Option(name: [.short, .long], help: "Path to <path>/private.key & public.key")
    var path: String? = nil
    
    mutating func run() throws {
        let pqCrypto = PQCrypto()
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
            
            let keys = try pqCrypto.generateEncodeKeys(password: pass)
            
            print(keys.publicKey)
            print(keys.secretKey)
            
            if let savePath = savePath {
                do {
                    try saveKeys(publicKey: keys.publicKey, privateKey: keys.secretKey, to: savePath)
                    print("Key succesfully saved.\n")
                } catch {
                    print("Keys weren't saved.")
                }
            }
            return
        }
        
        if decrypt {
            if let path = path {
                // Read the secret key from a file
                let secretKeyPath = "\(path)/private.key"
                var secretKeyData: String = ""
                do {
                    secretKeyData = try String(contentsOf: URL(fileURLWithPath: secretKeyPath))
                } catch {
                    print("Can't read private key from provided path.\n")
                    return
                }
                
                print("Please enter password to decrypt private key:\n")
                guard let password = getpass("Enter password: ") else {
                    return print("Password is required.\n")
                }
                
                let decryptedKey = try pqCrypto.decryptPrivateKey(pemKey: secretKeyData, password: String(cString: password))
                print("DECRYPTED KEY: \(decryptedKey.base64EncodedString())")
                return
            } else {
                print("Path to keys isn't provided. use -p {PATH}")
            }
        }
        
        if verify {
            if let path = path {
                // Read the secret key from a file
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
                guard let decodedPublicKey = decodePemKey(pemKey: publicKeyData) else {
                    print("Unable to decode public key.")
                    return
                }
                
                if validateKeys(pqCrypto: pqCrypto, publicKey: decodedPublicKey, secretKey: decryptedPrivateKey) {
                    print("Keys are valid.")
                    return
                } else {
                    print("Keys are invalid.")
                    return
                }
            } else {
                print("Path to keys isn't provided. use -p {PATH}")
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
func validateKeys(pqCrypto: PQCrypto, publicKey: Data, secretKey: Data) -> Bool {
    let encrypt = pqCrypto.kemEncrypt(publicKey: publicKey.uint8Array)
    let decrypt = pqCrypto.kemDecrypt(ciphertext: encrypt.cipherText, secretKey: secretKey.uint8Array)
    
    if encrypt.sharedSecret == decrypt {
        return true
    }
    return false
}
