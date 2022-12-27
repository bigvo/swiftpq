# SwiftPQ - Post-Quantum Crypto Swift library and CLI, based on [PQClean](https://github.com/PQClean/PQClean)

SwiftPQ helps you utilize Post-Quantum Digital Signature and Key Encapsulation schemes in your project.

## Description

SwiftPQ utilizes wrapped C functions from [PQClean](https://github.com/PQClean/PQClean)

**Available algorithms**

*KEM:*
* Kyber512
* Kyber1024
* HQCRMRS128
* HQCRMRS192
* HQCRMRS256

*Digital Signature:*
* Dilithium2
* Dilithium3
* Dilithium5
* Falcon-512
* Falcon-1024

### Usage example - CLI

- Generate keys in required algorithm and save to required path, --save <path> is optional
```
./SwiftPQCLI -g -a kyber512 --save .
```

- Validate generated keys, -p <path> to keys should be provided
```
./SwiftPQCLI -c -a kyber512 -p <path>
```

- Sign any message, works only with Digital Signatures schemes
```
./SwiftPQCLI -s -m <message> -p <pathToKeys> -a <algorithm>
```

- Verify signature 
```
./SwiftPQCLI --signature <signature> -m <message> -p <pathToKeys> -a <algorithm>
```

### Usage example - Library

Add it to your App:

```swift
.package(url: "https://github.com/bigvo/swiftpq.git", from: "0.0.1"),
```

import with

```swift
import SwiftPQ
```

Use with your Vapor app:

```swift
    // Play with KEM
    
    let kyber512 = PQCrypto.KEM.Kyber512()
    let keys = kyber512.kemKeypair()
    let encrypt = kyber512.kemEncrypt(publicKey: keys.publicKey)
    let sharedSecret = kemDecrypt.kemDecrypt(cipherText: encrypt.cipherText, secretKey: keys.secretKey)
    
    if encrypt.sharedSecret == sharedSecret {
        // Do something
    }
    
    // Play with Digital Signatures
    
    let dilithium2 = PQCrypto.SIGN.Dilithium2()
    let keys = dilithium2.signKeypair()
    ...
```

## License
Each subdirectory containing implementations contains a `LICENSE` file stating under what license that specific implementation is released.
The files in `common` contain licensing information at the top of the file (and are currently either public domain or MIT).
All other code in this repository is released under the conditions of MIT.
