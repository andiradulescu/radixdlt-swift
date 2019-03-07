//
//  AtomJsonDeserializationMintedTokenBadValuesSpec.swift
//  RadixSDK iOS Tests
//
//  Created by Alexander Cyon on 2019-02-22.
//  Copyright © 2019 Radix DLT. All rights reserved.
//

@testable import RadixSDK
import Nimble
import Quick

class AtomJsonDeserializationMintedTokenBadValuesSpec: AtomJsonDeserializationChangeJson {
        
    override func jsonString() -> String {
        return """
            {
                "\(RadixModelType.jsonKey)": \(RadixModelType.atom.rawValue),
                "signatures": {},
                "metaData": {},
                "particleGroups": [
                    {
                        "\(RadixModelType.jsonKey)": \(RadixModelType.particleGroup.rawValue),
                        "particles": [
                            {
                                "\(RadixModelType.jsonKey)": \(RadixModelType.spunParticle.rawValue),
                                "spin": 1,
                                "particle": {
                                    "\(RadixModelType.jsonKey)": \(RadixModelType.mintedTokenParticle.rawValue),
                                    "owner": ":byt:A3hanCWf3pmR5E+i+wtWWfKleBrDOQduLb/vcFKOSt9o",
                                    "receiver": ":adr:JH1P8f3znbyrDj8F4RWpix7hRkgxqHjdW2fNnKpR3v6ufXnknor",
                                    "nonce": 992284943125945,
                                    "planck": 24805440,
                                    "amount": ":u20:100000",
                                    "token_reference": ":rri:/JH1P8f3znbyrDj8F4RWpix7hRkgxqHjdW2fNnKpR3v6ufXnkntokens/XRD"
                                }
                            }
                        ],
                        "metaData": {}
                    }
                ]
            }
        """
    }
}