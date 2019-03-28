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
                "\(RadixModelType.jsonKey)": \(RadixModelType.atom.serializerId),
                "signatures": {},
                "metaData": {},
                "particleGroups": [
                    {
                        "\(RadixModelType.jsonKey)": \(RadixModelType.particleGroup.serializerId),
                        "particles": [
                            {
                                "\(RadixModelType.jsonKey)": \(RadixModelType.spunParticle.serializerId),
                                "spin": 1,
                                "particle": {
                                    "\(RadixModelType.jsonKey)": \(RadixModelType.mintedTokensParticle.serializerId),
                                    "address": ":adr:JH1P8f3znbyrDj8F4RWpix7hRkgxqHjdW2fNnKpR3v6ufXnknor",
                                    "granularity": ":u20:1",
                                    "nonce": 992284943125945,
                                    "planck": 24805440,
                                    "amount": ":u20:100000",
                                    "tokenDefinitionReference": ":rri:/JH1P8f3znbyrDj8F4RWpix7hRkgxqHjdW2fNnKpR3v6ufXnkntokens/XRD"
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
