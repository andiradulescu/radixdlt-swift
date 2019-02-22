//
//  AtomJsonDeserializationSpec.swift
//  RadixSDKTests
//
//  Created by Alexander Cyon on 2019-01-22.
//  Copyright © 2019 Radix DLT. All rights reserved.
//

@testable import RadixSDK

import Nimble
import Quick


struct UnexpectedNilError: Error {}

class AtomJsonDeserializationSpec: QuickSpec {
    
    override func spec() {
        
        describe("JSON deserialization - RLAU-567") {
            
            describe("Scenario 1: Trivial Atom") {
                let atom: Atom = model(from: trivialAtomJson)
                it("should contain empty MetaData") {
                    expect(atom.metaData).to(beEmpty())
                }
                it("should contain empty Signatures") {
                    expect(atom.signatures).to(beEmpty())
                }
                it("should contain one single ParticleGroup") {
                    expect(atom.particleGroups).to(haveCount(1))
                    expect(atom.particleGroups).to(containElementSatisfying({ particleGroup in
                        return particleGroup.isEmpty
                    }, "which contains zero particles"))
                }
            }
            
            describe("Scenario 2: Incorrect JSON Key") {
                it("should fail with decoding error") {
                    let badJson = """
                        {
                            "signatures": {},
                            "metaData": {},
                            "p4rticleGroups": [
                                {
                                    "particles": [],
                                    "metaData": {}
                                }
                            ]
                        }
                        """.data(using: .utf8)!
                    do {
                        _ = try JSONDecoder().decode(Atom.self, from: badJson)
                        fail("Should not be able to decode json with incorrect key")
                    } catch {
                        expect(error).to(beAKindOf(DecodingError.self))
                    }
                }
            }
            
            describe("Scenario 3: Non trivial Atom") {
                let atom: Atom = model(from: nonTrivialAtomJson)
                describe("Its non empty Signature") {
                    let signature = atom.signatures["71c3c2fc9fee73b13cad082800a6d0de"]!
                    it("should contain a BigInteger r") {
                        expect(signature.r).to(equal(BigUnsignedInt(hex: "94542c69265b3c55c7402d3bc358999d00a9b8ba846fd58fa19ea01dd3bc7017")))
                    }
                }
                describe("Its non empty ParticleGroup") {
                    let particleGroup = atom.particleGroups[0]
                    it("should contain a TokenDefinitionParticle") {
                        expect(particleGroup[0].particle).to(beAKindOf(TokenDefinitionParticle.self))
                    }
                    describe("The ParticleGroup's TokenDefinitionParticle") {
                        let tokenDefinitionParticle = particleGroup[0].particle as! TokenDefinitionParticle
                        
                        it("has a name") {
                            expect(tokenDefinitionParticle.name).to(equal("Cyon"))
                        }
                        
                        it("has a symbol") {
                            expect(tokenDefinitionParticle.symbol).to(equal("CCC"))
                        }
                        
                        it("has a description") {
                            expect(tokenDefinitionParticle.description).to(equal("Cyon Crypto Coin is the worst shit coin"))
                        }
                        
                        describe("Its non-empty metadata") {
                            let metaData = tokenDefinitionParticle.metaData
                            it("contains two values") {
                                expect(metaData).to(haveCount(2))
                            }
                        }
                    }
                }
            }
            
            describe("Scenario 4: Too long symbol name") {
                let badJson = """
                        {
                            "signatures": {},
                            "metaData": {},
                            "particleGroups": [
                                {
                                    "particles": [
                                        {
                                            "spin": 1,
                                            "particle": {
                                                "type": "tokenDefinition",
                                                "symbol": ":str:01234567890123456",
                                                "name": ":str:BadCoin",
                                                "description": ":str:The symbol of this coin too many chars",
                                                "metaData": {},
                                                "granularity": ":u20:1",
                                                "permissions": {
                                                    "burn": ":str:none"
                                                },
                                                "address": ":adr:JHdWTe8zD2BMWwMWZxcKAFx1E8kK3UqBSsqxD9UWkkVD78uMCei"
                                            }
                                        }
                                    ],
                                    "metaData": {}
                                }
                            ]
                        }
                        """.data(using: .utf8)!
                
                it("should fail to deserialize JSON with too long symbol") {
                    do {
                        let atom = try JSONDecoder().decode(Atom.self, from: badJson)
                        fail("Should not be able to decode JSON with a TokenDefinitionParticle having a symbol with too many characters, symbol value: \(atom.particleGroups[0].spunParticles[0].particle(as: TokenDefinitionParticle.self)!.symbol)")
                    } catch let error as InvalidStringError {
                        switch error {
                        case .tooManyCharacters(let expectedAtMost, let butGot):
                            expect(expectedAtMost).to(equal(16))
                            expect(butGot).to(equal(17))
                        default: fail("wrong error")
                        }
                    } catch {
                        fail("Wrong error type, got: \(error)")
                    }
                }
            }
            
            describe("Scenario 5: Bad int value for spin") {
                let badJson = """
                        {
                            "signatures": {},
                            "metaData": {},
                            "particleGroups": [
                                {
                                    "particles": [
                                        {
                                            "spin": 2,
                                            "particle": {
                                                "type": "mintedToken",
                                                "owner": ":byt:A3hanCWf3pmR5E+i+wtWWfKleBrDOQduLb/vcFKOSt9o",
                                                "receiver": ":adr:JH1P8f3znbyrDj8F4RWpix7hRkgxqHjdW2fNnKpR3v6ufXnknor",
                                                "nonce": 992284943125945,
                                                "planck": 24805440,
                                                "amount": ":u20:1000000000000000000000000000",
                                                "token_reference": ":rri:/JH1P8f3znbyrDj8F4RWpix7hRkgxqHjdW2fNnKpR3v6ufXnknor/tokens/XRD"
                                            }
                                        }
                                    ],
                                    "metaData": {}
                                }
                            ]
                        }
                        """.data(using: .utf8)!
                
                it("should fail to deserialize JSON with a particle of spin 2") {
                    do {
                        let atom = try JSONDecoder().decode(Atom.self, from: badJson)
                        fail("Should not be able to decode JSON with a spin of: \(atom.particleGroups[0].spunParticles[0].spin.rawValue)")
                    } catch let error as DecodingError {
                        switch error {
                        case .dataCorrupted(let context):
                            expect(context.debugDescription).to(contain("Cannot initialize Spin from invalid Int value 2"))
                        default: fail("wrong error")
                        }
                    } catch {
                        fail("Wrong error type, got: \(error)")
                    }
                }
            }
        }
    }
}

let trivialAtomJson = """
{
    "signatures": {},
    "metaData": {},
    "particleGroups": [
        {
            "particles": [],
            "metaData": {}
        }
    ]
}
"""

let nonTrivialAtomJson = """
{
    "signatures": {
        "71c3c2fc9fee73b13cad082800a6d0de":{
            "r":":byt:AJRULGkmWzxVx0AtO8NYmZ0Aqbi6hG/Vj6GeoB3TvHAX",
            "s":":byt:AKbKCyHw9GYP6EyjbyQackXtF4Hj7CgX2fmTltg5VX9H"
        }
    },
    "metaData": {},
    "particleGroups": [
        {
            "metaData": {},
            "particles": [
                {
                    "spin": 1,
                    "particle": {
                        "type": "tokenDefinition",
                        "symbol": ":str:CCC",
                        "name": ":str:Cyon",
                        "description": ":str:Cyon Crypto Coin is the worst shit coin",
                        "metaData": {
                            "foo": ":str:bar",
                            "bar": ":str:buz"
                        },
                        "granularity": ":u20:1",
                        "permissions": {
                            "burn": ":str:none",
                            "mint": ":str:pow",
                            "transfer": ":str:none"
                        },
                        "address": ":adr:JHdWTe8zD2BMWwMWZxcKAFx1E8kK3UqBSsqxD9UWkkVD78uMCei"
                    }
                }
            ]
        },
        {
            "metaData": {},
            "particles": [
                {
                    "spin": 1,
                    "particle": {
                        "type": "mintedToken",
                        "owner": ":byt:A3hanCWf3pmR5E+i+wtWWfKleBrDOQduLb/vcFKOSt9o",
                        "receiver": ":adr:JH1P8f3znbyrDj8F4RWpix7hRkgxqHjdW2fNnKpR3v6ufXnknor",
                        "nonce": 992284943125945,
                        "planck": 24805440,
                        "amount": ":u20:1000000000000000000000000000",
                        "token_reference": ":rri:/JH1P8f3znbyrDj8F4RWpix7hRkgxqHjdW2fNnKpR3v6ufXnknor/tokens/XRD"
                    }
                }
            ]
        }
    ]
}
"""
