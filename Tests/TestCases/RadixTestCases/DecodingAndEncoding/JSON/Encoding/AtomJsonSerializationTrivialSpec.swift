//
//  AtomJsonSerializationTrivialSpec.swift
//  RadixSDK iOS Tests
//
//  Created by Alexander Cyon on 2019-02-25.
//  Copyright © 2019 Radix DLT. All rights reserved.
//

@testable import RadixSDK
import Nimble
import Quick

class AtomToDsonSpec: QuickSpec {
    override func spec() {
        describe("Dson encoding of trivial atom") {
            it("should not encode empty signatures and empty particle group list") {
                let atom = Atom(metaData: .timestamp("1234567890123"))
                let dson = try! atom.toDSON()
                let dsonHex = dson.hex
                expect(dsonHex).to(contain(try! Atom.CodingKeys.metaData.rawValue.toDSON(output: .all).hex))
                expect(dsonHex).toNot(contain(try! Atom.CodingKeys.signatures.rawValue.toDSON(output: .all).hex))
                expect(dsonHex).toNot(contain(try! Atom.CodingKeys.particleGroups.rawValue.toDSON(output: .all).hex))
            }
        }
    }
}

class AtomJsonSerializationTrivialSpec: QuickSpec {
    
    override func spec() {
        /// Scenario 1
        /// https://radixdlt.atlassian.net/browse/RLAU-943
        describe("JSON serialization - Trivial Atom") {
            let atom = Atom(
                particleGroups: [
                    ParticleGroup(spunParticles: [
                        AnySpunParticle(
                            spin: .up,
                            particle: UniqueParticle(
                                address: "JHdWTe8zD2BMWwMWZxcKAFx1E8kK3UqBSsqxD9UWkkVD78uMCei",
                                uniqueName: "Sajjon"
                            )
                        )
                    ])
                ]
            )
            
            it("should result in the appropriate trival JSON") {
                do {
                    let json = try RadixJSONEncoder(outputFormat: .prettyPrinted).encode(atom)
                    let jsonString = String(data: json)
                    let atomFromJSON = try RadixJSONDecoder().decode(Atom.self, from: jsonString.toData())
                    expect(atomFromJSON).to(equal(atom))
                } catch {
                    fail("unexpected error: \(error)")
                }
            }
        }
        
    }
}

private let expectedJson = """
{
    "\(RadixModelType.jsonKey)": "\(RadixModelType.atom.serializerId)",
    "signatures": {},
    "metaData": {},
    "particleGroups": [
        {
            "\(RadixModelType.jsonKey)": "\(RadixModelType.particleGroup.serializerId)",
            "particles": [
                {
                    "\(RadixModelType.jsonKey)": "\(RadixModelType.spunParticle.serializerId)",
                    "spin": 1,
                    "particle": {
                        "\(RadixModelType.jsonKey)": "\(RadixModelType.uniqueParticle.serializerId)",
                        "name": ":str:Sajjon",
                        "nonce": 0,
                        "address": ":adr:JHdWTe8zD2BMWwMWZxcKAFx1E8kK3UqBSsqxD9UWkkVD78uMCei"
                    }
                }
            ],
            "metaData": {}
        }
    ]
}
"""
