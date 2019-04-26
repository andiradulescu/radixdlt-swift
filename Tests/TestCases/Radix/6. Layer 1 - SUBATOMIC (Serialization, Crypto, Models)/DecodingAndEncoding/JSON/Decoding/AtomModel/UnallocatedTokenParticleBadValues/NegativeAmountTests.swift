//
//  NegativeAmountTests.swift
//  RadixSDK iOS Tests
//
//  Created by Alexander Cyon on 2019-02-22.
//  Copyright © 2019 Radix DLT. All rights reserved.
//

@testable import RadixSDK
import XCTest

class NegativeAmountTests: AtomJsonDeserializationUnallocatedTokenBadValuesTests {
    func testJsonDecodingUnallocatedTokensParticleNegativeAmount() {
        // GIVEN
        let badJson = self.replaceValueInTokenParticle(for: .amount, with: ":u20:-1")
        
        XCTAssertThrowsSpecificError(
            // WHEN
            // I try decoding the bad json string into an Atom
            try decode(Atom.self, jsonString: badJson),
            // THEN
            InvalidStringError.invalidCharacters(expectedCharacters: CharacterSet.decimalDigits, butGot: "-1"),
            "Decoding should fail to deserialize JSON with negative granularity"
        )
    }
}