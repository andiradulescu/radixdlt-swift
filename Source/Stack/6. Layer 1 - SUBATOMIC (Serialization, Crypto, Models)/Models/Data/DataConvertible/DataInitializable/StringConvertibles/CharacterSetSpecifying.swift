//
//  CharacterSetSpecifying.swift
//  RadixSDK iOS
//
//  Created by Alexander Cyon on 2019-01-22.
//  Copyright © 2019 Radix DLT. All rights reserved.
//

import Foundation

public protocol CharacterSetSpecifying {
    static var allowedCharacters: CharacterSet { get }
}

public extension CharacterSetSpecifying {
    var allowedCharacters: CharacterSet {
        return Self.allowedCharacters
    }
    
    static func isSupersetOfCharacters(in string: String) -> Bool {
        return allowedCharacters.isSuperset(of: CharacterSet(charactersIn: string))
    }
    
    static func disallowedCharacters(in string: String) -> String? {
        for char in string {
            for unicodeScalar in char.unicodeScalars {
                guard allowedCharacters.contains(unicodeScalar) else {
                    return String(unicodeScalar)
                }
            }
        }
        return nil
    }
    
    static func validateCharacters(in string: String) throws {
        if let disallowed = disallowedCharacters(in: string) {
            throw InvalidStringError.invalidCharacters(expectedCharacters: allowedCharacters, butGot: disallowed)
        }
    }
}