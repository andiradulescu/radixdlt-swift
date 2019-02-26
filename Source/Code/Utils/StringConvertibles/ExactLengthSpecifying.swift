//
//  ExactLengthSpecifying.swift
//  RadixSDK iOS
//
//  Created by Alexander Cyon on 2019-02-26.
//  Copyright © 2019 Radix DLT. All rights reserved.
//

import Foundation

public protocol ExactLengthSpecifying: MinLengthSpecifying, MaxLengthSpecifying {
    static var length: Int { get }
}

public extension ExactLengthSpecifying {
    static var minLength: Int {
        return length
    }
    static var maxLength: Int {
        return length
    }
    
    static func validateLength<S>(of stringRepresentable: S) throws where S: StringRepresentable {
        try validateMaxLength(of: stringRepresentable)
        try validateMinLength(of: stringRepresentable)
    }
}
