//
//  StringInitializable.swift
//  RadixSDK iOS
//
//  Created by Alexander Cyon on 2019-01-25.
//  Copyright © 2019 Radix DLT. All rights reserved.
//

import Foundation

public protocol StringInitializable: Codable, ValidValueInitializable where ValidationValue == String {
    init(string: String) throws
}

public extension StringInitializable {
    init(unvalidated value: ValidationValue) throws {
        try self.init(string: value)
    }
}

extension String: StringInitializable {
   
    public static var jsonPrefix: JSONPrefix {
        return .string
    }
    
    public init(string: String) throws {
        self = string
    }
}
