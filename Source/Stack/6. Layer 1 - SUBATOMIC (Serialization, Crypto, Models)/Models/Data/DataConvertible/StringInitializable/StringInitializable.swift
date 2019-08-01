//
//  StringInitializable.swift
//  RadixSDK iOS
//
//  Created by Alexander Cyon on 2019-01-25.
//  Copyright © 2019 Radix DLT. All rights reserved.
//

import Foundation

public protocol StringInitializable: ExpressibleByStringLiteral, ValidValueInitializable where ValidationValue == String {
    init(string: String) throws
}

public extension StringInitializable {
    init(unvalidated value: ValidationValue) throws {
        try self.init(string: value)
    }
    
    init?(string: String?) throws {
        guard let string = string else {
            return nil
        }
        try self.init(string: string)
    }
}

// MARK: - ExpressibleByStringLiteral
public extension StringInitializable {
    init(stringLiteral value: String) {
        do {
            try self.init(string: value)
        } catch {
            fatalError("Passed bad string value: `\(value)`, error: \(error)")
        }
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
