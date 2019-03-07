//
//  ValueValidating.swift
//  RadixSDK iOS
//
//  Created by Alexander Cyon on 2019-02-25.
//  Copyright © 2019 Radix DLT. All rights reserved.
//

import Foundation

public protocol ValueValidating {
    associatedtype ValidationValue: Comparable
    static func validate(_ value: ValidationValue) throws -> ValidationValue
}