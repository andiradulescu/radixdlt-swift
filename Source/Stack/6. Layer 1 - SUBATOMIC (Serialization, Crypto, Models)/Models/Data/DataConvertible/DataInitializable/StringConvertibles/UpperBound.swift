//
//  UpperBound.swift
//  RadixSDK iOS
//
//  Created by Alexander Cyon on 2019-02-25.
//  Copyright © 2019 Radix DLT. All rights reserved.
//

import Foundation

public protocol UpperBound {
    static var maxValue: Int { get }
}

public extension UpperBound {
    var maxValue: Int {
        return Self.maxValue
    }
}