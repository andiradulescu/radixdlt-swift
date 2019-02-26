//
//  LowerBound.swift
//  RadixSDK iOS
//
//  Created by Alexander Cyon on 2019-02-25.
//  Copyright © 2019 Radix DLT. All rights reserved.
//

import Foundation

public protocol LowerBound {
    static var minValue: Int { get }
}

public extension LowerBound {
    var minValue: Int {
        return Self.minValue
    }
}
