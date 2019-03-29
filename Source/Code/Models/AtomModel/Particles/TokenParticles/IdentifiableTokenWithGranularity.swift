//
//  IdentifiableTokenWithGranularity.swift
//  RadixSDK iOS
//
//  Created by Alexander Cyon on 2019-03-29.
//  Copyright © 2019 Radix DLT. All rights reserved.
//

import Foundation

public protocol IdentifiableTokenWithGranularity {
    var tokenDefinitionIdentifier: TokenDefinitionIdentifier { get }
    var granularity: Granularity { get }
}
