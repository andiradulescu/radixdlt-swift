//
//  TokenDefinitionParticle+CodingKeys.swift
//  RadixSDK iOS
//
//  Created by Alexander Cyon on 2019-03-08.
//  Copyright © 2019 Radix DLT. All rights reserved.
//

import Foundation

public extension TokenDefinitionParticle {
    enum CodingKeys: String, CodingKey {
        case serializer, version
        
        case symbol, name, description, address, granularity, permissions, icon
    }
}
