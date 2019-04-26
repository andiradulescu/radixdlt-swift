//
//  UniqueParticle.swift
//  RadixSDK iOS
//
//  Created by Alexander Cyon on 2019-01-24.
//  Copyright © 2019 Radix DLT. All rights reserved.
//

import Foundation

// swiftlint:disable colon

/// A representation of something unique.
public struct UniqueParticle:
    ParticleConvertible,
    RadixModelTypeStaticSpecifying,
    RadixCodable {
// swiftlint:enable colon

    public static let serializer = RadixModelType.uniqueParticle
    public let address: Address
    public let name: Name
    public let nonce: Nonce
    
    public init(
        address: Address,
        uniqueName name: Name,
        nonce: Nonce = Nonce()
        ) {
        self.address = address
        self.name = name
        self.nonce = nonce
    }
}

// MARK: Codable
public extension UniqueParticle {

    enum CodingKeys: String, CodingKey {
        case serializer, version
        case address, name, nonce
    }
    
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        address = try container.decode(Address.self, forKey: .address)
        name = try container.decode(Name.self, forKey: .name)
        nonce = try container.decode(Nonce.self, forKey: .nonce)
    }
    
    func encodableKeyValues() throws -> [EncodableKeyValue<CodingKeys>] {
        return [
            EncodableKeyValue(key: .address, value: address),
            EncodableKeyValue(key: .name, value: name),
            EncodableKeyValue(key: .nonce, value: nonce)
        ]
    }
}

public extension UniqueParticle {
    var identifier: ResourceIdentifier {
        return ResourceIdentifier(address: address, name: name.stringValue)
    }
}
