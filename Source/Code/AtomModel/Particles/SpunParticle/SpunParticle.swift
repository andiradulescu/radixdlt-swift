//
//  SpunParticle.swift
//  RadixSDK iOS
//
//  Created by Alexander Cyon on 2019-01-21.
//  Copyright © 2019 Radix DLT. All rights reserved.
//

import Foundation

public struct SpunParticle: Codable {
    public let particle: ParticleConvertible
    public let spin: Spin
}

// MARK: - Deodable
public extension SpunParticle {
    
    public enum CodingKeys: CodingKey {
        case particle, spin
    }
    
    private enum ParticleTypeKey: String, CodingKey {
        case type
    }
    
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let particleNestedContainer = try container.nestedContainer(keyedBy: ParticleTypeKey.self, forKey: .particle)
        let particleType = try particleNestedContainer.decode(ParticleTypes.self, forKey: .type)
        switch particleType {
        case .message: particle = try container.decode(MessageParticle.self, forKey: .particle)
        case .burnedToken, .transferredToken, .mintedToken:
            particle = try container.decode(TokenParticle.self, forKey: .particle)
        case .tokenDefinition: particle = try container.decode(TokenDefinitionParticle.self, forKey: .particle)
        case .unique: particle = try container.decode(UniqueParticle.self, forKey: .particle)
        }
        spin = try container.decode(Spin.self, forKey: .spin)
    }
}

// MARK: - Encodable
public extension SpunParticle {
    
    func encode(to encoder: Encoder) throws {
        var encoder = encoder.container(keyedBy: CodingKeys.self)
        if let messageParticle = particle as? MessageParticle {
            try encoder.encode(messageParticle, forKey: .particle)
        } else if let tokenParticle = particle as? TokenParticle {
            try encoder.encode(tokenParticle, forKey: .particle)
        } else if let uniqueParticle = particle as? UniqueParticle {
            try encoder.encode(uniqueParticle, forKey: .particle)
        }
        try encoder.encode(spin, forKey: .spin)
    }
}

public extension SpunParticle {
    static func up(particle: ParticleConvertible) -> SpunParticle {
        return SpunParticle(particle: particle, spin: .up)
    }
    
    static func down(particle: ParticleConvertible) -> SpunParticle {
        return SpunParticle(particle: particle, spin: .down)
    }
    
    func particle<P>(as type: P.Type) -> P? where P: ParticleConvertible {
        return particle.as(P.self)
    }
}
