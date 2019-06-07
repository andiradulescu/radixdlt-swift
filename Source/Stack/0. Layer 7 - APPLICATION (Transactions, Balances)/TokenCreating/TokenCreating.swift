//
//  TokenCreating.swift
//  RadixSDK iOS
//
//  Created by Alexander Cyon on 2019-05-14.
//  Copyright © 2019 Radix DLT. All rights reserved.
//

import Foundation
import RxSwift

public protocol TokenCreating {
    /// Creates a token
    func create(token: CreateTokenAction) -> SingleWanted<ResourceIdentifier>
}

// swiftlint:disable opening_brace

public extension TokenCreating
where
    Self: NodeInteractingSubmit,
    Self: Magical,
    Self: AtomSigning,
    Self: ProofOfWorkWorking,
    Self: TokensDefinitionsReferencing
{
    // swiftlint:enable opening_brace
    func create(token createToken: CreateTokenAction) -> SingleWanted<ResourceIdentifier> {
        
        log.info("\(createToken.creator) creates new token: \(createToken.identifier)")
        
        let actionToParticleGroupsMapper = DefaultCreateTokenActionToParticleGroupsMapper()
        
        let atom = actionToParticleGroupsMapper.particleGroups(for: createToken).wrapInAtom()
        return performProvableWorkThenSignAndSubmit(atom: atom, powWorker: proofOfWorkWorker)
            .map { createToken.identifier }
            .do(onNext: {
                self.tokens.add(token: Token(tokenConvertible: createToken), resourceIdentifier: $0)
            })
    }
}
