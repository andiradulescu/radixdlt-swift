//
//  StatefulActionToParticleGroupsMapper.swift
//  RadixSDK iOS
//
//  Created by Alexander Cyon on 2019-06-15.
//  Copyright © 2019 Radix DLT. All rights reserved.
//

import Foundation

public protocol BaseStatefulActionToParticleGroupsMapper {
    func requiredStateForAnAction(_ userAction: UserAction) -> [AnyShardedParticleStateId]
    func particleGroupsForAnAction(_ userAction: UserAction, upParticles: [AnyUpParticle]) throws -> ParticleGroups
}

public protocol StatefulActionToParticleGroupsMapper: BaseStatefulActionToParticleGroupsMapper {
    associatedtype Action: UserAction
    func requiredState(for action: Action) -> [AnyShardedParticleStateId]
    func particleGroups(for action: Action, upParticles: [AnyUpParticle]) throws -> ParticleGroups
}

public extension StatefulActionToParticleGroupsMapper {
    func particleGroupsForAnAction(_ userAction: UserAction, upParticles: [AnyUpParticle]) throws -> ParticleGroups {

        // TODO throw error instead of fatalError?
        let action = castOrKill(instance: userAction, toType: Action.self)
        return try particleGroups(for: action, upParticles: upParticles)
    }
    
    func requiredStateForAnAction(_ userAction: UserAction) -> [AnyShardedParticleStateId] {
        // TODO throw error instead of fatalError?
        let action = castOrKill(instance: userAction, toType: Action.self)
        return requiredState(for: action)
    }
}
