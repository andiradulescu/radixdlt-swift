//
//  SendMessageActionToParticleGroupsMapper.swift
//  RadixSDK iOS
//
//  Created by Alexander Cyon on 2019-05-29.
//  Copyright © 2019 Radix DLT. All rights reserved.
//

import Foundation

public protocol SendMessageActionToParticleGroupsMapper: StatelessActionToParticleGroupsMapper where Action == SendMessageAction {}
