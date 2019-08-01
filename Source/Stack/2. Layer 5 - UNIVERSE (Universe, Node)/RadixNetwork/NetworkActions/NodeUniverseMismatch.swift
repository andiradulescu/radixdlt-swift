//
//  NodeUniverseMismatch.swift
//  RadixSDK iOS
//
//  Created by Alexander Cyon on 2019-07-02.
//  Copyright © 2019 Radix DLT. All rights reserved.
//

import Foundation

public struct NodeUniverseMismatch: NodeAction {
    public let node: Node
    public let expectedConfig: UniverseConfig
    public let actualConfig: UniverseConfig
}
