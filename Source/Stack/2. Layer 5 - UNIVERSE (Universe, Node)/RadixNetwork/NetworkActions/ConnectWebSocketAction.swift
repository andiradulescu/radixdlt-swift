//
//  ConnectWebSocketAction.swift
//  RadixSDK iOS
//
//  Created by Alexander Cyon on 2019-07-02.
//  Copyright © 2019 Radix DLT. All rights reserved.
//

import Foundation

public struct ConnectWebSocketAction: NodeAction {
    public let node: Node
    init(node: Node) {
        self.node = node
    }
}
