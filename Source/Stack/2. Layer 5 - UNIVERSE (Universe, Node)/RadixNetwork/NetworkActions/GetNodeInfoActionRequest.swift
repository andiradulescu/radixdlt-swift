//
//  GetNodeInfoActionRequest.swift
//  RadixSDK iOS
//
//  Created by Alexander Cyon on 2019-07-02.
//  Copyright © 2019 Radix DLT. All rights reserved.
//

import Foundation

public struct GetNodeInfoActionRequest: JsonRpcMethodNodeAction {
    public let node: Node
    
    public init(node: Node) {
        self.node = node
    }
}
