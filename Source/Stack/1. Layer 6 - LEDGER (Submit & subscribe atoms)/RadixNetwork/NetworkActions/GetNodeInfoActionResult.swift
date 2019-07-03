//
//  GetNodeInfoActionResult.swift
//  RadixSDK iOS
//
//  Created by Alexander Cyon on 2019-07-02.
//  Copyright © 2019 Radix DLT. All rights reserved.
//

import Foundation

public struct GetNodeInfoActionResult: JsonRpcResultAction {
    public let node: Node
    private let nodeInfo: NodeInfo
    
    public init(node: Node, result: Result) {
        self.node = node
        self.nodeInfo = result
    }
}

public extension GetNodeInfoActionResult {
    typealias Result = NodeInfo
    var result: Result {
        return nodeInfo
    }
}
