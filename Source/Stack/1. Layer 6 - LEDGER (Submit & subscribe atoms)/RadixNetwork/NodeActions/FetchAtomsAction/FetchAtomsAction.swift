//
//  FetchAtomsAction.swift
//  RadixSDK iOS
//
//  Created by Alexander Cyon on 2019-06-26.
//  Copyright © 2019 Radix DLT. All rights reserved.
//

import Foundation

public protocol FetchAtomsAction: NodeAction {
    var address: Address { get }
    var uuid: UUID { get }
}

public struct FetchAtomsActionCancel: FetchAtomsAction {
    public let address: Address
    public let uuid: UUID
    private init(address: Address, uuid: UUID = .init()) {
        self.address = address
        self.uuid = uuid
    }
    public init(request: FetchAtomsActionRequest) {
        self.init(address: request.address, uuid: request.uuid)
    }
}

public struct FetchAtomsActionObservation: FetchAtomsAction {
    public let address: Address
    public let node: Node
    public let atomObservation: AtomObservation
    public let uuid: UUID
}

public struct FetchAtomsActionRequest: FetchAtomsAction, FindANodeRequestAction {
    public let address: Address
    public let uuid: UUID
    
    public init(address: Address, uuid: UUID = .init()) {
        self.address = address
        self.uuid = uuid
    }
    
    public var shards: Shards {
        return Shards(single: address.shard)
    }
}

public struct FetchAtomsActionSubscribe: FetchAtomsAction {
    public let address: Address
    public let node: Node
    public let uuid: UUID
}

//public enum FetchAtomsAction: NodeAction {
//    public typealias Submission = (uuid: UUID, address: Address)
//
//    /// Step 1: Action which signals a new fetch atoms query request
//    case request(Submission)
//
//    /// Step 2: Action which represents a fetch atom query submitted to a specific node.
//    case submitted(Submission, toNode: Node)
//
//    /// Step 3: action which represents an atom observed event from a specific node for an atom fetch flow.
//    case observation(Submission, fromNode: Node, observation: AtomObservation)
//
//    /// Cancel action
//    case cancel(Submission)
//
//}
//
//public extension FetchAtomsAction {
//    var node: Node? {
//        switch self {
//        case .request:
//            // No node assigned yet
//            return nil
//        case .submitted(_, let toNode): return toNode
//        case .observation(_, let fromNode, _): return fromNode
//        case .cancel: return nil
//        }
//    }
//
//    var submission: Submission {
//        switch self {
//        case .request(let submission): return submission
//        case .submitted(let submission, _): return submission
//        case .observation(let submission, _, _): return submission
//        case .cancel(let submission): return submission
//        }
//    }
//}
//
//public extension FetchAtomsAction {
//
//    static func newRequest(address: Address) -> FetchAtomsAction {
//
//        return FetchAtomsAction.request(
//            (UUID.init(), address)
//        )
//    }
//
//    static func cancel(action: FetchAtomsAction) -> FetchAtomsAction {
//        return FetchAtomsAction.cancel(action.submission)
//    }
//}
