//
// MIT License
// 
// Copyright (c) 2018-2019 Radix DLT ( https://radixdlt.com )
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//

import Foundation
import RxSwift

public final class FindANodeEpic: RadixNetworkEpic {
    public typealias PeerSelector = (NonEmptySet<Node>) -> Node
    private let peerSelector: PeerSelector
    
    init(
        peerSelector: @escaping PeerSelector = { $0.randomElement() }
    ) {
        self.peerSelector = peerSelector
    }
}

public extension FindANodeEpic {
    
    func epic(actions: Observable<NodeAction>, networkState: Observable<RadixNetworkState>) -> Observable<NodeAction> {
        return actions.ofType(FindANodeRequestAction.self)
            .flatMap { findANodeRequestAction -> Observable<NodeAction> in
                let connectedNodes: Observable<[Node]> = networkState.map { state in
                    getConnectedNodes(shards: findANodeRequestAction.shards, state: state)
                }
                
                let selectedNode: Observable<NodeAction> = connectedNodes
                    .compactMap { try? NonEmptySet(array: $0) }
                    .firstOrError()
                    .map { [unowned self] in self.peerSelector($0) }
                    .map { FindANodeResultAction(node: $0, request: findANodeRequestAction) }
                    .cache()
                
                let findConnectionAction: Observable<NodeAction> = connectedNodes
                    .filter { $0.isEmpty }
                    .firstOrError()
                    .asCompletable()
                    .andThen(
                        Observable<Int>.timer(RxTimeInterval.seconds(0), period: RxTimeInterval.seconds(1), scheduler: MainScheduler.instance)
                            .withLatestFrom(networkState) { $1 }
                            .flatMapIterable { [unowned self] (state: RadixNetworkState) in
                                self.nextConnectionRequest(shards: findANodeRequestAction.shards, state: state)
                        }
                        
                    )
                    .takeUntil(selectedNode)
                
                let cleanupConnections: Observable<NodeAction> = findConnectionAction
                    .ofType(ConnectWebSocketAction.self)
                    .flatMap { connectWebsocketAction -> Observable<NodeAction> in
                        let node = connectWebsocketAction.node
                        return selectedNode.map { $0.node }
                            .filter { $0 != node }
                            .map { CloseWebSocketAction(node: $0) }
                }
                
                return Observable<NodeAction>.merge(
                    findConnectionAction.concat(selectedNode),
                    cleanupConnections
                )
                
        }
    }
}

private extension FindANodeEpic {
    func nextConnectionRequest(shards: Shards, state: RadixNetworkState) -> [NodeAction] {
        
        let statusMap: [WebSocketStatus: [Node]] = WebSocketStatus.allCases.map { status in
            return KeyValuePair<WebSocketStatus, [Node]>(key: status, value:
                state.nodes
                    .filter { $0.value.websocketStatus == status }
                    .map { $0.key }
            )
            }.toDictionary()
        
        let connectingNodeCount = statusMap.valueFor(key: .connecting)?.count ?? 0
        
        guard connectingNodeCount < maxSimultaneousConnectionsRequest else {
            return []
        }
        
        guard let disconnectedPeers = statusMap.valueFor(key: .disconnected) else {
            return [DiscoverMoreNodesAction()]
        }
        
        let correctShardNodes = try? NonEmptySet(array: disconnectedPeers.filter { state.nodes[$0]?.shardSpace?.intersectsWithShards(shards) ?? false })
        if let correctShardNodes = correctShardNodes {
            return [ConnectWebSocketAction(node: self.peerSelector(correctShardNodes))]
        }
        assert(correctShardNodes == nil, "Non nil correctShardNodes should have been handled above")
        
        guard
            let nodesWithUnknownShard = try? NonEmptySet(array: disconnectedPeers.filter { state.nodes.valueFor(key: $0)?.shardSpace == nil }) else {
                return [DiscoverMoreNodesAction()]
        }
        
        return nodesWithUnknownShard.flatMap {
            [NodeAction](arrayLiteral:
                GetNodeInfoActionRequest(node: $0),
                GetUniverseConfigActionRequest(node: $0)
            )
        }
        
    }
}

private let maxSimultaneousConnectionsRequest = 2

private func getConnectedNodes(shards: Shards, state: RadixNetworkState) -> [Node] {
    return state.nodes
        .filter { $0.value.websocketStatus == .ready }
        .filter { $0.value.shardSpace?.intersectsWithShards(shards) ?? false }
        .map {
            return $0.key
            
        }
    
}
