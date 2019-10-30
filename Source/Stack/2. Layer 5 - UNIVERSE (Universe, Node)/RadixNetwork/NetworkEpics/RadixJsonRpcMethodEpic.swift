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
import Combine

// swiftlint:disable colon opening_brace

/// A multipurpose RadixNetworkEpic wrapping JSON-RPC API calls
public final class RadixJsonRpcMethodEpic<Request, RpcMethodResult>:
    NetworkWebsocketEpic
where
    Request: JsonRpcMethodNodeAction,
    RpcMethodResult: JsonRpcResultAction
{
    
    // swiftlint:enable colon opening_brace

    // TODO: Precision should return `Single`?
    public typealias MethodCall = (RPCClient, Request) -> AnyPublisher<RpcMethodResult, Never>
    
    public let webSockets: WebSocketsEpic.WebSockets
    private let methodCall: MethodCall
    
    private init(
        webSockets: WebSocketsEpic.WebSockets,
        methodCall: @escaping MethodCall
    ) {
        self.webSockets = webSockets
        self.methodCall = methodCall
    }
}

public extension RadixJsonRpcMethodEpic {
    
    func epic(
        actions: CombineObservable<NodeAction>,
        networkState: CombineObservable<RadixNetworkState>
    ) -> CombineObservable<NodeAction> {
        
        combineMigrationInProgress()
//        return actions
//            .ofType(Request.self)
//            .flatMapSingle { [unowned self] (rpcMethod: Request) -> AnyPublisher<Result, Never> in
//                return self.waitForConnectionReturnWS(toNode: rpcMethod.node)
//                    .map { DefaultRPCClient(channel: $0) }
//                    .flatMap { rpcClient -> AnyPublisher<Result> in
//                        return self.methodCall(rpcClient, rpcMethod)
//                    }
//            }.map { $0 }
    }
}

// MARK: Instances
public extension RadixJsonRpcMethodEpic {
    
    static func createGetLivePeersEpic(webSockets: WebSocketsEpic.WebSockets) -> NetworkWebsocketEpic {
        
//        return RadixJsonRpcMethodEpic<GetLivePeersActionRequest, GetLivePeersActionResult>(
//            webSockets: webSockets
//        ) { (rpcClient: RPCClient, action: GetLivePeersActionRequest) -> AnyPublisher<GetLivePeersActionResult, Never> in
//
//            rpcClient.getLivePeers().map { GetLivePeersActionResult(node: action.node, result: $0) }
//        }
        combineMigrationInProgress()
    }
    
    static func createGetNodeInfoEpic(webSockets: WebSocketsEpic.WebSockets) -> NetworkWebsocketEpic {
//        return RadixJsonRpcMethodEpic<GetNodeInfoActionRequest, GetNodeInfoActionResult>(
//            webSockets: webSockets
//        ) { (rpcClient: RPCClient, action: GetNodeInfoActionRequest) -> AnyPublisher<GetNodeInfoActionResult, Never> in
//            rpcClient.getInfo().map { GetNodeInfoActionResult(node: action.node, result: $0) }.asSingle()
//
//        }
        combineMigrationInProgress()
    }
    
    static func createUniverseConfigEpic(webSockets: WebSocketsEpic.WebSockets) -> NetworkWebsocketEpic {
        
//        return RadixJsonRpcMethodEpic<GetUniverseConfigActionRequest, GetUniverseConfigActionResult>(
//            webSockets: webSockets
//        ) { (rpcClient: RPCClient, action: GetUniverseConfigActionRequest) -> AnyPublisher<GetUniverseConfigActionResult, Never> in
//
//            rpcClient.getUniverseConfig().map { GetUniverseConfigActionResult(node: action.node, result: $0) }.asSingle()
//        }
//
        combineMigrationInProgress()
    }
}
