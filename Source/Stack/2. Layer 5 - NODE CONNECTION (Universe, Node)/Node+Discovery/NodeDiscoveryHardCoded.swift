//
//  NodeDiscoveryHardCoded.swift
//  RadixSDK iOS
//
//  Created by Alexander Cyon on 2019-03-27.
//  Copyright © 2019 Radix DLT. All rights reserved.
//

import Foundation
import RxSwift

public final class NodeDiscoveryHardCoded: NodeDiscovery {
    private let urls: [FormattedURL]
    
    public typealias MakeNetworkDetailsRequester = (FormattedURL) -> NodeNetworkDetailsRequesting
    private let makeNetworkDetailsRequester: MakeNetworkDetailsRequester
    
    public init(
        hosts: [Host],
        networkDetailsRequestingFactory: @escaping MakeNetworkDetailsRequester = { RESTClientsRetainer.restClient(urlToNode: $0) }
    ) throws {
        self.urls = try hosts.map {
            try URLFormatter.format(url: $0, protocol: .hypertext, useSSL: !$0.isLocal)
        }
        self.makeNetworkDetailsRequester = networkDetailsRequestingFactory
    }
}

// MARK: - NodeDiscovery
public extension NodeDiscoveryHardCoded {
    
    func loadNodes() -> Observable<[Node]> {
        return Observable<[FormattedURL]>.just(urls)
            .flatMap { (nodeUrls: [FormattedURL]) -> Observable<[Node]> in
                let nodeObservables: [Observable<Node>] = nodeUrls.map { [unowned self] (nodeUrl: FormattedURL) -> Observable<Node> in
                    self.makeNetworkDetailsRequester(nodeUrl)
                        .networkDetails()
                        .map { $0.udp }
                        .asObservable()
                        .first(ifEmptyThrow: Error.udpNetworkDetailsEmptyForNode(url: nodeUrl.url))
                        .map {
                            return try Node(
                                info: $0,
                                websocketsUrl: try URLFormatter.format(url: nodeUrl, protocol: .websockets, useSSL: !nodeUrl.isLocal),
                                httpUrl: try URLFormatter.format(url: nodeUrl, protocol: .hypertext, useSSL: !nodeUrl.isLocal)
                            )
                    }
                }
                return Observable.combineLatest(nodeObservables) { $0 }
        }
    }
}

public extension NodeDiscoveryHardCoded {
    enum Error: Swift.Error {
        case udpNetworkDetailsEmptyForNode(url: URL)
    }
}
