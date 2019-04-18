//
//  NodeDiscoveryTests.swift
//  RadixSDK iOS Tests
//
//  Created by Alexander Cyon on 2019-03-25.
//  Copyright © 2019 Radix DLT. All rights reserved.
//

import Foundation
@testable import RadixSDK
import XCTest
import RxSwift

class NodeDiscoveryTests: XCTestCase {

    func testLocalHost() {
        let nodeDiscovery: NodeDiscoveryHardCoded = .localhost
        guard let nodeArray = nodeDiscovery.loadNodes().blockingTakeFirst() else { return }
        XCTAssertEqual(nodeArray.count, 1)
        let node = nodeArray[0]
        XCTAssertEqual(node.httpUrl.url.absoluteString, "http://localhost:8080/api")
        XCTAssertEqual(node.websocketsUrl.url.absoluteString, "ws://localhost:8080/rpc")
    }
    
    func testBadNode() {
        
        let subject = PublishSubject<NodeNetworkDetails>()
        
        let nodeDiscovery = try! NodeDiscoveryHardCoded(
            hosts: [Host.local()],
            networkDetailsRequestingFactory: { _ in
                return MockedNetworkDetailsRequester(subject: subject)
        }
        )
        subject.onError(MockedError.incompatibleJson)
        XCTAssertThrowsError(try nodeDiscovery.loadNodes().toBlocking(timeout: 1).first(), "Should throw error when receiving error from API") { error in
            guard let networkError = error as? MockedError else {
                return XCTFail("Wrong error")
            }
            XCTAssertEqual(networkError, MockedError.incompatibleJson)
        }
    }
  
    func testNodeFinder() {
        let nodeFinder: NodeFinder = .sunstone
        guard let nodes = nodeFinder.loadNodes().blockingTakeFirst() else { return }
        XCTAssertFalse(nodes.isEmpty)
    }
    
    func testIncorrectIP() {
        // Some incorrect IP address
        let nodeDiscovery = try! NodeDiscoveryHardCoded(hosts: ["35.111.222.212"])
        XCTAssertThrowsError(try nodeDiscovery.loadNodes().take(1).toBlocking(timeout: 1).first())
    }
    
    func testNodeFinderBadURL() {
        let nodeFinder = try! NodeFinder(bootstrapHost: try! Host(ipAddress: "google.com", port: 443))
        XCTAssertThrowsError(try nodeFinder.loadNodes().take(1).toBlocking(timeout: 1).first())
    }
    

    
    
}

struct MockedNetworkDetailsRequester: NodeNetworkDetailsRequesting {
    private let single: SingleWanted<NodeNetworkDetails>
    init(_ single: SingleWanted<NodeNetworkDetails>) {
        self.single = single
    }
    init(subject: PublishSubject<NodeNetworkDetails>) {
        self.init(subject.asObservable())
    }
    func networkDetails() -> SingleWanted<NodeNetworkDetails> {
        return single
    }
}

enum MockedError: Swift.Error, Equatable {
    case incompatibleJson
}
