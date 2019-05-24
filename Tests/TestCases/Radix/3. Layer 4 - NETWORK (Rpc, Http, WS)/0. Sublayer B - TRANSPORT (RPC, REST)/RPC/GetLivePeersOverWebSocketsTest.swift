//
//  WebSocketsGetLivePeersTest.swift
//  RadixSDK iOS Tests
//
//  Created by Alexander Cyon on 2019-03-27.
//  Copyright © 2019 Radix DLT. All rights reserved.
//

import Foundation
@testable import RadixSDK
import XCTest
import RxSwift
import RxTest


class GetLivePeersOverWebSocketsTest: WebsocketTest {
    
    func testLivePeersOverWS() {
        guard let rpcClient = makeRpcClient() else { return }
        guard let livePeers = rpcClient.getLivePeers().blockingTakeFirst(timeout: 1) else { return }
        
        XCTAssertEqual(livePeers.count, 1)
        let livePeer = livePeers[0]
        XCTAssertFalse(livePeer.host.ipAddress.isEmpty)
    }
    
    // This is kind of a test of my mock
    func testLivePeersMockedGoodJson() {
        let subject = ReplaySubject<String>.create(bufferSize: 1)
        let mockedWebsocket = MockedWebsocket(subject: subject)
        let mockedRpcClient = MockedRPCClient(channel: mockedWebsocket)
        subject.onNext(goodJsonLivePeers)
        
        guard let livePeers = mockedRpcClient.getLivePeers().blockingTakeFirst(timeout: 1) else { return }
        
        XCTAssertEqual(livePeers.count, 1)
        let livePeer = livePeers[0]
        XCTAssertFalse(livePeer.host.ipAddress.isEmpty)
    }
    
    func testLivePeersMockedBadJson() {
        let subject = ReplaySubject<String>.create(bufferSize: 1)
        let mockedWebsocket = MockedWebsocket(subject: subject)
        let mockedRpcClient = MockedRPCClient(channel: mockedWebsocket)
        subject.onNext(badJsonLivePeers)

        XCTAssertThrowsSpecificError(
            try mockedRpcClient.getLivePeers().take(1).toBlocking(timeout: 1).first(),
            RPCError.failedToDecodeResponse(DecodingError.keyNotFound(NodeInfo.CodingKeys.system)),
            "Should throw error when receiving error from API"
        )
    }
    
}

struct MockedWebsocket: FullDuplexCommunicationChannel {
    func sendMessage(_ message: String) {
        /* doing nothing */
    }

    var messages: Observable<String>
    init(messages: Observable<String>) {
        self.messages = messages
    }
    
    init(subject: ReplaySubject<String>) {
        self.init(messages: subject.asObservable())
    }
}

struct MockedRPCClient: RPCClient, FullDuplexCommunicating {
    let channel: FullDuplexCommunicationChannel
    init(channel: FullDuplexCommunicationChannel) {
        self.channel = channel
    }
    
    func getLivePeers() -> SingleWanted<[NodeInfo]> {
        return channel.responseForMessage(with: nil)
    }
    
    func getUniverseConfig() -> SingleWanted<UniverseConfig> {
        return channel.responseForMessage(with: nil)
    }
}

private let goodJsonLivePeers = """
{
	"id": 0,
	"jsonrpc": "2.0",
	"result": [
		{
			"hid": ":uid:817bcb056b2cbc054ee536aa8c680499",
			"host": {
				"ip": ":str:172.18.0.3",
				"port": 30000
			},
			"serializer": "\(RadixModelType.nodeInfo.serializerId)",
			"system": {
				"agent": {
					"name": ":str:/Radix:/2700000",
					"protocol": 100,
					"version": 2700000
				},
				"clock": 5,
				"commitment": ":hsh:1e00000000000000000000000000000000000000000000000000000000000000",
				"hid": ":uid:bfe488a94313036680a0ecbb69cb7f1b",
				"key": ":byt:AlXEENfkjHDcySk4Ivc5vyRFxilXNuIJGzyfZ91IuBo2",
				"nid": ":uid:fb04c011af5ad0bbbc0f0bf1f8591e0f",
				"planck": 25925352,
				"port": 30000,
				"serializer": "\(RadixModelType.radixSystem.serializerId)",
				"shards": {
					"high": 9223372036854775807,
					"low": -9223372036854775808
				},
				"version": 100
			},
			"version": 100
		}
	]
}
"""

private let badJsonLivePeers = """
{
	"id": 0,
	"jsonrpc": "2.0",
	"result": [
		{
			"host": {
				"ip": ":str:172.18.0.3",
				"port": 30000
			}
		}
	]
}
"""
