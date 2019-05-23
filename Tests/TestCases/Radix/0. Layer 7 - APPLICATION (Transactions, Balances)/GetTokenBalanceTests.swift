//
//  GetTokenBalanceTests.swift
//  RadixSDK iOS Tests
//
//  Created by Alexander Cyon on 2019-04-29.
//  Copyright © 2019 Radix DLT. All rights reserved.
//

import XCTest
@testable import RadixSDK
import RxSwift

class GetTokenBalanceTests: XCTestCase {
    
    // RLAU-1119 AC: 0
    func testGetTokenBalance() {
        // GIVEN
        // a Radix Application
        let identity = RadixIdentity()
        let (replaySubject, application) = applicationWithMockedSubscriber(identity: identity)
        
        func atomUpdate(amount: PositiveAmount, spin: Spin, isHead: Bool = false) -> AtomUpdate {
            return AtomUpdate(
                atom: atomTransferrable(amount, address: identity.address, spin: spin),
                isHead: isHead)
        }
        
        // WHEN
        // The node returns an atom with 7 consumable (spin up) XRD
        replaySubject.onNext([
            atomUpdate(amount: 7, spin: .up, isHead: true)
        ])
        
        guard let balance = application.getBalances(for: xrdAddress, ofToken: xrd).blockingTakeFirst() else { return }

        XCTAssertEqual(
            balance.amount,
            7,
            // THEN
            "My balance is 7"
        )
    }

    func testThatOrderOfAtomsDoesNotMatterForBalanceCalculation() {
        // GIVEN
        let identity = RadixIdentity()
        let myAddress = identity.address

        let (replaySubject, application) = applicationWithMockedSubscriber(identity: identity, bufferSize: 3)
        
        func atomUpdate(amount: PositiveAmount, spin: Spin, isHead: Bool = false) -> AtomUpdate {
            return AtomUpdate(
                atom: atomTransferrable(amount, address: myAddress, spin: spin),
                isHead: isHead)
        }
        
        replaySubject.onNext([
           atomUpdate(amount: 1, spin: .down),
           atomUpdate(amount: 1, spin: .up),
           atomUpdate(amount: 1, spin: .up, isHead: true)
        ])
        
        guard let downUpUpBalance = application.getMyBalance(of: xrd).blockingTakeFirst() else { return }
        
        replaySubject.onNext([
            atomUpdate(amount: 1, spin: .up),
            atomUpdate(amount: 1, spin: .down),
            atomUpdate(amount: 1, spin: .up, isHead: true)
            ])

        guard let upDownUpBalance = application.getMyBalance(of: xrd).blockingTakeFirst() else { return }

        XCTAssertAllEqual(
            downUpUpBalance.amount,
            upDownUpBalance.amount,
            1
        )
    }
    
    func testIncrease() {
        // GIVEN
        
        let alice = RadixIdentity()
        let myAddress = alice.address
        let (replaySubject, application) = applicationWithMockedSubscriber(identity: alice)
        
        func atomUpdate(amount: PositiveAmount, spin: Spin, isHead: Bool = false) -> AtomUpdate {
            return AtomUpdate(
                atom: atomTransferrable(amount, address: myAddress, spin: spin),
                isHead: isHead)
        }
        
        replaySubject.onNext([
            atomUpdate(amount: 0, spin: .up, isHead: true)
        ])
        
        guard let aliceStartBalance = application.getMyBalance(of: xrd).blockingTakeFirst() else { return }
        
        XCTAssertEqual(aliceStartBalance.amount, 0)
        
        replaySubject.onNext([
            atomUpdate(amount: 3, spin: .up, isHead: true)
        ])
        
        guard let aliceNewBalance = application.getMyBalance(of: xrd).blockingTakeFirst() else { return }
        
        XCTAssertEqual(aliceNewBalance.amount, 3)
        
    }
}

private extension GetTokenBalanceTests {
    func applicationWithMockedSubscriber(identity: RadixIdentity, bufferSize: Int = 1) -> (subject: ReplaySubject<[AtomUpdate]>, app: DefaultRadixApplicationClient) {
        let replaySubject = ReplaySubject<[AtomUpdate]>.create(bufferSize: bufferSize)
        
        let application = DefaultRadixApplicationClient(
            nodeSubscriber: MockedNodeSubscribing(replaySubject: replaySubject),
            nodeUnsubscriber: MockedNodeUnsubscribing(),
            nodeSubmitter: MockedNodeSubmitting(),
            identity: identity,
            magic: magic
        )
        
        return (subject: replaySubject, app: application)
    }
}

private let xrdAddress: Address = "JH1P8f3znbyrDj8F4RWpix7hRkgxqHjdW2fNnKpR3v6ufXnknor"
private let xrd = ResourceIdentifier(address: xrdAddress, name: "XRD")

private func atomTransferrable(_ amount: PositiveAmount, address: Address, spin: Spin) -> Atom {
    let particle = TransferrableTokensParticle(
        amount: amount,
        address: address,
        tokenDefinitionReference: xrd
    )
    return Atom(particle: particle, spin: spin)
}

private let magic: Magic = 63799298

private extension RadixIdentity {
    init() {
        self.init(magic: magic)
    }
}
