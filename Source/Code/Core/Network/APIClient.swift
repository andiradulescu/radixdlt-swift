//
//  APIClient.swift
//  RadixSDK iOS
//
//  Created by Alexander Cyon on 2019-01-23.
//  Copyright © 2019 Radix DLT. All rights reserved.
//

import Foundation
import RxSwift

public protocol APIClient: AtomSubmitter {
    var networkState: BehaviorSubject<NetworkState> { get }
    var nodeActions: PublishSubject<NodeAction> { get }
    func fetchAtoms(for address: Address) -> Observable<AtomObservation>
    func submit(atom: Atom) -> Observable<SubmitAtomAction>
}
