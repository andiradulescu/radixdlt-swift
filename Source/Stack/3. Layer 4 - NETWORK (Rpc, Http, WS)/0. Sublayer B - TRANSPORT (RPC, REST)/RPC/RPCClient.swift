//
//  RPCClient.swift
//  RadixSDK iOS
//
//  Created by Alexander Cyon on 2019-03-26.
//  Copyright © 2019 Radix DLT. All rights reserved.
//

import Foundation
import RxSwift

// swiftlint:disable colon opening_brace

public protocol RPCClient:
    NodeInfoRequesting,
    LivePeersRequesting,
    UniverseConfigRequesting,
    AtomsByAddressSubscribing,
    AtomSubscriptionCancelling,
    AtomSubmitting
{
    // swiftlint:enable colon opening_brace
}

public protocol AtomSubscriptionCancelling {
    func unsubscribe(subscriberId: SubscriberId) -> Observable<AtomSubscriptionStartOrCancel>
}
