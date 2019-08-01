//
//  AtomSubscriptionCancelling.swift
//  RadixSDK iOS
//
//  Created by Alexander Cyon on 2019-07-09.
//  Copyright © 2019 Radix DLT. All rights reserved.
//

import Foundation
import RxSwift

public protocol AtomSubscriptionCancelling {
    func cancelAtomsSubscription(subscriberId: SubscriberId) -> Completable
}
