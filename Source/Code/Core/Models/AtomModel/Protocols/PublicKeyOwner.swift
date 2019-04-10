//
//  PublicKeyOwner.swift
//  RadixSDK iOS
//
//  Created by Alexander Cyon on 2019-04-10.
//  Copyright © 2019 Radix DLT. All rights reserved.
//

import Foundation

public protocol PublicKeyOwner {
    var publicKey: PublicKey { get }
}
