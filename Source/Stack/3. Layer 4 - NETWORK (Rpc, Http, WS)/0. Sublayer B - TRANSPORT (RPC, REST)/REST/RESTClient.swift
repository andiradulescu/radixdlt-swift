//
//  RESTClient.swift
//  RadixSDK iOS
//
//  Created by Alexander Cyon on 2019-04-11.
//  Copyright © 2019 Radix DLT. All rights reserved.
//

import Foundation

public protocol RESTClient: NodeNetworkDetailsRequesting, LivePeersRequesting, NodeAddressRequesting {}
