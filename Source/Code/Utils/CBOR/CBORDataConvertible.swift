//
//  CBORDataConvertible.swift
//  RadixSDK iOS
//
//  Created by Alexander Cyon on 2019-03-12.
//  Copyright © 2019 Radix DLT. All rights reserved.
//

import Foundation

public protocol DSONPrefixedDataConvertible: CBORConvertible, DSONPrefixSpecifying {
    var dborEncodedData: Data { get }
}

public typealias CBORDataConvertible = DSONPrefixedDataConvertible & DataConvertible

// MARK: - DSONPrefixSpecifying
public extension DSONPrefixedDataConvertible where Self: DataConvertible {
    
    var dborEncodedData: Data {
        return asData
    }
    
    var dsonPrefix: DSONPrefix {
        return .bytesBase64
    }
}

// MARK: - CBORConvertible
public extension DSONPrefixedDataConvertible {
    func toCBOR() -> CBOR {
        return CBOR.bytes(dborEncodedData, dsonPrefix: dsonPrefix)
    }
}
