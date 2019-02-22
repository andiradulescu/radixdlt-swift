//
//  DsonDecodable.swift
//  RadixSDK iOS
//
//  Created by Alexander Cyon on 2019-01-25.
//  Copyright © 2019 Radix DLT. All rights reserved.
//

import Foundation

public protocol DsonDecodable: CustomStringConvertible, Decodable {
    static var tag: DsonTag { get }
    associatedtype From: StringInitializable
    init(from: From) throws
}

extension String: DsonDecodable {
    public static var tag: DsonTag { return .string }
    public init(from: String) throws {
        self = from
    }
}

public protocol DsonEncodable: Encodable {
//    static var tag: DsonTag { get }
//    var stringToDecode: String { get }
}

public typealias DsonCodable = DsonDecodable & DsonEncodable

//public extension DsonEncodable {
//    func encode(to encoder: Encoder) throws {
//        var container = encoder.singleValueContainer()
//        try container.encode(Dson(value: ))
//    }
//}
