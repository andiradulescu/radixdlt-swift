//
//  AnyDecodable.swift
//  RadixSDK iOS
//
//  Created by Alexander Cyon on 2019-05-20.
//  Copyright © 2019 Radix DLT. All rights reserved.
//

import Foundation

/// Container for any decodable type, this is probably only useful when we would like to print some JSON that failed
/// to decode into our own types. Useful in e.g. a custom DecodingError message, where we would like to include the JSON
/// that we failed to decode.
public struct AnyDecodable: Decodable {
    public let value: Any
    
    public init(_ value: Any?) {
        self.value = value ?? ()
    }
}

// MARK: - Decodable
public extension AnyDecodable {
    // Code from: https://github.com/Flight-School/Guide-to-Swift-Codable-Sample-Code/blob/master/Chapter%203/AnyDecodable.playground/Sources/AnyDecodable.swift
    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        
        if container.decodeNil() {
            self.value = ()
        } else if let bool = try? container.decode(Bool.self) {
            self.value = bool
        } else if let int = try? container.decode(Int.self) {
            self.value = int
        } else if let uint = try? container.decode(UInt.self) {
            self.value = uint
        } else if let double = try? container.decode(Double.self) {
            self.value = double
        } else if let string = try? container.decode(String.self) {
            self.value = string
        } else if let array = try? container.decode([AnyDecodable].self) {
            self.value = array.map { $0.value }
        } else if let dictionary = try? container.decode([String: AnyDecodable].self) {
            self.value = dictionary.mapValues { $0.value }
        } else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "AnyCodable value cannot be decoded")
        }
    }
}
