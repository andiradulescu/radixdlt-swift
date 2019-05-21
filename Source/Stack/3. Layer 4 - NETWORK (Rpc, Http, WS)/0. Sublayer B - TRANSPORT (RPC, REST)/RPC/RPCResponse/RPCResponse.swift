//
//  RPCResponse.swift
//  RadixSDK iOS
//
//  Created by Alexander Cyon on 2019-03-29.
//  Copyright © 2019 Radix DLT. All rights reserved.
//

import Foundation

/// Simple although important wrapper of _ALL_ JSON-RPC responses, taking a `ResultOrParam` which must conform to Decodable and decodes the
/// JSON from the RPC API. It can be on two different formats:
///
/// Either we get a response containing a requestId (`"id"`), matching the number sent in our request. This also contains the JSON key
/// and value for `"result"`, this is the first message response of the `Atoms.subscribe` request, followed by two messages on the other
/// format.
/// ```
///     {
///         "id": 1,
///         "jsonrpc": "2.0",
///         "result": {
///             "success": true
///         }
///     }
/// ```
///
/// Here follows the second possible format of responses from the RPC API, the message lacks both `"id"` and `"result"`, instead it contains
/// `"method"` and `"params"`, just like our requests we sent. When we send a `Atoms.subscribe` request as mentioned above, the first response
/// is the previous example followed by these two messages:
/// ```
///     {
///         "jsonrpc": "2.0",
///         "method": "Atoms.subscribeUpdate",
///         "params": {
///             "atomEvents": [
///             {
///             "atom": { /* ATOM OMITTED FOR SAKE OF BREVITY */ },
///             "serializer": "radix.atom",
///             "type": ":str:store",
///             "version": 100
///             }
///             ],
///             "isHead": false,
///             "subscriberId": "2388888"
///         }
///     }
/// ```
/// Followed by the third message, also on the same format:
/// ```
///     {
///         "jsonrpc": "2.0",
///         "method": "Atoms.subscribeUpdate",
///         "params": {
///             "atomEvents": [],
///             "isHead": true,
///             "subscriberId": "1783940"
///         }
///     }
/// ```
/// Another example of such a message, lacking `"result"` and `"id"` but containing `"params"` and `"method"` is
/// The absolute first message received from the RPC API over webscoket, nameley the `Radix.welcome` message, which looks like this:
/// ```
///     {
///         "jsonrpc": "2.0",
///         "method": "Radix.welcome",
///         "params": {
///             "message": "Hello!"
///         }
///     }
/// ```
/// It is important to note that this message SHOULD have been filtered out by the Websocket code, i.e. the RCP client code
/// should not have to care about this message.
internal enum RPCResponse<ResultOrParam>: Decodable, RPCResposeResultConvertible where ResultOrParam: Decodable {
    case resultWithRequestId(RPCResponseResultWithRequestId<ResultOrParam>)
    case resultLookingLikeRequest(RPCResponseLookingLikeRequest<ResultOrParam>)
}

// MARK: - RPCResposeResultConvertible
extension RPCResponse {
    var model: ResultOrParam {
        switch self {
        case .resultWithRequestId(let response): return response.model
        case .resultLookingLikeRequest(let response): return response.model
        }
    }
}

extension RPCResponse {
    var resultWithRequestId: RPCResponseResultWithRequestId<ResultOrParam>? {
        guard case .resultWithRequestId(let resultWithRequestId) = self else { return nil }
        return resultWithRequestId
    }
}

// MARK: - Decodable
extension RPCResponse {

    enum CodingKeys: String, CodingKey {
        case result, params
    }
    
    init(from decoder: Decoder) throws {
        let keyedContainer = try decoder.container(keyedBy: CodingKeys.self)
        let singleValueContainer = try decoder.singleValueContainer()
        
        if keyedContainer.contains(.params) {
            do {
                self = .resultLookingLikeRequest(try singleValueContainer.decode(RPCResponseLookingLikeRequest<ResultOrParam>.self))
            } catch let decodingError as DecodingError {
                throw decodingError
            } catch {
                incorrectImplementation("Unexpected and unhandled error trying to decode JSON into `RPCResponseLookingLikeRequest`: \(error)")
            }
        } else if keyedContainer.contains(.result) {
            do {
              self = .resultWithRequestId(try singleValueContainer.decode(RPCResponseResultWithRequestId<ResultOrParam>.self))
            } catch let decodingError as DecodingError {
                throw decodingError
            } catch {
                incorrectImplementation("Unexpected and unhandled error trying to decode JSON into `RPCResponseResultWithRequestId`: \(error)")
            }
        } else {
            incorrectImplementation("Error decoding `RPCResponse`, found neither json key `\(CodingKeys.result.stringValue)`, nor `\(CodingKeys.params.stringValue)`")
        }
    }
}
