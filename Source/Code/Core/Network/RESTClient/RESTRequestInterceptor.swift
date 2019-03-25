//
//  RESTRequestInterceptor.swift
//  RadixSDK iOS
//
//  Created by Alexander Cyon on 2019-03-25.
//  Copyright © 2019 Radix DLT. All rights reserved.
//

import Foundation
import Alamofire

public final class RESTRequestInterceptor: RequestInterceptor {
    private let baseURL: URL
    init?(baseURL: URL?) {
        guard let baseURL = baseURL else {
            return nil
        }
        self.baseURL = baseURL
    }
}

// MARK: - RequestInterceptor
public extension RESTRequestInterceptor {
    func adapt(_ urlRequest: URLRequest, for session: Alamofire.Session, completion: @escaping (Alamofire.Result<URLRequest>) -> Void) {
        var urlRequest = urlRequest
        if urlRequest.url?.baseURL != baseURL {
            urlRequest = urlRequest.settingBaseForUrl(base: baseURL)
        }
        completion(.success(urlRequest))
    }
    
    func retry(_ request: Alamofire.Request, for session: Alamofire.Session, dueTo error: Error, completion: @escaping (Alamofire.RetryResult) -> Void) {
        completion(.doNotRetry)
    }
}
