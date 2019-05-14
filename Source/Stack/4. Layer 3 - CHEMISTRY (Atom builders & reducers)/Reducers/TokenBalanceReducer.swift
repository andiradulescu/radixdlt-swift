//
//  TokenBalanaceReducer.swift
//  RadixSDK iOS
//
//  Created by Alexander Cyon on 2019-03-30.
//  Copyright © 2019 Radix DLT. All rights reserved.
//

import Foundation
import RxSwift

public struct TokenBalanceReducer {
    private let initial: BalancePerToken
    public init(initial: BalancePerToken = [:]) {
        self.initial = initial
    }
}

public typealias SpunTransferrable = SpunParticle<TransferrableTokensParticle>

public extension TokenBalanceReducer {
    func reduce(spunParticles: [AnySpunParticle]) -> BalancePerToken {
        let tokenBalances = spunParticles.compactMap { (spunParticle: AnySpunParticle) -> TokenBalance? in
            guard let transferrableTokensParticle = spunParticle.particle as? TransferrableTokensParticle else {
                return nil
            }
            return TokenBalance(transferrable: transferrableTokensParticle, spin: spunParticle.spin)
        }
        return reduce(tokenBalances: tokenBalances)
    }
    
    func reduce(spunTransferrable: [SpunTransferrable]) -> BalancePerToken {
        let tokenBalances = spunTransferrable.map {
            return TokenBalance(spunTransferrable: $0)
        }
        return reduce(tokenBalances: tokenBalances)
    }

    func reduce(_ spunTransferrable: SpunTransferrable) -> BalancePerToken {
        let tokenBalance = TokenBalance(spunTransferrable: spunTransferrable)
        return reduce(tokenBalances: [tokenBalance])
    }
    
    func reduce(_ transferrableTokensParticle: TransferrableTokensParticle, spin: Spin) -> BalancePerToken {
        let tokenBalance = TokenBalance(transferrable: transferrableTokensParticle, spin: spin)
        return reduce(tokenBalances: [tokenBalance])
    }
    
    func reduce(tokenBalances: [TokenBalance]) -> BalancePerToken {
        return reduce(balancePerToken: BalancePerToken(reducing: tokenBalances))
    }
    
    func reduce(balancePerToken: BalancePerToken) -> BalancePerToken {
        return balancePerToken.merging(with: initial)
    }
    
    func reduce(balancePerTokens: [BalancePerToken]) -> BalancePerToken {
        return balancePerTokens.reduce(initial, { $0.merging(with: $1) })
    }
}

// MARK: - Rx
public extension TokenBalanceReducer {
    
    func reduce(atoms: Observable<[Atom]>) -> Observable<BalancePerToken> {
        return atoms.map { atomArray -> [TokenBalance] in
            atomArray.flatMap { atom in
                atom.tokensBalances()
            }
        }.map { (tokenBalances: [TokenBalance]) -> BalancePerToken in
            return self.reduce(tokenBalances: tokenBalances)
        }
    }
}

