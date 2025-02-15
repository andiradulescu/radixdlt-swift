//
// MIT License
//
// Copyright (c) 2018-2019 Radix DLT ( https://radixdlt.com )
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//

import Foundation

public protocol UserActionMaking {
    func makeSomeUserAction(tokenContext: TokenContext) -> UserAction
}

public protocol UserActionMakingSpecific: UserActionMaking where SpecificAction.Other == Self {

    associatedtype SpecificAction: UserAction & ExpressibleByOwnedTokenContextAndOther
    func makeSpecificUserAction(tokenContext: TokenContext) -> SpecificAction

}

// UserActionMaking
public extension UserActionMakingSpecific {
    func makeSomeUserAction(tokenContext: TokenContext) -> UserAction {
        return makeSpecificUserAction(tokenContext: tokenContext)
    }

    func makeSpecificUserAction(tokenContext: TokenContext) -> SpecificAction {
        return SpecificAction(tokenContext: tokenContext, other: self)
    }
}

public protocol ExpressibleByOwnedTokenContextAndOther {
    associatedtype Other: UserActionMakingSpecific
    init(tokenContext: TokenContext, other: Other)
}

public typealias Burn = BurnTokensAction.Other
extension BurnTokensAction: ExpressibleByOwnedTokenContextAndOther {}
public extension BurnTokensAction {

    struct Other: UserActionMakingSpecific {
        public typealias SpecificAction = BurnTokensAction

        let amount: PositiveAmount
    }

    init(tokenContext: TokenContext, other: Other) {
        self.init(
            tokenDefinitionReference: tokenContext.rri,
            amount: other.amount,
            burner: tokenContext.actor
        )
    }
}

public typealias Mint = MintTokensAction.Other
extension MintTokensAction: ExpressibleByOwnedTokenContextAndOther {}
public extension MintTokensAction {

    struct Other: UserActionMakingSpecific {
        public typealias SpecificAction = MintTokensAction

        let amount: PositiveAmount
        let creditNewlyMintedTokensTo: Address?
        init(amount: PositiveAmount, creditNewlyMintedTokensTo: Address? = nil) {
            self.amount = amount
            self.creditNewlyMintedTokensTo = creditNewlyMintedTokensTo
        }
    }

    init(tokenContext: TokenContext, other: Other) {
        self.init(
            tokenDefinitionReference: tokenContext.rri,
            amount: other.amount,
            minter: tokenContext.actor,
            creditNewlyMintedTokensTo: other.creditNewlyMintedTokensTo
        )
    }
}
