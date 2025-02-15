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
import RxSwift

public final class DefaultProofOfWorkWorker: ProofOfWorkWorker {
    private let dispatchQueue = DispatchQueue(label: "Radix.DefaultProofOfWorkWorker", qos: .userInitiated)
    private let targetNumberOfLeadingZeros: ProofOfWork.NumberOfLeadingZeros
    private let sha256TwiceHasher: SHA256TwiceHashing

    public init(
        targetNumberOfLeadingZeros: ProofOfWork.NumberOfLeadingZeros = .default,
        sha256TwiceHasher: SHA256TwiceHashing = SHA256TwiceHasher()
    ) {
        self.targetNumberOfLeadingZeros = targetNumberOfLeadingZeros
        self.sha256TwiceHasher = sha256TwiceHasher
    }
    
    deinit {
        log.verbose("POW Worker deinit")
    }
}

public extension DefaultProofOfWorkWorker {
    static let expectedByteCountOfSeed = 32
    
    func work(
        seed: Data,
        magic: Magic
    ) -> Single<ProofOfWork> {
        return Single.create { [unowned self] single in
            var powDone = false
            self.dispatchQueue.async {
                log.verbose("POW started")
                self.doWork(
                    seed: seed,
                    magic: magic
                ) { resultOfWork in
                    switch resultOfWork {
                    case .failure(let error):
                        log.error("POW failed: \(error), seed: \(seed), magic: \(magic), #0: \(self.targetNumberOfLeadingZeros)")
                        single(.error(error))
                    case .success(let pow):
                        powDone = true
                        log.verbose("POW done")
                        single(.success(pow))
                    }
                }
            }
            
            return Disposables.create {
                if !powDone {
                    log.warning("POW cancelled")
                }
            }
        }
    }
}

// MARK: - Internal (for testing, ought to be private)
internal extension DefaultProofOfWorkWorker {
    func doWork(
        seed: Data,
        magic: Magic,
        done: ((Result<ProofOfWork, Error>) -> Void)
    ) {
        guard seed.length == DefaultProofOfWorkWorker.expectedByteCountOfSeed else {
            let error = ProofOfWork.Error.workInputIncorrectLengthOfSeed(expectedByteCountOf: DefaultProofOfWorkWorker.expectedByteCountOfSeed, butGot: seed.length)
            done(.failure(error))
            return
        }
        
        var nonce: Nonce = 0
        let base: Data = magic.toFourBigEndianBytes() + seed
        var radixHash: RadixHash!
        repeat {
            nonce += 1
            let unhashed = base + nonce.toEightBigEndianBytes()
            radixHash = RadixHash(unhashedData: unhashed, hashedBy: sha256TwiceHasher)
        } while radixHash.numberOfLeadingZeroBits < targetNumberOfLeadingZeros.numberOfLeadingZeros
        
        let pow = ProofOfWork(seed: seed, targetNumberOfLeadingZeros: targetNumberOfLeadingZeros, magic: magic, nonce: nonce)
        done(.success(pow))
    }
}

extension DefaultProofOfWorkWorker: FeeMapper {}
public extension DefaultProofOfWorkWorker {
    func feeBasedOn(atom: Atom, universeConfig: UniverseConfig, key: PublicKey) -> Single<AtomWithFee> {
        return work(atom: atom, magic: universeConfig.magic).map {
            try AtomWithFee(atomWithoutPow: atom, proofOfWork: $0)
        }
    }
}
