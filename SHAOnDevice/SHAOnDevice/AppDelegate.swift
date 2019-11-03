//
//  AppDelegate.swift
//  SHAOnDevice
//
//  Created by Andrei Radulescu on 11/3/19.
//  Copyright © 2019 Radix DLT. All rights reserved.
//

import UIKit
import RadixSDK

@UIApplicationMain
class AppDelegate: UIResponder, UIApplicationDelegate {

    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        let slowestVector = vectorsSlow[0]
        powInBackground(hasher: SHA256TwiceHasher(), vector: slowestVector) { [weak self] timeForCryptoSwift in
            self?.powInBackground(hasher: CryptoKitSha256TwiceHasher(), vector: slowestVector) { timeForCryptoKit in
                let rate = timeForCryptoSwift / timeForCryptoKit
                print(String(format: "POW using CryptoKit is %.2fx faster", rate))
            }
        }
        return true
    }

    // MARK: UISceneSession Lifecycle

    func application(_ application: UIApplication, configurationForConnecting connectingSceneSession: UISceneSession, options: UIScene.ConnectionOptions) -> UISceneConfiguration {
        // Called when a new scene session is being created.
        // Use this method to select a configuration to create the new scene with.
        return UISceneConfiguration(name: "Default Configuration", sessionRole: connectingSceneSession.role)
    }

    func application(_ application: UIApplication, didDiscardSceneSessions sceneSessions: Set<UISceneSession>) {
        // Called when the user discards a scene session.
        // If any sessions were discarded while the application was not running, this will be called shortly after application:didFinishLaunchingWithOptions.
        // Use this method to release any resources that were specific to the discarded scenes, as they will not return.
    }

    private let dispatchQueue = DispatchQueue(
          label: "POW",
          qos: DispatchQoS(qosClass: .background, relativePriority: 1),
          attributes: .concurrent,
          autoreleaseFrequency: .workItem,
          target: nil
      )
}

private extension AppDelegate {
    func powInBackground(hasher sha256TwiceHasher: SHA256TwiceHashing, vector: Vector, done: ((CFAbsoluteTime) -> Void)? = nil) {
        dispatchQueue.async {
            self.doTest(
                zeros: vector.zeros,
                expectedNonce: vector.expectedResultingNonce,
                magic: vector.magic,
                seed: vector.seed,
                sha256TwiceHasher: sha256TwiceHasher,
                done: done
            )
        }
    }
    
    func doTest(
        zeros: ProofOfWork.NumberOfLeadingZeros,
        expectedNonce: Nonce,
        magic overridingMagic: Magic,
        seed overridingSeed: HexString,
        sha256TwiceHasher: SHA256TwiceHashing = CryptoKitSha256TwiceHasher(),
        done: ((CFAbsoluteTime) -> Void)? = nil
    ) {
    
        let magicUsed = overridingMagic
        let seedUsed = overridingSeed

        let worker = DefaultProofOfWorkWorker(
            targetNumberOfLeadingZeros: zeros,
            sha256TwiceHasher: sha256TwiceHasher
        )
        
        let start = CFAbsoluteTimeGetCurrent()

        worker.doWork(seed: seedUsed.asData, magic: magicUsed) { _ in
            
            DispatchQueue.main.sync {
                let end = CFAbsoluteTimeGetCurrent()
                let executionTime: CFAbsoluteTime = end - start
                print(String(format: "POW using '%@' took %.3f seconds", sha256TwiceHasher.nameOfHasher, executionTime))
                done?(executionTime)
            }
        }
    }
}

private typealias Vector = (expectedResultingNonce: Nonce, seed: HexString, magic: Magic, zeros: ProofOfWork.NumberOfLeadingZeros)
private let vectorsSlow: [Vector] = [
    (
        expectedResultingNonce: 510190,
        seed: "887a9e87ecbcc8f13ea60dd732a3c115ea9478519ee3faac3be3ed89b4bbc535",
        magic: -1332248574,
        zeros: 16
    ),
    (
        expectedResultingNonce: 322571,
        seed: "46ad4f54098f18f856a2ff05df25f5af587bd4f6dfc1e3b4cb406ceb25c61552",
        magic: -1332248574,
        zeros: 16
    ),
    (
        expectedResultingNonce: 312514,
        seed: "f0f178d42ffe8fade8b8197782fd1ee72a4068d046d868806da7bfb1d0ffa7c1",
        magic: -1332248574,
        zeros: 16
    ),
    (
        expectedResultingNonce: 311476,
        seed: "a33a90d0422aa12b68d1de6c53e83ca049ab82b06efeb03cf6731231e82470ef",
        magic: -1332248574,
        zeros: 16
    ),
    (
        expectedResultingNonce: 285315,
        seed: "0519269eafbac3accba00cf6f7e93238aae1974a1e5439a58a6f53726a963095",
        magic: -1332248574,
        zeros: 16
    ),
    (
        expectedResultingNonce: 270233,
        seed: "34931f7c0522352426d9d95f1c5527fafffce55b13082ae3723dc89f3c3e6276",
        magic: -1332248574,
        zeros: 16
    )
]
