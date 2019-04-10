//
//  TestScheduler.swift
//  RadixSDK iOS Tests
//
//  Created by Alexander Cyon on 2019-03-30.
//  Copyright © 2019 Radix DLT. All rights reserved.
//

import Foundation

import XCTest
import RxTest
import RxBlocking
import RxSwift


extension TestScheduler {
    
    
    /// Run the simulation and record all events using observer returned by this function.
    /// Subscribe at virtual time 0
    /// Dispose subscription at virtual time 1000
    func start<Element>(
        created: TestTime = 0,
        subscribed: TestTime = 0,
        disposed: TestTime = 1000,
        createRecored: @escaping () -> TestableObservable<Element>
        ) -> TestableObserver<Element> {
        
        return self.start(created: created, subscribed: subscribed, disposed: disposed) {
            createRecored().asObservable()
        }
        
    }
    
    /// Run the simulation and record all events using observer returned by this function.
    /// Subscribe at virtual time 0
    /// Dispose subscription at virtual time 1000
    func start<Element>(
        created: TestTime = 0,
        subscribed: TestTime = 0,
        disposed: TestTime = 1000,
        type: CreateHotOrCold = .hot,
        recorded recordedEvents: [Recorded<Event<Element>>]
        ) -> TestableObserver<Element> {
        
        return self.start(
            created: created,
            subscribed: subscribed,
            disposed: disposed,
            createRecored: {
                type.create(scheduler: self, recordedEvents: recordedEvents)
        })
    }
    
    static func schedule<Element>(
        initialClock: TestTime = 0,
        created: TestTime = 0,
        subscribed: TestTime = 0,
        disposed: TestTime = 1000,
        type: CreateHotOrCold = .hot,
        recorded recordedEvents: [Recorded<Event<Element>>]
    ) -> TestableObserver<Element> {
        
        return TestScheduler(initialClock: initialClock).start(
            created: created,
            subscribed: subscribed,
            disposed: disposed,
            type: type,
            recorded: recordedEvents
        )
    }
        
    enum CreateHotOrCold {
        case hot, cold
        func create<Element>(scheduler: TestScheduler, recordedEvents: [Recorded<Event<Element>>]) -> TestableObservable<Element> {
            switch self {
            case .cold: return scheduler.createColdObservable(recordedEvents)
            case .hot: return scheduler.createHotObservable(recordedEvents)
            }
        }
    }
}
