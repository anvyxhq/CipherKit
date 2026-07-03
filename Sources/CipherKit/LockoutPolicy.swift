//
//  LockoutPolicy.swift
//  CipherKit
//
//  Created by AnhPT on 03/07/2026.
//
//  Brute-force throttling for local passcode/PIN entry (pure, testable state).

import Foundation

/// Configures how failed attempts escalate into lockouts.
public struct LockoutPolicy: Equatable {
    public var maxAttempts: Int          // failures allowed before the first lockout
    public var baseLockout: TimeInterval // seconds for the first lockout
    public var multiplier: Double        // exponential growth per subsequent failure
    public var maxLockout: TimeInterval

    public init(maxAttempts: Int = 5, baseLockout: TimeInterval = 30,
                multiplier: Double = 2, maxLockout: TimeInterval = 3600) {
        self.maxAttempts = maxAttempts; self.baseLockout = baseLockout
        self.multiplier = multiplier; self.maxLockout = maxLockout
    }
}

/// Persistable throttling state (store between launches).
public struct LockoutState: Codable, Equatable {
    public var failedAttempts: Int
    public var lockedUntil: Date?
    public init(failedAttempts: Int = 0, lockedUntil: Date? = nil) {
        self.failedAttempts = failedAttempts; self.lockedUntil = lockedUntil
    }
}

/// Pure lockout state machine — feed it the current state, get the next one.
public enum PasscodeThrottle {

    public static func isLockedOut(_ state: LockoutState, now: Date = Date()) -> Bool {
        guard let until = state.lockedUntil else { return false }
        return now < until
    }

    public static func remainingLockout(_ state: LockoutState, now: Date = Date()) -> TimeInterval {
        guard let until = state.lockedUntil else { return 0 }
        return max(0, until.timeIntervalSince(now))
    }

    /// Record a failed attempt; escalates the lockout once `maxAttempts` is passed.
    public static func recordFailure(_ state: LockoutState, policy: LockoutPolicy = .init(),
                                     now: Date = Date()) -> LockoutState {
        let attempts = state.failedAttempts + 1
        guard attempts >= policy.maxAttempts else {
            return LockoutState(failedAttempts: attempts, lockedUntil: nil)
        }
        let overshoot = attempts - policy.maxAttempts
        let duration = min(policy.maxLockout, policy.baseLockout * pow(policy.multiplier, Double(overshoot)))
        return LockoutState(failedAttempts: attempts, lockedUntil: now.addingTimeInterval(duration))
    }

    /// Reset after a successful entry.
    public static func recordSuccess(_ state: LockoutState) -> LockoutState { LockoutState() }
}
