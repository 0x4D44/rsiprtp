//! Stack-to-stack B2B call tests.
//!
//! These tests use the actual production stack components to verify
//! end-to-end call functionality without external dependencies.

mod stack_instance;

use stack_instance::{StackConfig, StackEvent, StackInstance};
use std::time::Duration;

/// Enable debug output for tests (set to true when debugging)
const DEBUG: bool = false;

macro_rules! debug_println {
    ($($arg:tt)*) => {
        if DEBUG {
            eprintln!($($arg)*);
        }
    };
}

/// Test basic call flow between two stack instances.
///
/// Flow:
/// 1. Alice calls Bob
/// 2. Bob receives incoming call
/// 3. Bob answers
/// 4. Both sides are established
/// 5. RTP is exchanged
/// 6. Alice hangs up
/// 7. Both sides are terminated
#[tokio::test]
async fn test_basic_call_flow() {
    let alice_config = StackConfig::new("alice", 0, 0); // 0 = auto-assign port
    let bob_config = StackConfig::new("bob", 0, 0);

    let mut alice = StackInstance::new(alice_config).await.unwrap();
    let mut bob = StackInstance::new(bob_config).await.unwrap();

    debug_println!("Alice SIP: {}", alice.sip_addr());
    debug_println!("Bob SIP: {}", bob.sip_addr());

    // Alice calls Bob
    let bob_uri = format!("sip:bob@{}", bob.sip_addr());
    debug_println!("Alice calling: {}", bob_uri);
    let call_id = alice.make_call(&bob_uri);
    debug_println!("Call ID: {:?}", call_id);

    // Run both stacks until Bob receives the incoming call
    let mut bob_got_call = false;

    for i in 0..100 {
        // Process Alice
        if let Some(event) = alice.step().await {
            debug_println!("Alice event (iter {}): {:?}", i, event);
        }

        // Process Bob
        if let Some(event) = bob.step().await {
            debug_println!("Bob event (iter {}): {:?}", i, event);
            if matches!(event, StackEvent::IncomingCall { .. }) {
                bob_got_call = true;
                break;
            }
        }

        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    assert!(bob_got_call, "Bob should receive incoming call");
    debug_println!("Bob received incoming call!");

    // Get the incoming call ID from Bob's side
    let bob_calls = bob.pending_incoming_calls();
    debug_println!("Bob pending calls: {:?}", bob_calls);
    assert_eq!(bob_calls.len(), 1, "Bob should have one pending call");
    let bob_call_id = bob_calls[0].clone();

    // Bob answers
    debug_println!("Bob answering call...");
    bob.answer_call(&bob_call_id);

    // Run until both sides are established
    let mut alice_established = false;
    let mut bob_established = bob.is_call_established(&bob_call_id);
    debug_println!("After answer - Bob established: {}", bob_established);

    for i in 0..100 {
        if let Some(event) = alice.step().await {
            debug_println!("Alice event (iter {}): {:?}", i, event);
            if matches!(event, StackEvent::CallEstablished { .. }) {
                alice_established = true;
            }
        }
        if let Some(event) = bob.step().await {
            debug_println!("Bob event (iter {}): {:?}", i, event);
        }

        if alice.is_call_established(&call_id) {
            alice_established = true;
        }
        bob_established = bob.is_call_established(&bob_call_id);

        if alice_established && bob_established {
            debug_println!("Both sides established!");
            break;
        }

        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    debug_println!(
        "Final: alice_established={}, bob_established={}",
        alice_established,
        bob_established
    );
    assert!(
        alice_established && bob_established,
        "Call should be established on both sides"
    );

    // Alice hangs up
    debug_println!("Alice hanging up...");
    alice.hangup(&call_id);

    // Run until Bob sees hangup
    let mut bob_hangup = false;
    for i in 0..50 {
        if let Some(event) = alice.step().await {
            debug_println!("Alice event (iter {}): {:?}", i, event);
        }
        if let Some(event) = bob.step().await {
            debug_println!("Bob event (iter {}): {:?}", i, event);
            if matches!(event, StackEvent::CallEnded { .. }) {
                bob_hangup = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    assert!(bob_hangup, "Bob should see call ended");
}

/// Test call rejection with 486 Busy.
#[tokio::test]
async fn test_call_rejection() {
    let alice_config = StackConfig::new("alice", 0, 0);
    let bob_config = StackConfig::new("bob", 0, 0);

    let mut alice = StackInstance::new(alice_config).await.unwrap();
    let mut bob = StackInstance::new(bob_config).await.unwrap();

    // Alice calls Bob
    let bob_uri = format!("sip:bob@{}", bob.sip_addr());
    let call_id = alice.make_call(&bob_uri);

    // Run until Bob receives call
    for _ in 0..100 {
        alice.step().await;
        if let Some(StackEvent::IncomingCall { .. }) = bob.step().await {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Bob rejects with 486 Busy
    let bob_calls = bob.pending_incoming_calls();
    assert!(!bob_calls.is_empty());
    bob.reject_call(&bob_calls[0], 486);

    // Run until Alice sees rejection
    let mut alice_rejected = false;
    for _ in 0..50 {
        if let Some(StackEvent::CallRejected { .. }) = alice.step().await {
            alice_rejected = true;
            break;
        }
        bob.step().await;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    assert!(alice_rejected, "Alice should see call rejected");
    assert!(!alice.is_call_established(&call_id));
}
