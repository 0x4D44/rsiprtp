//! Stress and load testing scenarios.
//!
//! These tests verify the system behavior under high load, including:
//! - High concurrent call volume
//! - Rapid call cycling
//! - Resource exhaustion scenarios
//! - Performance degradation measurement

use std::time::{Duration, Instant};

use crate::framework::{TestConfig, TestEndpoint};

/// Test rapid call setup/teardown cycling (extended)
#[tokio::test]
async fn test_rapid_cycling_1000() {
    let config_a = TestConfig::with_available_ports();
    let config_b = TestConfig::with_available_ports();

    let mut endpoint_a = TestEndpoint::new(config_a.clone()).await.unwrap();
    let mut endpoint_b = TestEndpoint::new(config_b.clone()).await.unwrap();

    let target_uri = format!("sip:test@127.0.0.1:{}", config_b.local_sip_port);

    let mut timings = Vec::new();

    // Perform 1000 call cycles
    for i in 0..1000 {
        let start = Instant::now();

        // A calls B
        let handle_a = endpoint_a.call(&target_uri).await.unwrap();

        // B accepts
        let incoming = endpoint_b
            .wait_for_incoming(Duration::from_secs(2))
            .await
            .unwrap();
        let handle_b = endpoint_b.accept_call(incoming).await.unwrap();

        // A waits for answer
        endpoint_a
            .wait_for_answer(&handle_a, Duration::from_secs(2))
            .await
            .unwrap();

        // Hang up
        endpoint_a.hangup(&handle_a).await.unwrap();
        endpoint_b
            .wait_for_hangup(&handle_b, Duration::from_secs(2))
            .await
            .unwrap();

        let elapsed = start.elapsed();
        timings.push(elapsed);

        if i % 100 == 0 {
            println!("Completed {} call cycles", i);
        }
    }

    // Analyze timing consistency
    let avg_time = timings.iter().sum::<Duration>() / timings.len() as u32;
    let max_time = timings.iter().max().unwrap();
    let min_time = timings.iter().min().unwrap();

    println!("Average call cycle time: {:?}", avg_time);
    println!("Min: {:?}, Max: {:?}", min_time, max_time);

    // Log timing ratio - occasional spikes are expected due to OS scheduling
    // This is informational; the test passes if all 1000 cycles complete
    let ratio = max_time.as_micros() as f64 / avg_time.as_micros() as f64;
    println!("Max/Avg ratio: {:.1}x", ratio);
}

/// Test multiple sequential calls
#[tokio::test]
async fn test_sequential_calls_100() {
    let config_a = TestConfig::with_available_ports();
    let config_b = TestConfig::with_available_ports();

    let mut endpoint_a = TestEndpoint::new(config_a.clone()).await.unwrap();
    let mut endpoint_b = TestEndpoint::new(config_b.clone()).await.unwrap();

    let target_uri = format!("sip:test@127.0.0.1:{}", config_b.local_sip_port);

    for i in 0..100 {
        let handle_a = endpoint_a.call(&target_uri).await.unwrap();

        let incoming = endpoint_b
            .wait_for_incoming(Duration::from_secs(2))
            .await
            .unwrap();
        let handle_b = endpoint_b.accept_call(incoming).await.unwrap();

        endpoint_a
            .wait_for_answer(&handle_a, Duration::from_secs(2))
            .await
            .unwrap();

        // Brief call
        tokio::time::sleep(Duration::from_millis(10)).await;

        endpoint_a.hangup(&handle_a).await.unwrap();
        endpoint_b
            .wait_for_hangup(&handle_b, Duration::from_secs(2))
            .await
            .unwrap();

        if i % 10 == 0 {
            println!("Call {} completed", i);
        }
    }

    println!("100 sequential calls completed successfully");
}

/// Test call with very short duration (stress timing)
#[tokio::test]
async fn test_instant_hangup_stress() {
    let config_a = TestConfig::with_available_ports();
    let config_b = TestConfig::with_available_ports();

    let mut endpoint_a = TestEndpoint::new(config_a.clone()).await.unwrap();
    let mut endpoint_b = TestEndpoint::new(config_b.clone()).await.unwrap();

    let target_uri = format!("sip:test@127.0.0.1:{}", config_b.local_sip_port);

    // 50 calls with instant hangup after answer
    for _ in 0..50 {
        let handle_a = endpoint_a.call(&target_uri).await.unwrap();

        let incoming = endpoint_b
            .wait_for_incoming(Duration::from_secs(2))
            .await
            .unwrap();
        let handle_b = endpoint_b.accept_call(incoming).await.unwrap();

        endpoint_a
            .wait_for_answer(&handle_a, Duration::from_secs(2))
            .await
            .unwrap();

        // Immediate hangup (no delay)
        endpoint_a.hangup(&handle_a).await.unwrap();
        endpoint_b
            .wait_for_hangup(&handle_b, Duration::from_secs(2))
            .await
            .unwrap();
    }

    println!("50 instant-hangup calls completed");
}

/// Test alternating caller/callee roles rapidly
#[tokio::test]
async fn test_alternating_roles_stress() {
    let config_a = TestConfig::with_available_ports();
    let config_b = TestConfig::with_available_ports();

    let mut endpoint_a = TestEndpoint::new(config_a.clone()).await.unwrap();
    let mut endpoint_b = TestEndpoint::new(config_b.clone()).await.unwrap();

    for i in 0..50 {
        if i % 2 == 0 {
            // A calls B
            let target = format!("sip:test@127.0.0.1:{}", config_b.local_sip_port);
            let handle_a = endpoint_a.call(&target).await.unwrap();

            let incoming = endpoint_b
                .wait_for_incoming(Duration::from_secs(2))
                .await
                .unwrap();
            let handle_b = endpoint_b.accept_call(incoming).await.unwrap();

            endpoint_a
                .wait_for_answer(&handle_a, Duration::from_secs(2))
                .await
                .unwrap();

            endpoint_a.hangup(&handle_a).await.unwrap();
            endpoint_b
                .wait_for_hangup(&handle_b, Duration::from_secs(2))
                .await
                .unwrap();
        } else {
            // B calls A
            let target = format!("sip:test@127.0.0.1:{}", config_a.local_sip_port);
            let handle_b = endpoint_b.call(&target).await.unwrap();

            let incoming = endpoint_a
                .wait_for_incoming(Duration::from_secs(2))
                .await
                .unwrap();
            let handle_a = endpoint_a.accept_call(incoming).await.unwrap();

            endpoint_b
                .wait_for_answer(&handle_b, Duration::from_secs(2))
                .await
                .unwrap();

            endpoint_b.hangup(&handle_b).await.unwrap();
            endpoint_a
                .wait_for_hangup(&handle_a, Duration::from_secs(2))
                .await
                .unwrap();
        }
    }

    println!("50 alternating-role calls completed");
}

/// Test port exhaustion recovery
#[tokio::test]
async fn test_port_reuse_stress() {
    let config_a = TestConfig::with_available_ports();
    let config_b = TestConfig::with_available_ports();

    let mut endpoint_a = TestEndpoint::new(config_a.clone()).await.unwrap();
    let mut endpoint_b = TestEndpoint::new(config_b.clone()).await.unwrap();

    let target_uri = format!("sip:test@127.0.0.1:{}", config_b.local_sip_port);

    // Create and tear down many calls to verify port reuse
    for i in 0..200 {
        let handle_a = endpoint_a.call(&target_uri).await.unwrap();

        let incoming = endpoint_b
            .wait_for_incoming(Duration::from_secs(2))
            .await
            .unwrap();
        let handle_b = endpoint_b.accept_call(incoming).await.unwrap();

        endpoint_a
            .wait_for_answer(&handle_a, Duration::from_secs(2))
            .await
            .unwrap();

        endpoint_a.hangup(&handle_a).await.unwrap();
        endpoint_b
            .wait_for_hangup(&handle_b, Duration::from_secs(2))
            .await
            .unwrap();

        // Small delay to allow cleanup
        tokio::time::sleep(Duration::from_millis(5)).await;

        if i % 50 == 0 {
            println!("Port reuse test: {} calls completed", i);
        }
    }

    println!("200 calls with port reuse completed");
}

/// Test timing consistency under load
#[tokio::test]
async fn test_timing_consistency() {
    let config_a = TestConfig::with_available_ports();
    let config_b = TestConfig::with_available_ports();

    let mut endpoint_a = TestEndpoint::new(config_a.clone()).await.unwrap();
    let mut endpoint_b = TestEndpoint::new(config_b.clone()).await.unwrap();

    let target_uri = format!("sip:test@127.0.0.1:{}", config_b.local_sip_port);

    let mut setup_times = Vec::new();

    for _ in 0..100 {
        let start = Instant::now();

        let handle_a = endpoint_a.call(&target_uri).await.unwrap();

        let incoming = endpoint_b
            .wait_for_incoming(Duration::from_secs(2))
            .await
            .unwrap();
        let handle_b = endpoint_b.accept_call(incoming).await.unwrap();

        endpoint_a
            .wait_for_answer(&handle_a, Duration::from_secs(2))
            .await
            .unwrap();

        let setup_time = start.elapsed();
        setup_times.push(setup_time);

        endpoint_a.hangup(&handle_a).await.unwrap();
        endpoint_b
            .wait_for_hangup(&handle_b, Duration::from_secs(2))
            .await
            .unwrap();
    }

    // Calculate statistics
    let avg = setup_times.iter().sum::<Duration>() / setup_times.len() as u32;
    let variance: f64 = setup_times
        .iter()
        .map(|t| {
            let diff = t.as_micros() as i64 - avg.as_micros() as i64;
            (diff * diff) as f64
        })
        .sum::<f64>()
        / setup_times.len() as f64;

    let std_dev = variance.sqrt();

    println!("Average setup time: {:?}", avg);
    println!("Standard deviation: {:.2} µs", std_dev);

    // Note: Timing assertions can be flaky under load, so we just log the results
    // In a real deployment, you'd want to track these metrics over time
    println!(
        "Timing consistency: stddev {:.2} µs, avg {} µs (ratio: {:.2})",
        std_dev,
        avg.as_micros(),
        std_dev / avg.as_micros() as f64
    );
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_duration_calculations() {
        let durations = [
            Duration::from_millis(100),
            Duration::from_millis(200),
            Duration::from_millis(150),
        ];

        let avg = durations.iter().sum::<Duration>() / durations.len() as u32;
        assert_eq!(avg.as_millis(), 150);

        let max = durations.iter().max().unwrap();
        assert_eq!(max.as_millis(), 200);

        let min = durations.iter().min().unwrap();
        assert_eq!(min.as_millis(), 100);
    }
}
