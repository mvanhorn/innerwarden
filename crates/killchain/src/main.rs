//! innerwarden-killchain — Kill chain detection service.
//! Consumes eBPF events from Redis, detects attack patterns, publishes incidents.

mod config;
mod redis;

use anyhow::Result;
use clap::Parser;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;
use tokio::signal;
use tracing::info;

use config::Config;
use innerwarden_killchain::metrics::Metrics;
use innerwarden_killchain::tracker::PidTracker;

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Parse config
    let config = Config::parse();

    // 2. Init tracing
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&config.log_level));
    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    info!("innerwarden-killchain starting");
    info!(
        redis_url = %config.redis_url,
        events_stream = %config.events_stream,
        incidents_stream = %config.incidents_stream,
        pre_chain_threshold = %config.pre_chain_threshold,
        session_timeout_secs = %config.session_timeout_secs,
        "Configuration loaded"
    );

    // 3. Connect to Redis
    let mut redis_client = crate::redis::RedisClient::connect(
        &config.redis_url,
        &config.events_stream,
        &config.incidents_stream,
    )
    .await?;

    // 4. Create PidTracker and Metrics
    let mut tracker = PidTracker::new()
        .with_timeout(config.session_timeout_secs)
        .with_pre_chain_threshold(config.pre_chain_threshold);
    let metrics = Arc::new(Metrics::new());
    let mut last_maintenance = Instant::now();

    info!("Entering main event loop");

    // 5. Main loop with graceful shutdown
    loop {
        tokio::select! {
            // Graceful shutdown on SIGINT or SIGTERM
            _ = signal::ctrl_c() => {
                info!("Received shutdown signal, exiting");
                break;
            }

            // Main processing loop iteration
            result = redis_client.read_events() => {
                let events = match result {
                    Ok(events) => events,
                    Err(e) => {
                        tracing::error!("Failed to read events from Redis: {}", e);
                        // Brief pause before retrying on error
                        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                        continue;
                    }
                };

                if events.is_empty() {
                    // No events this cycle; check if maintenance is due
                    if last_maintenance.elapsed().as_secs() >= 60 {
                        tracker.cleanup_stale();
                        metrics.log_summary();
                        last_maintenance = Instant::now();
                    }
                    continue;
                }

                let mut stream_ids = Vec::with_capacity(events.len());
                let mut incidents = Vec::new();

                // 5a-5c. Process each event
                for (stream_id, event) in &events {
                    stream_ids.push(stream_id.clone());
                    metrics.events_processed.fetch_add(1, Ordering::Relaxed);

                    // 5b. Let the tracker process the event (detects chain progression)
                    let tracker_incidents = tracker.process_event(event);
                    for inc in tracker_incidents {
                        metrics.chains_detected.fetch_add(1, Ordering::Relaxed);
                        incidents.push(inc);
                    }

                    // 5c. Check for LSM blocked events
                    if let Some(incident) = innerwarden_killchain::detector::process_lsm_blocked(event, &tracker) {
                        metrics.lsm_blocked_processed.fetch_add(1, Ordering::Relaxed);
                        incidents.push(incident);
                    }
                }

                // 5d. Publish all incidents to Redis
                for incident in &incidents {
                    if let Err(e) = redis_client.publish_incident(incident).await {
                        tracing::error!("Failed to publish incident: {}", e);
                    } else {
                        metrics.incidents_published.fetch_add(1, Ordering::Relaxed);
                    }
                }

                // 5e. ACK processed events
                if let Err(e) = redis_client.ack_events(&stream_ids).await {
                    tracing::error!("Failed to ACK events: {}", e);
                }

                // 5f. Periodic maintenance (every 60s)
                if last_maintenance.elapsed().as_secs() >= 60 {
                    tracker.cleanup_stale();
                    metrics.log_summary();
                    last_maintenance = Instant::now();
                }
            }
        }
    }

    // Final summary before exit
    info!("Shutting down — final metrics:");
    metrics.log_summary();

    Ok(())
}
