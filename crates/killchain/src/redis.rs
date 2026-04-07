//! Redis stream consumer and publisher for innerwarden events/incidents.

use anyhow::{Context, Result};
use redis::aio::MultiplexedConnection;
use redis::AsyncCommands;
use serde_json::Value;
use tracing::{debug, info, warn};

/// Redis client for consuming events and publishing incidents via Redis Streams.
pub struct RedisClient {
    conn: MultiplexedConnection,
    events_stream: String,
    incidents_stream: String,
    consumer_group: String,
    consumer_name: String,
    batch_size: usize,
}

impl RedisClient {
    /// Connect to Redis and create the consumer group if it does not exist.
    ///
    /// Uses `XGROUP CREATE ... MKSTREAM` to ensure both the stream and group exist.
    pub async fn connect(url: &str, events_stream: &str, incidents_stream: &str) -> Result<Self> {
        let client = redis::Client::open(url)
            .with_context(|| format!("Failed to parse Redis URL: {}", url))?;

        let conn = client
            .get_multiplexed_async_connection()
            .await
            .with_context(|| format!("Failed to connect to Redis at {}", url))?;

        info!("Connected to Redis at {}", url);

        let consumer_group = "innerwarden-killchain".to_string();
        let consumer_name = "consumer-1".to_string();

        let mut instance = Self {
            conn,
            events_stream: events_stream.to_string(),
            incidents_stream: incidents_stream.to_string(),
            consumer_group,
            consumer_name,
            batch_size: 500,
        };

        // Create consumer group (ignore error if it already exists)
        instance.ensure_consumer_group().await;

        Ok(instance)
    }

    /// Create the consumer group on the events stream, ignoring "BUSYGROUP" errors
    /// (which indicate the group already exists).
    ///
    /// After ensuring the group exists, reset its last-delivered-id to "0" so that
    /// any events added while the service was offline are re-delivered on the next
    /// XREADGROUP call.  Without this, events produced between restarts are silently
    /// skipped because Redis marks them as "delivered" even though no consumer ever
    /// processed them.
    async fn ensure_consumer_group(&mut self) {
        let result: redis::RedisResult<String> = redis::cmd("XGROUP")
            .arg("CREATE")
            .arg(&self.events_stream)
            .arg(&self.consumer_group)
            .arg("0")
            .arg("MKSTREAM")
            .query_async(&mut self.conn)
            .await;

        match result {
            Ok(_) => {
                info!(
                    "Created consumer group '{}' on stream '{}'",
                    self.consumer_group, self.events_stream
                );
            }
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("BUSYGROUP") {
                    debug!(
                        "Consumer group '{}' already exists on '{}'",
                        self.consumer_group, self.events_stream
                    );
                    // Reset the last-delivered-id to 0 so events produced while
                    // we were offline are re-consumed on the next XREADGROUP ">".
                    let set_result: redis::RedisResult<String> = redis::cmd("XGROUP")
                        .arg("SETID")
                        .arg(&self.events_stream)
                        .arg(&self.consumer_group)
                        .arg("0")
                        .query_async(&mut self.conn)
                        .await;
                    match set_result {
                        Ok(_) => info!(
                            "Reset consumer group '{}' last-delivered-id to 0 (catch up on missed events)",
                            self.consumer_group
                        ),
                        Err(e) => warn!(
                            "Failed to reset consumer group '{}' offset: {}",
                            self.consumer_group, e
                        ),
                    }
                } else {
                    warn!(
                        "Failed to create consumer group '{}': {}",
                        self.consumer_group, e
                    );
                }
            }
        }
    }

    /// Read a batch of events from the Redis stream using `XREADGROUP`.
    ///
    /// Blocks for up to 1000ms waiting for new events.
    /// Returns a vector of `(stream_id, parsed_json_value)` tuples.
    pub async fn read_events(&mut self) -> Result<Vec<(String, Value)>> {
        let opts = redis::streams::StreamReadOptions::default()
            .group(&self.consumer_group, &self.consumer_name)
            .count(self.batch_size)
            .block(1000);

        let result: redis::streams::StreamReadReply = self
            .conn
            .xread_options(&[&self.events_stream], &[">"], &opts)
            .await
            .context("XREADGROUP failed")?;

        let mut events = Vec::new();

        for stream_key in &result.keys {
            for entry in &stream_key.ids {
                let stream_id = entry.id.clone();

                // The event data is stored under the "data" field as JSON
                if let Some(redis::Value::BulkString(bytes)) = entry.map.get("data") {
                    match serde_json::from_slice::<Value>(bytes) {
                        Ok(value) => {
                            events.push((stream_id, value));
                        }
                        Err(e) => {
                            warn!(
                                stream_id = %stream_id,
                                "Failed to parse event JSON: {}",
                                e
                            );
                        }
                    }
                } else {
                    debug!(
                        stream_id = %stream_id,
                        "Event entry missing 'data' field, skipping"
                    );
                }
            }
        }

        if !events.is_empty() {
            debug!("Read {} events from stream", events.len());
        }

        Ok(events)
    }

    /// Acknowledge processed events so they are not re-delivered.
    ///
    /// Sends `XACK` for the given stream IDs.
    pub async fn ack_events(&mut self, ids: &[String]) -> Result<()> {
        if ids.is_empty() {
            return Ok(());
        }

        let id_refs: Vec<&str> = ids.iter().map(|s| s.as_str()).collect();

        let _: u64 = self
            .conn
            .xack(&self.events_stream, &self.consumer_group, &id_refs)
            .await
            .context("XACK failed")?;

        debug!("Acknowledged {} events", ids.len());

        Ok(())
    }

    /// Publish an incident to the incidents Redis stream.
    ///
    /// Uses `XADD` with `MAXLEN ~ 50000` to cap stream size.
    pub async fn publish_incident(&mut self, incident: &Value) -> Result<()> {
        let json_data =
            serde_json::to_string(incident).context("Failed to serialize incident to JSON")?;

        let _: String = redis::cmd("XADD")
            .arg(&self.incidents_stream)
            .arg("MAXLEN")
            .arg("~")
            .arg(50000u64)
            .arg("*")
            .arg("data")
            .arg(&json_data)
            .query_async(&mut self.conn)
            .await
            .context("XADD to incidents stream failed")?;

        debug!("Published incident to '{}'", self.incidents_stream);

        Ok(())
    }
}
