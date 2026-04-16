// Auto-extracted from mod.rs — dashboard sse handlers

use super::*;
use std::sync::atomic::Ordering;

// ---------------------------------------------------------------------------
// D6 - SSE file watcher and stream handler
// ---------------------------------------------------------------------------

/// Polls today's incidents and decisions JSONL files every 2 s.
/// Broadcasts a `"refresh"` SSE payload whenever either file grows.
pub(super) async fn watch_for_new_entries(data_dir: PathBuf, tx: EventTx) {
    use std::collections::HashMap;
    use std::io::{Read, Seek, SeekFrom};

    // Track byte offsets so we can read only new lines.
    let mut offsets: HashMap<String, u64> = HashMap::new();
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));

    loop {
        interval.tick().await;
        if tx.receiver_count() == 0 {
            continue;
        }

        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();

        // Check decisions + incidents for growth → generic refresh signal.
        let refresh_files = [
            format!("incidents-{today}.jsonl"),
            format!("decisions-{today}.jsonl"),
        ];
        let mut changed = false;
        for name in &refresh_files {
            let path = data_dir.join(name);
            let current = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            let prev = offsets.entry(name.clone()).or_insert(current);
            if current > *prev {
                *prev = current;
                changed = true;
            }
        }
        if changed {
            let _ = tx.send(SsePayload {
                kind: "refresh".to_string(),
                data: None,
            });
        }

        // D8 - read new incident lines and emit `alert` for High/Critical.
        let inc_name = format!("incidents-{today}.jsonl");
        let inc_path = data_dir.join(&inc_name);
        let alert_key = format!("alert:{inc_name}");
        let alert_offset = offsets.entry(alert_key.clone()).or_insert(0);

        if let Ok(mut f) = std::fs::File::open(&inc_path) {
            let file_len = f.seek(SeekFrom::End(0)).unwrap_or(0);
            if file_len > *alert_offset {
                let _ = f.seek(SeekFrom::Start(*alert_offset));
                let mut buf = String::new();
                if f.read_to_string(&mut buf).is_ok() {
                    *alert_offset = file_len;
                    for line in buf.lines() {
                        if let Ok(inc) = serde_json::from_str::<Incident>(line) {
                            if matches!(inc.severity, Severity::High | Severity::Critical) {
                                let (etype, evalue) = extract_alert_entity(&inc);

                                let payload = serde_json::json!({
                                    "severity":     format!("{:?}", inc.severity).to_lowercase(),
                                    "title":        inc.title,
                                    "entity_type":  etype,
                                    "entity_value": evalue,
                                });
                                let _ = tx.send(SsePayload {
                                    kind: "alert".to_string(),
                                    data: Some(payload),
                                });
                            }
                        }
                    }
                }
            } else {
                // File shrunk (rotation) - reset offset.
                if file_len < *alert_offset {
                    *alert_offset = 0;
                }
            }
        }
    }
}

/// CORS middleware - injects headers on every response for live-feed routes.
pub(super) async fn cors_middleware(req: Request<Body>, next: Next) -> Response {
    if req.method() == Method::OPTIONS {
        return axum::http::Response::builder()
            .status(204)
            .header("access-control-allow-origin", "*")
            .header("access-control-allow-methods", "GET, OPTIONS")
            .header("access-control-allow-headers", "content-type, accept")
            .body(Body::empty())
            .unwrap()
            .into_response();
    }
    let mut resp = next.run(req).await;
    resp.headers_mut()
        .insert("access-control-allow-origin", HeaderValue::from_static("*"));
    resp
}
/// `GET /api/events/stream` - SSE live event stream (D6).
pub(super) async fn api_events_stream(
    State(state): State<DashboardState>,
) -> Result<
    Sse<impl futures_core::Stream<Item = Result<SseEvent, std::convert::Infallible>>>,
    StatusCode,
> {
    let current = SSE_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
    if current >= MAX_SSE_CONNECTIONS {
        SSE_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    let rx = state.event_tx.subscribe();
    let guard = SseGuard;
    let stream = BroadcastStream::new(rx).filter_map(move |msg: Result<SsePayload, _>| {
        let _keep = &guard;
        let payload = msg.ok()?;
        let data = serde_json::to_string(&payload).unwrap_or_default();
        Some(Ok(SseEvent::default().event(&payload.kind).data(data)))
    });
    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

// ---------------------------------------------------------------------------
// Route handlers

pub(super) fn extract_alert_entity(
    inc: &innerwarden_core::incident::Incident,
) -> (&'static str, String) {
    // Pick first ip entity, fall back to first entity of any kind.
    let entity = inc
        .entities
        .iter()
        .find(|e| e.r#type == innerwarden_core::entities::EntityType::Ip)
        .or_else(|| inc.entities.first());

    entity
        .map(|e| {
            let t = match e.r#type {
                innerwarden_core::entities::EntityType::Ip => "ip",
                innerwarden_core::entities::EntityType::User => "user",
                innerwarden_core::entities::EntityType::Container => "container",
                innerwarden_core::entities::EntityType::Path => "path",
                innerwarden_core::entities::EntityType::Service => "service",
            };
            (t, e.value.clone())
        })
        .unwrap_or(("ip", "unknown".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use innerwarden_core::entities::{EntityRef, EntityType};
    use innerwarden_core::incident::Incident;

    #[test]
    fn test_extract_alert_entity() {
        // Picks best entity representation for alert payload rendering.
        let root_inc = Incident {
            ts: Utc::now(),
            host: "test".to_string(),
            incident_id: "test1".to_string(),
            severity: innerwarden_core::event::Severity::High,
            title: "Test".to_string(),
            summary: "Test".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef {
                r#type: EntityType::User,
                value: "root".to_string(),
            }],
        };

        let (etype, eval) = extract_alert_entity(&root_inc);
        assert_eq!(etype, "user");
        assert_eq!(eval, "root");

        let ip_inc = Incident {
            entities: vec![
                EntityRef {
                    r#type: EntityType::User,
                    value: "root".to_string(),
                },
                EntityRef {
                    r#type: EntityType::Ip,
                    value: "1.2.3.4".to_string(),
                },
            ],
            ..root_inc
        };

        let (etype, eval) = extract_alert_entity(&ip_inc);
        assert_eq!(etype, "ip"); // should prefer ip over user
        assert_eq!(eval, "1.2.3.4");

        let empty_inc = Incident {
            entities: vec![],
            ..ip_inc
        };
        let (etype, eval) = extract_alert_entity(&empty_inc);
        assert_eq!(etype, "ip");
        assert_eq!(eval, "unknown");
    }

    #[test]
    fn test_sse_connection_count_starts_at_zero() {
        // The global SSE connection counter should be initialized to zero.
        assert_eq!(SSE_CONNECTIONS.load(Ordering::Relaxed), 0);
    }
}
