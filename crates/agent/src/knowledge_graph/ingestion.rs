use innerwarden_core::event::Event;
use innerwarden_core::incident::Incident;

use super::graph::KnowledgeGraph;
use super::types::*;

/// Helper to extract a string field from event.details JSON.
fn detail_str(event: &Event, key: &str) -> Option<String> {
    event.details.get(key).and_then(|v| v.as_str()).map(|s| s.to_string())
}

fn detail_u32(event: &Event, key: &str) -> Option<u32> {
    event.details.get(key).and_then(|v| v.as_u64()).map(|v| v as u32)
}

fn detail_u16(event: &Event, key: &str) -> Option<u16> {
    event.details.get(key).and_then(|v| v.as_u64()).map(|v| v as u16)
}

fn detail_u64(event: &Event, key: &str) -> Option<u64> {
    event.details.get(key).and_then(|v| v.as_u64())
}

fn detail_f32(event: &Event, key: &str) -> Option<f32> {
    event.details.get(key).and_then(|v| v.as_f64()).map(|v| v as f32)
}

fn detail_i64(event: &Event, key: &str) -> Option<i64> {
    event.details.get(key).and_then(|v| v.as_i64())
}

impl KnowledgeGraph {
    /// Ingest a sensor event into the graph, creating/updating nodes and edges.
    pub fn ingest(&mut self, event: &Event) {
        match event.kind.as_str() {
            // ── Shell & Execution ───────────────────────────────────
            "shell.command_exec" => self.ingest_shell_command_exec(event),
            "process.exec" => self.ingest_process_exec(event),
            "process.exit" => self.ingest_process_exit(event),
            "process.clone" => self.ingest_process_clone(event),
            "shell.tty_input" => self.ingest_shell_tty_input(event),

            // ── Privilege & Credentials ─────────────────────────────
            "privilege.escalation" => self.ingest_privilege_escalation(event),
            "privilege.setuid" => self.ingest_privilege_setuid(event),
            "sudo.command" => self.ingest_sudo_command(event),

            // ── SSH & Authentication ────────────────────────────────
            "ssh.login_failed" => self.ingest_ssh_login(event, false),
            "ssh.login_success" => self.ingest_ssh_login(event, true),
            "ssh.authorized_keys_changed" => self.ingest_ssh_authorized_keys_changed(event),

            // ── Network ─────────────────────────────────────────────
            "network.outbound_connect" => self.ingest_network_outbound(event),
            "network.accept" => self.ingest_network_accept(event),
            "network.listen" | "network.bind_listen" => self.ingest_network_listen(event),
            "network.connection_blocked" => self.ingest_network_blocked(event),
            "network.connection" => self.ingest_network_connection(event),
            "network.snapshot" => self.ingest_network_snapshot(event),

            // ── HTTP ────────────────────────────────────────────────
            "http.request" | "http.error" => self.ingest_http_request(event),

            // ── DNS ─────────────────────────────────────────────────
            "dns.query" | "suricata.dns.query" => self.ingest_dns_query(event),

            // ── File & Filesystem ───────────────────────────────────
            "file.write_access" => self.ingest_file_write(event),
            "file.read_access" => self.ingest_file_read(event),
            "file.delete" => self.ingest_file_delete(event),
            "file.rename" => self.ingest_file_rename(event),
            "file.truncate" => self.ingest_file_truncate(event),
            "file.timestomp" => self.ingest_file_timestomp(event),
            "file.ransomware_burst" => self.ingest_file_ransomware_burst(event),
            "file.changed" => self.ingest_file_changed(event),
            "file.extracted_from_network" => self.ingest_file_extracted(event),
            "file.scanned" => self.ingest_file_scanned(event),
            "filesystem.mount" => self.ingest_filesystem_mount(event),
            "cron.tampering" => self.ingest_cron_tampering(event),

            // ── Containers ──────────────────────────────────────────
            "container.start" => self.ingest_container_start(event),
            "container.die" => self.ingest_container_die(event),
            "container.oom" => self.ingest_container_oom(event),

            // ── Kernel & Firmware ───────────────────────────────────
            "kernel.module_load" => self.ingest_kernel_module_load(event),
            "kernel.new_module_post_boot" => self.ingest_kernel_new_module(event),
            "kernel.bpf_program_loaded" => self.ingest_kernel_bpf_loaded(event),
            "kernel.syscall_table_modified" => self.ingest_syscall_table_modified(event),
            "firmware.msr_write" => self.ingest_firmware_event(event, Relation::WroteMsr),
            "firmware.efi_call" => self.ingest_firmware_event(event, Relation::CalledEfi),
            "firmware.ioperm" => self.ingest_firmware_event(event, Relation::ChangedIoperm),
            "firmware.iopl" => self.ingest_firmware_event(event, Relation::ChangedIopl),
            "firmware.acpi_eval" => self.ingest_firmware_event(event, Relation::EvalAcpi),
            "firmware.timing_anomaly" => self.ingest_firmware_event(event, Relation::TimingAnomaly),
            "firmware.bpf_load" => self.ingest_firmware_event(event, Relation::LoadedBpf),

            // ── Process & Memory ────────────────────────────────────
            "process.ptrace_attach" => self.ingest_ptrace_attach(event),
            "process.prctl" => self.ingest_process_prctl(event),
            "process.signal" => self.ingest_process_signal(event),
            "process.fd_redirect" => self.ingest_fd_redirect(event),
            "process.memfd_create" => self.ingest_memfd_create(event),
            "memory.mprotect_exec" => self.ingest_mprotect_exec(event),

            // ── Hardware & IO ───────────────────────────────────────
            "hardware.usb_inserted" => self.ingest_usb(event, Relation::InsertedOn),
            "hardware.usb_removed" => self.ingest_usb(event, Relation::RemovedFrom),
            "io_uring.submit" => self.ingest_io_uring_submit(event),
            "io_uring.create" => self.ingest_io_uring_create(event),

            // ── System & Misc ───────────────────────────────────────
            "system.sysctl_changed" => self.ingest_sysctl_changed(event),
            "lsm.exec_blocked" => self.ingest_lsm_exec_blocked(event),
            "suricata.alert.potentially_bad_traffic" => self.ingest_suricata_alert(event),
            "web_scan" => self.ingest_web_scan(event),

            _ => {} // Unknown event kind — skip silently
        }
    }

    /// Ingest an incident into the graph as an Incident node with TriggeredBy edges.
    pub fn ingest_incident(&mut self, incident: &Incident) {
        let mitre_ids: Vec<String> = incident
            .tags
            .iter()
            .filter(|t| t.starts_with('T') && t.len() >= 5)
            .cloned()
            .collect();

        let detector = incident
            .incident_id
            .split(':')
            .next()
            .unwrap_or("unknown")
            .to_string();

        let inc_id = self.upsert_node(Node::Incident {
            incident_id: incident.incident_id.clone(),
            detector,
            severity: format!("{:?}", incident.severity),
            title: incident.title.clone(),
            summary: incident.summary.clone(),
            ts: incident.ts,
            mitre_ids,
            decision: None,
            confidence: None,
        });

        // Create TriggeredBy edges from Incident to each entity
        for entity in &incident.entities {
            let target = match entity.r#type {
                innerwarden_core::entities::EntityType::Ip => {
                    Some(self.ensure_ip(&entity.value, incident.ts))
                }
                innerwarden_core::entities::EntityType::User => {
                    Some(self.ensure_user(&entity.value))
                }
                innerwarden_core::entities::EntityType::Path => {
                    Some(self.ensure_file(&entity.value))
                }
                innerwarden_core::entities::EntityType::Container => {
                    Some(self.ensure_container(&entity.value))
                }
                innerwarden_core::entities::EntityType::Service => None,
            };
            if let Some(target_id) = target {
                self.add_edge(Edge::new(inc_id, target_id, Relation::TriggeredBy, incident.ts));
            }
        }
    }

    // ── Shell & Execution ───────────────────────────────────────────

    fn ingest_shell_command_exec(&mut self, event: &Event) {
        let pid = match detail_u32(event, "pid") {
            Some(p) => p,
            None => return,
        };
        let ppid = detail_u32(event, "ppid").unwrap_or(0);
        let comm = detail_str(event, "comm").unwrap_or_default();
        let uid = detail_u32(event, "uid").unwrap_or(0);

        let proc_id = self.ensure_process(pid, ppid, &comm, uid, event.ts);

        // Update exe if present
        if let Some(exe) = detail_str(event, "exe") {
            if let Some(Node::Process { exe: ref mut e, .. }) = self.get_node_mut(proc_id) {
                if e.is_none() {
                    *e = Some(exe.clone());
                }
            }
            // Executed edge
            let file_id = self.ensure_file(&exe);
            self.add_edge(Edge::new(proc_id, file_id, Relation::Executed, event.ts));
        }

        // Update container_id
        if let Some(cid) = detail_str(event, "container_id") {
            if !cid.is_empty() {
                if let Some(Node::Process { container_id, .. }) = self.get_node_mut(proc_id) {
                    if container_id.is_none() {
                        *container_id = Some(cid.clone());
                    }
                }
                let cont_id = self.ensure_container(&cid);
                self.add_edge(Edge::new(proc_id, cont_id, Relation::InContainer, event.ts));
            }
        }

        // SpawnedBy edge (child → parent)
        if ppid > 0 {
            let parent_id = self.ensure_process(ppid, 0, "", 0, event.ts);
            self.add_edge(Edge::new(proc_id, parent_id, Relation::SpawnedBy, event.ts));
        }

        // RunAs edge (process → user)
        let user_name = self.uid_to_user_name(event, uid);
        let user_id = self.ensure_user(&user_name);
        self.add_edge(Edge::new(proc_id, user_id, Relation::RunAs, event.ts));
    }

    fn ingest_process_exec(&mut self, event: &Event) {
        let pid = match detail_u32(event, "pid") {
            Some(p) => p,
            None => return,
        };
        let comm = detail_str(event, "comm").unwrap_or_default();
        let proc_id = self.ensure_process(pid, 0, &comm, 0, event.ts);

        if let Some(exe) = detail_str(event, "exe") {
            let file_id = self.ensure_file(&exe);
            self.add_edge(Edge::new(proc_id, file_id, Relation::Executed, event.ts));
        }
    }

    fn ingest_process_exit(&mut self, event: &Event) {
        let pid = match detail_u32(event, "pid") {
            Some(p) => p,
            None => return,
        };
        if let Some(proc_id) = self.find_by_pid(pid) {
            if let Some(Node::Process { exit_ts, .. }) = self.get_node_mut(proc_id) {
                *exit_ts = Some(event.ts);
            }
        }
    }

    fn ingest_process_clone(&mut self, event: &Event) {
        let child_pid = match detail_u32(event, "child_pid").or_else(|| detail_u32(event, "pid")) {
            Some(p) => p,
            None => return,
        };
        let parent_pid = detail_u32(event, "ppid").or_else(|| detail_u32(event, "parent_pid")).unwrap_or(0);
        let comm = detail_str(event, "comm").unwrap_or_default();
        let uid = detail_u32(event, "uid").unwrap_or(0);

        let child_id = self.ensure_process(child_pid, parent_pid, &comm, uid, event.ts);
        if parent_pid > 0 {
            let parent_id = self.ensure_process(parent_pid, 0, "", 0, event.ts);
            self.add_edge(Edge::new(child_id, parent_id, Relation::SpawnedBy, event.ts));
        }
    }

    fn ingest_shell_tty_input(&mut self, event: &Event) {
        if let Some(pid) = detail_u32(event, "pid") {
            if let Some(proc_id) = self.find_by_pid(pid) {
                if let Some(tty) = detail_str(event, "tty") {
                    // Just enrich — no new edges
                    let _ = (proc_id, tty);
                }
            }
        }
    }

    // ── Privilege & Credentials ─────────────────────────────────────

    fn ingest_privilege_escalation(&mut self, event: &Event) {
        let pid = match detail_u32(event, "pid") {
            Some(p) => p,
            None => return,
        };
        let comm = detail_str(event, "comm").unwrap_or_default();
        let uid = detail_u32(event, "uid").unwrap_or(0);
        let proc_id = self.ensure_process(pid, 0, &comm, uid, event.ts);

        let new_uid = detail_u32(event, "new_uid").unwrap_or(0);
        let user_name = format!("uid:{}", new_uid);
        let user_id = self.ensure_user(&user_name);

        let mut edge = Edge::new(proc_id, user_id, Relation::EscalatedTo, event.ts);
        edge = edge.with_prop("old_uid", serde_json::Value::from(uid));
        edge = edge.with_prop("new_uid", serde_json::Value::from(new_uid));
        self.add_edge(edge);
    }

    fn ingest_privilege_setuid(&mut self, event: &Event) {
        // Same structure as escalation
        self.ingest_privilege_escalation(event);
    }

    fn ingest_sudo_command(&mut self, event: &Event) {
        let user = detail_str(event, "user").unwrap_or_default();
        let run_as = detail_str(event, "run_as").unwrap_or_else(|| "root".to_string());
        let command = detail_str(event, "command").unwrap_or_default();

        // Try to find process by pid if available
        let proc_id = if let Some(pid) = detail_u32(event, "pid") {
            self.ensure_process(pid, 0, "sudo", 0, event.ts)
        } else {
            // Create a generic sudo process node
            let pid = (event.ts.timestamp_millis() & 0xFFFF) as u32 + 60000;
            self.ensure_process(pid, 0, "sudo", 0, event.ts)
        };

        let user_id = self.ensure_user(&run_as);
        let edge = Edge::new(proc_id, user_id, Relation::SudoAs, event.ts)
            .with_prop("command", serde_json::Value::from(command))
            .with_prop("original_user", serde_json::Value::from(user));
        self.add_edge(edge);
    }

    // ── SSH & Authentication ────────────────────────────────────────

    fn ingest_ssh_login(&mut self, event: &Event, success: bool) {
        let ip_str = detail_str(event, "ip").unwrap_or_default();
        let user_str = detail_str(event, "user").unwrap_or_default();

        if ip_str.is_empty() || user_str.is_empty() {
            return;
        }

        let user_id = self.ensure_user(&user_str);
        let ip_id = self.ensure_ip(&ip_str, event.ts);

        let mut edge = Edge::new(user_id, ip_id, Relation::LoggedInFrom, event.ts);
        edge = edge.with_prop("success", serde_json::Value::from(success));
        if let Some(method) = detail_str(event, "method") {
            edge = edge.with_prop("method", serde_json::Value::from(method));
        }
        if !success {
            if let Some(reason) = detail_str(event, "reason") {
                edge = edge.with_prop("reason", serde_json::Value::from(reason));
            }
        }
        self.add_edge(edge);
    }

    fn ingest_ssh_authorized_keys_changed(&mut self, event: &Event) {
        let path = detail_str(event, "path").unwrap_or_default();
        if path.is_empty() {
            return;
        }
        let file_id = self.ensure_file(&path);

        // IntegrityChanged self-loop
        let mut edge = Edge::new(file_id, file_id, Relation::IntegrityChanged, event.ts);
        if let Some(old) = detail_str(event, "old_hash") {
            edge = edge.with_prop("old_hash", serde_json::Value::from(old));
        }
        if let Some(new) = detail_str(event, "new_hash") {
            edge = edge.with_prop("new_hash", serde_json::Value::from(new.clone()));
            // Update file sha256
            if let Some(Node::File { sha256, .. }) = self.get_node_mut(file_id) {
                *sha256 = Some(new);
            }
        }
        self.add_edge(edge);
    }

    // ── Network ─────────────────────────────────────────────────────

    fn ingest_network_outbound(&mut self, event: &Event) {
        let pid = match detail_u32(event, "pid") {
            Some(p) => p,
            None => return,
        };
        let comm = detail_str(event, "comm").unwrap_or_default();
        let uid = detail_u32(event, "uid").unwrap_or(0);
        let dst_ip = match detail_str(event, "dst_ip") {
            Some(ip) => ip,
            None => return,
        };
        let dst_port = detail_u16(event, "dst_port").unwrap_or(0);

        let proc_id = self.ensure_process(pid, 0, &comm, uid, event.ts);
        let ip_id = self.ensure_ip(&dst_ip, event.ts);

        let edge = Edge::new(proc_id, ip_id, Relation::ConnectedTo, event.ts)
            .with_prop("port", serde_json::Value::from(dst_port))
            .with_prop("proto", serde_json::Value::from("tcp"));
        self.add_edge(edge);

        // Container context
        if let Some(cid) = detail_str(event, "container_id") {
            if !cid.is_empty() {
                let cont_id = self.ensure_container(&cid);
                self.add_edge(Edge::new(proc_id, cont_id, Relation::InContainer, event.ts));
            }
        }
    }

    fn ingest_network_accept(&mut self, event: &Event) {
        let pid = match detail_u32(event, "pid") {
            Some(p) => p,
            None => return,
        };
        let comm = detail_str(event, "comm").unwrap_or_default();
        let uid = detail_u32(event, "uid").unwrap_or(0);
        let src_ip = match detail_str(event, "src_ip").or_else(|| detail_str(event, "ip")) {
            Some(ip) => ip,
            None => return,
        };

        let proc_id = self.ensure_process(pid, 0, &comm, uid, event.ts);
        let ip_id = self.ensure_ip(&src_ip, event.ts);

        let mut edge = Edge::new(proc_id, ip_id, Relation::AcceptedFrom, event.ts);
        if let Some(port) = detail_u16(event, "dst_port").or_else(|| detail_u16(event, "port")) {
            edge = edge.with_prop("port", serde_json::Value::from(port));
        }
        self.add_edge(edge);
    }

    fn ingest_network_listen(&mut self, event: &Event) {
        let pid = match detail_u32(event, "pid") {
            Some(p) => p,
            None => return,
        };
        let comm = detail_str(event, "comm").unwrap_or_default();
        let uid = detail_u32(event, "uid").unwrap_or(0);
        let port_num = match detail_u16(event, "port").or_else(|| detail_u16(event, "dst_port")) {
            Some(p) => p,
            None => return,
        };
        let proto = detail_str(event, "proto").unwrap_or_else(|| "tcp".to_string());

        let proc_id = self.ensure_process(pid, 0, &comm, uid, event.ts);
        let port_id = self.ensure_port(port_num, &proto);

        self.add_edge(Edge::new(proc_id, port_id, Relation::ListensOn, event.ts));
    }

    fn ingest_network_blocked(&mut self, event: &Event) {
        let src_ip = match detail_str(event, "src_ip") {
            Some(ip) => ip,
            None => return,
        };
        let dst_port = match detail_u16(event, "dst_port") {
            Some(p) => p,
            None => return,
        };
        let proto = detail_str(event, "proto").unwrap_or_else(|| "tcp".to_string());

        let ip_id = self.ensure_ip(&src_ip, event.ts);
        let port_id = self.ensure_port(dst_port, &proto);

        let mut edge = Edge::new(ip_id, port_id, Relation::ScannedPort, event.ts);
        if let Some(action) = detail_str(event, "action") {
            edge = edge.with_prop("action", serde_json::Value::from(action));
        }
        self.add_edge(edge);
    }

    fn ingest_network_connection(&mut self, event: &Event) {
        // Generic: try pid + dst_ip
        let dst_ip = match detail_str(event, "dst_ip") {
            Some(ip) => ip,
            None => return,
        };
        let ip_id = self.ensure_ip(&dst_ip, event.ts);

        if let Some(pid) = detail_u32(event, "pid") {
            let comm = detail_str(event, "comm").unwrap_or_default();
            let proc_id = self.ensure_process(pid, 0, &comm, 0, event.ts);
            self.add_edge(Edge::new(proc_id, ip_id, Relation::ConnectedTo, event.ts));
        }
    }

    fn ingest_network_snapshot(&mut self, event: &Event) {
        // Bulk connections from snapshot
        if let Some(connections) = event.details.get("connections").and_then(|v| v.as_array()) {
            for conn in connections {
                let pid = conn.get("pid").and_then(|v| v.as_u64()).map(|v| v as u32);
                let dst_ip = conn.get("dst_ip").and_then(|v| v.as_str());
                let port = conn.get("port").and_then(|v| v.as_u64()).map(|v| v as u16);
                let state = conn.get("state").and_then(|v| v.as_str());

                if let (Some(pid), Some(dst_ip)) = (pid, dst_ip) {
                    let proc_id = self.ensure_process(pid, 0, "", 0, event.ts);
                    let ip_id = self.ensure_ip(dst_ip, event.ts);
                    let mut edge = Edge::new(proc_id, ip_id, Relation::SnapshotConnectedTo, event.ts);
                    if let Some(p) = port {
                        edge = edge.with_prop("port", serde_json::Value::from(p));
                    }
                    if let Some(s) = state {
                        edge = edge.with_prop("state", serde_json::Value::from(s));
                    }
                    self.add_edge(edge);
                }
            }
        }

        if let Some(listening) = event.details.get("listening_ports").and_then(|v| v.as_array()) {
            for entry in listening {
                let pid = entry.get("pid").and_then(|v| v.as_u64()).map(|v| v as u32);
                let port_num = entry.get("port").and_then(|v| v.as_u64()).map(|v| v as u16);
                let proto = entry.get("proto").and_then(|v| v.as_str()).unwrap_or("tcp");

                if let (Some(pid), Some(port_num)) = (pid, port_num) {
                    let proc_id = self.ensure_process(pid, 0, "", 0, event.ts);
                    let port_id = self.ensure_port(port_num, proto);
                    self.add_edge(Edge::new(proc_id, port_id, Relation::SnapshotListensOn, event.ts));
                }
            }
        }
    }

    // ── HTTP ────────────────────────────────────────────────────────

    fn ingest_http_request(&mut self, event: &Event) {
        let src_ip = match detail_str(event, "ip").or_else(|| detail_str(event, "src_ip")) {
            Some(ip) => ip,
            None => return,
        };
        let src_id = self.ensure_ip(&src_ip, event.ts);

        // Destination can be host header or dst_ip
        let dst = detail_str(event, "host").or_else(|| detail_str(event, "dst_ip"));
        let dst_id = if let Some(ref d) = dst {
            self.ensure_ip(d, event.ts)
        } else {
            // Self-referential for server-side captured requests
            self.ensure_system(&event.host)
        };

        let mut edge = Edge::new(src_id, dst_id, Relation::HttpRequestTo, event.ts);
        if let Some(method) = detail_str(event, "method") {
            edge = edge.with_prop("method", serde_json::Value::from(method));
        }
        if let Some(path) = detail_str(event, "path") {
            edge = edge.with_prop("path", serde_json::Value::from(path));
        }
        if let Some(status) = detail_u16(event, "status") {
            edge = edge.with_prop("status", serde_json::Value::from(status));
        }
        if let Some(ua) = detail_str(event, "user_agent") {
            edge = edge.with_prop("user_agent", serde_json::Value::from(ua));
        }
        self.add_edge(edge);
    }

    // ── DNS ─────────────────────────────────────────────────────────

    fn ingest_dns_query(&mut self, event: &Event) {
        let domain = match detail_str(event, "domain") {
            Some(d) => d,
            None => return,
        };
        let domain_id = self.ensure_domain(&domain);

        let mut edge_props = Vec::new();
        if let Some(qt) = detail_str(event, "query_type") {
            edge_props.push(("query_type", serde_json::Value::from(qt)));
        }
        if let Some(rc) = detail_str(event, "response_code") {
            edge_props.push(("response_code", serde_json::Value::from(rc)));
        }

        // If we have a pid, edge is Process → Domain
        if let Some(pid) = detail_u32(event, "pid") {
            let proc_id = self.ensure_process(pid, 0, "", 0, event.ts);
            let mut edge = Edge::new(proc_id, domain_id, Relation::Resolved, event.ts);
            for (k, v) in edge_props {
                edge = edge.with_prop(k, v);
            }
            self.add_edge(edge);
        } else if let Some(src_ip) = detail_str(event, "src_ip") {
            // Fallback: Ip → Domain
            let ip_id = self.ensure_ip(&src_ip, event.ts);
            let mut edge = Edge::new(ip_id, domain_id, Relation::Resolved, event.ts);
            for (k, v) in edge_props {
                edge = edge.with_prop(k, v);
            }
            self.add_edge(edge);
        }
    }

    // ── File & Filesystem ───────────────────────────────────────────

    fn ingest_file_write(&mut self, event: &Event) {
        let path = match detail_str(event, "path") {
            Some(p) => p,
            None => return,
        };
        let file_id = self.ensure_file(&path);

        if let Some(pid) = detail_u32(event, "pid") {
            let comm = detail_str(event, "comm").unwrap_or_default();
            let uid = detail_u32(event, "uid").unwrap_or(0);
            let proc_id = self.ensure_process(pid, 0, &comm, uid, event.ts);
            self.add_edge(Edge::new(proc_id, file_id, Relation::Wrote, event.ts));
        }
    }

    fn ingest_file_read(&mut self, event: &Event) {
        let path = match detail_str(event, "path") {
            Some(p) => p,
            None => return,
        };
        let file_id = self.ensure_file(&path);

        if let Some(pid) = detail_u32(event, "pid") {
            let comm = detail_str(event, "comm").unwrap_or_default();
            let proc_id = self.ensure_process(pid, 0, &comm, 0, event.ts);
            self.add_edge(Edge::new(proc_id, file_id, Relation::Read, event.ts));
        }
    }

    fn ingest_file_delete(&mut self, event: &Event) {
        let path = match detail_str(event, "pathname").or_else(|| detail_str(event, "path")) {
            Some(p) => p,
            None => return,
        };
        let file_id = self.ensure_file(&path);

        if let Some(pid) = detail_u32(event, "pid") {
            let proc_id = self.ensure_process(pid, 0, "", 0, event.ts);
            self.add_edge(Edge::new(proc_id, file_id, Relation::Deleted, event.ts));
        }
    }

    fn ingest_file_rename(&mut self, event: &Event) {
        let old_path = match detail_str(event, "old_path").or_else(|| detail_str(event, "path")) {
            Some(p) => p,
            None => return,
        };
        let new_path = detail_str(event, "new_path").unwrap_or_default();

        let file_id = self.ensure_file(&old_path);
        if !new_path.is_empty() {
            // Also create the new file node
            self.ensure_file(&new_path);
        }

        if let Some(pid) = detail_u32(event, "pid") {
            let proc_id = self.ensure_process(pid, 0, "", 0, event.ts);
            let edge = Edge::new(proc_id, file_id, Relation::Renamed, event.ts)
                .with_prop("new_path", serde_json::Value::from(new_path));
            self.add_edge(edge);
        }
    }

    fn ingest_file_truncate(&mut self, event: &Event) {
        let path = match detail_str(event, "path").or_else(|| detail_str(event, "pathname")) {
            Some(p) => p,
            None => return,
        };
        let file_id = self.ensure_file(&path);

        if let Some(pid) = detail_u32(event, "pid") {
            let proc_id = self.ensure_process(pid, 0, "", 0, event.ts);
            self.add_edge(Edge::new(proc_id, file_id, Relation::Truncated, event.ts));
        }
    }

    fn ingest_file_timestomp(&mut self, event: &Event) {
        let path = match detail_str(event, "path").or_else(|| detail_str(event, "pathname")) {
            Some(p) => p,
            None => return,
        };
        let file_id = self.ensure_file(&path);

        if let Some(pid) = detail_u32(event, "pid") {
            let proc_id = self.ensure_process(pid, 0, "", 0, event.ts);
            self.add_edge(Edge::new(proc_id, file_id, Relation::Timestomped, event.ts));
        }
    }

    fn ingest_file_ransomware_burst(&mut self, event: &Event) {
        let path = match detail_str(event, "path") {
            Some(p) => p,
            None => return,
        };
        let file_id = self.ensure_file(&path);

        if let Some(pid) = detail_u32(event, "pid") {
            let proc_id = self.ensure_process(pid, 0, "", 0, event.ts);
            let mut edge = Edge::new(proc_id, file_id, Relation::Wrote, event.ts);
            edge = edge.with_prop("ransomware_burst", serde_json::Value::from(true));
            if let Some(count) = detail_u32(event, "write_count") {
                edge = edge.with_prop("write_count", serde_json::Value::from(count));
            }
            if let Some(window) = detail_u32(event, "time_window_secs") {
                edge = edge.with_prop("time_window_secs", serde_json::Value::from(window));
            }
            self.add_edge(edge);
        }
    }

    fn ingest_file_changed(&mut self, event: &Event) {
        let path = match detail_str(event, "path") {
            Some(p) => p,
            None => return,
        };
        let file_id = self.ensure_file(&path);

        let mut edge = Edge::new(file_id, file_id, Relation::IntegrityChanged, event.ts);
        if let Some(old) = detail_str(event, "old_hash") {
            edge = edge.with_prop("old_hash", serde_json::Value::from(old));
        }
        if let Some(new) = detail_str(event, "new_hash") {
            edge = edge.with_prop("new_hash", serde_json::Value::from(new.clone()));
            if let Some(Node::File { sha256, .. }) = self.get_node_mut(file_id) {
                *sha256 = Some(new);
            }
        }
        self.add_edge(edge);
    }

    fn ingest_file_extracted(&mut self, event: &Event) {
        let filename = match detail_str(event, "filename") {
            Some(f) => f,
            None => return,
        };
        let source_ip = match detail_str(event, "source_ip") {
            Some(ip) => ip,
            None => return,
        };

        let file_id = self.ensure_file(&filename);
        let ip_id = self.ensure_ip(&source_ip, event.ts);

        // Enrich file node
        if let Some(Node::File { entropy, size, sha256, .. }) = self.get_node_mut(file_id) {
            if let Some(e) = detail_f32(event, "entropy") {
                *entropy = Some(e);
            }
            if let Some(s) = detail_u64(event, "size") {
                *size = Some(s);
            }
            if let Some(h) = detail_str(event, "sha256") {
                *sha256 = Some(h);
            }
        }

        let mut edge = Edge::new(file_id, ip_id, Relation::DownloadedFrom, event.ts);
        if let Some(method) = detail_str(event, "method") {
            edge = edge.with_prop("method", serde_json::Value::from(method));
        }
        self.add_edge(edge);
    }

    fn ingest_file_scanned(&mut self, event: &Event) {
        let path = match detail_str(event, "path") {
            Some(p) => p,
            None => return,
        };
        let file_id = self.ensure_file(&path);

        if let Some(rule) = detail_str(event, "yara_rule") {
            if let Some(Node::File { yara_matches, .. }) = self.get_node_mut(file_id) {
                if !yara_matches.contains(&rule) {
                    yara_matches.push(rule);
                }
            }
        }
    }

    fn ingest_filesystem_mount(&mut self, event: &Event) {
        let pid = match detail_u32(event, "pid") {
            Some(p) => p,
            None => return,
        };
        let mount_point = detail_str(event, "path").or_else(|| detail_str(event, "mount_point")).unwrap_or_default();
        let proc_id = self.ensure_process(pid, 0, "", 0, event.ts);
        let file_id = self.ensure_file(&mount_point);

        let mut edge = Edge::new(proc_id, file_id, Relation::Mounted, event.ts);
        if let Some(fstype) = detail_str(event, "fstype") {
            edge = edge.with_prop("fstype", serde_json::Value::from(fstype));
        }
        if let Some(flags) = detail_str(event, "flags") {
            edge = edge.with_prop("flags", serde_json::Value::from(flags));
        }
        self.add_edge(edge);
    }

    fn ingest_cron_tampering(&mut self, event: &Event) {
        let path = match detail_str(event, "path") {
            Some(p) => p,
            None => return,
        };
        let file_id = self.ensure_file(&path);

        // Mark as sensitive
        if let Some(Node::File { is_sensitive, .. }) = self.get_node_mut(file_id) {
            *is_sensitive = true;
        }

        let mut edge = Edge::new(file_id, file_id, Relation::IntegrityChanged, event.ts);
        if let Some(old) = detail_str(event, "old_hash") {
            edge = edge.with_prop("old_hash", serde_json::Value::from(old));
        }
        if let Some(new) = detail_str(event, "new_hash") {
            edge = edge.with_prop("new_hash", serde_json::Value::from(new));
        }
        self.add_edge(edge);
    }

    // ── Containers ──────────────────────────────────────────────────

    fn ingest_container_start(&mut self, event: &Event) {
        let container_id = match detail_str(event, "container_id") {
            Some(id) => id,
            None => return,
        };
        let cont_id = self.ensure_container(&container_id);

        if let Some(Node::Container { name, image, start_ts, .. }) = self.get_node_mut(cont_id) {
            if let Some(n) = detail_str(event, "name") {
                *name = Some(n);
            }
            if let Some(i) = detail_str(event, "image") {
                *image = Some(i);
            }
            *start_ts = Some(event.ts);
        }

        let sys_id = self.ensure_system(&event.host);
        self.add_edge(Edge::new(cont_id, sys_id, Relation::StartedOn, event.ts));
    }

    fn ingest_container_die(&mut self, event: &Event) {
        let container_id = match detail_str(event, "container_id") {
            Some(id) => id,
            None => return,
        };
        let cont_id = self.ensure_container(&container_id);

        if let Some(Node::Container { exit_ts, .. }) = self.get_node_mut(cont_id) {
            *exit_ts = Some(event.ts);
        }

        let sys_id = self.ensure_system(&event.host);
        self.add_edge(Edge::new(cont_id, sys_id, Relation::DiedOn, event.ts));
    }

    fn ingest_container_oom(&mut self, event: &Event) {
        let container_id = match detail_str(event, "container_id") {
            Some(id) => id,
            None => return,
        };
        let cont_id = self.ensure_container(&container_id);

        if let Some(Node::Container { oom_killed, .. }) = self.get_node_mut(cont_id) {
            *oom_killed = true;
        }

        let sys_id = self.ensure_system(&event.host);
        self.add_edge(Edge::new(cont_id, sys_id, Relation::OomKilled, event.ts));
    }

    // ── Kernel & Firmware ───────────────────────────────────────────

    fn ingest_kernel_module_load(&mut self, event: &Event) {
        let sys_id = self.ensure_system(&event.host);

        let mut edge = if let Some(pid) = detail_u32(event, "pid") {
            let proc_id = self.ensure_process(pid, 0, "", 0, event.ts);
            Edge::new(proc_id, sys_id, Relation::LoadedModule, event.ts)
        } else {
            Edge::new(sys_id, sys_id, Relation::LoadedModule, event.ts)
        };

        if let Some(name) = detail_str(event, "module_name") {
            edge = edge.with_prop("module_name", serde_json::Value::from(name));
        }
        if let Some(params) = detail_str(event, "module_params") {
            edge = edge.with_prop("module_params", serde_json::Value::from(params));
        }
        self.add_edge(edge);
    }

    fn ingest_kernel_new_module(&mut self, event: &Event) {
        let sys_id = self.ensure_system(&event.host);
        let mut edge = Edge::new(sys_id, sys_id, Relation::LoadedModule, event.ts);
        if let Some(name) = detail_str(event, "module_name") {
            edge = edge.with_prop("module_name", serde_json::Value::from(name));
        }
        edge = edge.with_prop("post_boot", serde_json::Value::from(true));
        self.add_edge(edge);
    }

    fn ingest_kernel_bpf_loaded(&mut self, event: &Event) {
        let sys_id = self.ensure_system(&event.host);
        let mut edge = Edge::new(sys_id, sys_id, Relation::LoadedBpf, event.ts);
        if let Some(pt) = detail_str(event, "prog_type") {
            edge = edge.with_prop("prog_type", serde_json::Value::from(pt));
        }
        self.add_edge(edge);
    }

    fn ingest_syscall_table_modified(&mut self, event: &Event) {
        let sys_id = self.ensure_system(&event.host);
        self.add_edge(Edge::new(sys_id, sys_id, Relation::SyscallTableModified, event.ts));
    }

    fn ingest_firmware_event(&mut self, event: &Event, relation: Relation) {
        let sys_id = self.ensure_system(&event.host);

        let edge = if let Some(pid) = detail_u32(event, "pid") {
            let proc_id = self.ensure_process(pid, 0, "", 0, event.ts);
            let mut e = Edge::new(proc_id, sys_id, relation, event.ts);
            // Copy relevant properties
            if let Some(msr) = detail_u32(event, "msr_number") {
                e = e.with_prop("msr_number", serde_json::Value::from(msr));
            }
            if let Some(val) = detail_u64(event, "value") {
                e = e.with_prop("value", serde_json::Value::from(val));
            }
            if let Some(delta) = detail_f32(event, "delta") {
                e = e.with_prop("delta", serde_json::Value::from(delta));
            }
            e
        } else {
            Edge::new(sys_id, sys_id, relation, event.ts)
        };
        self.add_edge(edge);
    }

    // ── Process & Memory ────────────────────────────────────────────

    fn ingest_ptrace_attach(&mut self, event: &Event) {
        let parent_pid = match detail_u32(event, "parent_pid").or_else(|| detail_u32(event, "pid")) {
            Some(p) => p,
            None => return,
        };
        let target_pid = match detail_u32(event, "target_pid") {
            Some(p) => p,
            None => return,
        };

        let parent_id = self.ensure_process(parent_pid, 0, "", 0, event.ts);
        let target_id = self.ensure_process(target_pid, 0, "", 0, event.ts);

        let mut edge = Edge::new(parent_id, target_id, Relation::PtraceAttached, event.ts);
        if let Some(req) = detail_u64(event, "request") {
            edge = edge.with_prop("request", serde_json::Value::from(req));
        }
        self.add_edge(edge);
    }

    fn ingest_process_prctl(&mut self, event: &Event) {
        // Enrichment only — no new edges
        if let Some(pid) = detail_u32(event, "pid") {
            self.ensure_process(pid, 0, "", 0, event.ts);
        }
    }

    fn ingest_process_signal(&mut self, event: &Event) {
        let sender_pid = match detail_u32(event, "pid") {
            Some(p) => p,
            None => return,
        };
        let target_pid = match detail_u32(event, "target_pid") {
            Some(p) => p,
            None => return,
        };
        let signal = detail_i64(event, "signal").unwrap_or(0) as i32;

        let sender_id = self.ensure_process(sender_pid, 0, "", 0, event.ts);
        let target_id = self.ensure_process(target_pid, 0, "", 0, event.ts);

        let edge = Edge::new(sender_id, target_id, Relation::Signaled, event.ts)
            .with_prop("signal", serde_json::Value::from(signal));
        self.add_edge(edge);
    }

    fn ingest_fd_redirect(&mut self, event: &Event) {
        let pid = match detail_u32(event, "pid") {
            Some(p) => p,
            None => return,
        };
        let proc_id = self.ensure_process(pid, 0, "", 0, event.ts);

        let mut edge = Edge::new(proc_id, proc_id, Relation::RedirectedFd, event.ts);
        if let Some(old_fd) = detail_i64(event, "old_fd") {
            edge = edge.with_prop("old_fd", serde_json::Value::from(old_fd));
        }
        if let Some(new_fd) = detail_i64(event, "new_fd") {
            edge = edge.with_prop("new_fd", serde_json::Value::from(new_fd));
        }
        self.add_edge(edge);
    }

    fn ingest_memfd_create(&mut self, event: &Event) {
        let pid = match detail_u32(event, "pid") {
            Some(p) => p,
            None => return,
        };
        let proc_id = self.ensure_process(pid, 0, "", 0, event.ts);

        let mut edge = Edge::new(proc_id, proc_id, Relation::CreatedMemfd, event.ts);
        if let Some(fd) = detail_i64(event, "fd") {
            edge = edge.with_prop("fd", serde_json::Value::from(fd));
        }
        self.add_edge(edge);
    }

    fn ingest_mprotect_exec(&mut self, event: &Event) {
        let pid = match detail_u32(event, "pid") {
            Some(p) => p,
            None => return,
        };
        let proc_id = self.ensure_process(pid, 0, "", 0, event.ts);

        let mut edge = Edge::new(proc_id, proc_id, Relation::MprotectExec, event.ts);
        if let Some(addr) = detail_u64(event, "addr") {
            edge = edge.with_prop("addr", serde_json::Value::from(addr));
        }
        if let Some(len) = detail_u64(event, "len") {
            edge = edge.with_prop("len", serde_json::Value::from(len));
        }
        if let Some(prot) = detail_u32(event, "prot") {
            edge = edge.with_prop("prot", serde_json::Value::from(prot));
        }
        self.add_edge(edge);
    }

    // ── Hardware & IO ───────────────────────────────────────────────

    fn ingest_usb(&mut self, event: &Event, relation: Relation) {
        let vendor = detail_str(event, "vendor").unwrap_or_default();
        let product = detail_str(event, "product").unwrap_or_default();
        let serial = detail_str(event, "serial");
        let dev_class = detail_str(event, "dev_class");

        let device_id = self.upsert_node(Node::Device {
            vendor,
            product,
            serial,
            dev_class,
        });
        let sys_id = self.ensure_system(&event.host);
        self.add_edge(Edge::new(device_id, sys_id, relation, event.ts));
    }

    fn ingest_io_uring_submit(&mut self, event: &Event) {
        let pid = match detail_u32(event, "pid") {
            Some(p) => p,
            None => return,
        };
        let proc_id = self.ensure_process(pid, 0, "", 0, event.ts);
        let sys_id = self.ensure_system(&event.host);

        let mut edge = Edge::new(proc_id, sys_id, Relation::IoUringSubmit, event.ts);
        if let Some(sqe) = detail_u32(event, "sqe_count") {
            edge = edge.with_prop("sqe_count", serde_json::Value::from(sqe));
        }
        if let Some(flags) = detail_u32(event, "flags") {
            edge = edge.with_prop("flags", serde_json::Value::from(flags));
        }
        self.add_edge(edge);
    }

    fn ingest_io_uring_create(&mut self, event: &Event) {
        let pid = match detail_u32(event, "pid") {
            Some(p) => p,
            None => return,
        };
        let proc_id = self.ensure_process(pid, 0, "", 0, event.ts);
        let sys_id = self.ensure_system(&event.host);

        let mut edge = Edge::new(proc_id, sys_id, Relation::IoUringCreate, event.ts);
        if let Some(entries) = detail_u32(event, "entries") {
            edge = edge.with_prop("entries", serde_json::Value::from(entries));
        }
        self.add_edge(edge);
    }

    // ── System & Misc ───────────────────────────────────────────────

    fn ingest_sysctl_changed(&mut self, event: &Event) {
        let sys_id = self.ensure_system(&event.host);

        let param = detail_str(event, "param").unwrap_or_default();
        let old_value = detail_str(event, "old_value").unwrap_or_default();
        let new_value = detail_str(event, "new_value").unwrap_or_default();

        // Update system node
        if let Some(Node::System { sysctl_params, .. }) = self.get_node_mut(sys_id) {
            sysctl_params.insert(param.clone(), new_value.clone());
        }

        let edge = Edge::new(sys_id, sys_id, Relation::ChangedSysctl, event.ts)
            .with_prop("param", serde_json::Value::from(param))
            .with_prop("old_value", serde_json::Value::from(old_value))
            .with_prop("new_value", serde_json::Value::from(new_value));
        self.add_edge(edge);
    }

    fn ingest_lsm_exec_blocked(&mut self, event: &Event) {
        let sys_id = self.ensure_system(&event.host);

        if let Some(pid) = detail_u32(event, "pid") {
            let proc_id = self.ensure_process(pid, 0, "", 0, event.ts);
            let mut edge = Edge::new(sys_id, proc_id, Relation::ExecBlocked, event.ts);
            if let Some(reason) = detail_str(event, "reason") {
                edge = edge.with_prop("reason", serde_json::Value::from(reason));
            }
            self.add_edge(edge);
        }
    }

    fn ingest_suricata_alert(&mut self, event: &Event) {
        let src_ip = detail_str(event, "src_ip");
        let dst_ip = detail_str(event, "dst_ip");

        if let (Some(src), Some(dst)) = (src_ip, dst_ip) {
            let src_id = self.ensure_ip(&src, event.ts);
            let dst_id = self.ensure_ip(&dst, event.ts);
            let mut edge = Edge::new(src_id, dst_id, Relation::ConnectedTo, event.ts);
            edge = edge.with_prop("suricata_alert", serde_json::Value::from(true));
            if let Some(sig) = detail_str(event, "signature") {
                edge = edge.with_prop("signature", serde_json::Value::from(sig));
            }
            self.add_edge(edge);
        }
    }

    fn ingest_web_scan(&mut self, event: &Event) {
        if let Some(src_ip) = detail_str(event, "src_ip").or_else(|| detail_str(event, "ip")) {
            let src_id = self.ensure_ip(&src_ip, event.ts);
            let sys_id = self.ensure_system(&event.host);
            let edge = Edge::new(src_id, sys_id, Relation::HttpRequestTo, event.ts)
                .with_prop("scan", serde_json::Value::from(true));
            self.add_edge(edge);
        }
    }

    // ── Internal helpers ────────────────────────────────────────────

    fn uid_to_user_name(&self, event: &Event, uid: u32) -> String {
        // Try to get user from entities
        for entity in &event.entities {
            if entity.r#type == innerwarden_core::entities::EntityType::User {
                return entity.value.clone();
            }
        }
        // Fallback to uid-based name
        match uid {
            0 => "root".to_string(),
            _ => format!("uid:{}", uid),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use innerwarden_core::entities::EntityRef;
    use innerwarden_core::event::Severity;

    fn make_event(kind: &str, details: serde_json::Value) -> Event {
        Event {
            ts: Utc.with_ymd_and_hms(2026, 4, 9, 14, 0, 0).unwrap(),
            host: "prod-01".to_string(),
            source: "ebpf".to_string(),
            kind: kind.to_string(),
            severity: Severity::Medium,
            summary: String::new(),
            details,
            tags: Vec::new(),
            entities: Vec::new(),
        }
    }

    #[test]
    fn test_ingest_shell_command_exec() {
        let mut g = KnowledgeGraph::new();
        let event = make_event(
            "shell.command_exec",
            serde_json::json!({
                "pid": 1234, "ppid": 800, "comm": "bash",
                "exe": "/bin/bash", "uid": 0
            }),
        );
        g.ingest(&event);

        assert!(g.find_by_pid(1234).is_some());
        assert!(g.find_by_pid(800).is_some()); // parent
        assert!(g.find_by_path("/bin/bash").is_some());
        assert!(g.find_by_user("root").is_some());
        // SpawnedBy + RunAs + Executed = 3 edges
        assert!(g.edge_count() >= 3);
    }

    #[test]
    fn test_ingest_ssh_login() {
        let mut g = KnowledgeGraph::new();
        let event = make_event(
            "ssh.login_failed",
            serde_json::json!({"ip": "185.1.1.1", "user": "root", "reason": "invalid password", "method": "password"}),
        );
        g.ingest(&event);

        assert!(g.find_by_ip("185.1.1.1").is_some());
        assert!(g.find_by_user("root").is_some());
        assert_eq!(g.edge_count(), 1); // LoggedInFrom
    }

    #[test]
    fn test_ingest_network_outbound() {
        let mut g = KnowledgeGraph::new();
        let event = make_event(
            "network.outbound_connect",
            serde_json::json!({"pid": 1234, "comm": "wget", "uid": 0, "dst_ip": "45.1.1.1", "dst_port": 80}),
        );
        g.ingest(&event);

        assert!(g.find_by_pid(1234).is_some());
        assert!(g.find_by_ip("45.1.1.1").is_some());
        assert_eq!(g.edge_count(), 1); // ConnectedTo
    }

    #[test]
    fn test_ingest_dns_query() {
        let mut g = KnowledgeGraph::new();
        let event = make_event(
            "dns.query",
            serde_json::json!({"pid": 100, "domain": "evil.com", "query_type": "A"}),
        );
        g.ingest(&event);

        assert!(g.find_by_domain("evil.com").is_some());
        assert_eq!(g.edge_count(), 1); // Resolved
    }

    #[test]
    fn test_ingest_file_extracted() {
        let mut g = KnowledgeGraph::new();
        let event = make_event(
            "file.extracted_from_network",
            serde_json::json!({"filename": "/tmp/payload", "source_ip": "45.1.1.1", "size": 2400000, "entropy": 7.2}),
        );
        g.ingest(&event);

        let file_id = g.find_by_path("/tmp/payload").unwrap();
        match g.get_node(file_id) {
            Some(Node::File { entropy, size, .. }) => {
                assert_eq!(*entropy, Some(7.2));
                assert_eq!(*size, Some(2400000));
            }
            _ => panic!("expected File node"),
        }
        assert_eq!(g.edge_count(), 1); // DownloadedFrom
    }

    #[test]
    fn test_ingest_container_lifecycle() {
        let mut g = KnowledgeGraph::new();

        let start = make_event(
            "container.start",
            serde_json::json!({"container_id": "abc123", "name": "web", "image": "nginx:latest"}),
        );
        g.ingest(&start);

        let cont_id = g.find_by_container("abc123").unwrap();
        match g.get_node(cont_id) {
            Some(Node::Container { name, image, .. }) => {
                assert_eq!(name.as_deref(), Some("web"));
                assert_eq!(image.as_deref(), Some("nginx:latest"));
            }
            _ => panic!("expected Container"),
        }

        let die = make_event("container.die", serde_json::json!({"container_id": "abc123"}));
        g.ingest(&die);

        match g.get_node(cont_id) {
            Some(Node::Container { exit_ts, .. }) => assert!(exit_ts.is_some()),
            _ => panic!("expected Container"),
        }
    }

    #[test]
    fn test_ingest_firmware_msr() {
        let mut g = KnowledgeGraph::new();
        let event = make_event(
            "firmware.msr_write",
            serde_json::json!({"pid": 1, "msr_number": 130u32, "value": 57005u64}),
        );
        g.ingest(&event);

        assert!(g.system_node().is_some());
        assert!(g.find_by_pid(1).is_some());
        assert_eq!(g.edge_count(), 1); // WroteMsr
    }

    #[test]
    fn test_ingest_usb() {
        let mut g = KnowledgeGraph::new();
        let event = make_event(
            "hardware.usb_inserted",
            serde_json::json!({"vendor": "SanDisk", "product": "USB Drive", "serial": "ABC123"}),
        );
        g.ingest(&event);

        assert!(g.system_node().is_some());
        assert_eq!(g.edge_count(), 1); // InsertedOn
    }

    #[test]
    fn test_ingest_incident() {
        let mut g = KnowledgeGraph::new();
        let incident = Incident {
            ts: Utc::now(),
            host: "prod-01".to_string(),
            incident_id: "ssh_bruteforce:185.1.1.1:123".to_string(),
            severity: Severity::High,
            title: "SSH Brute Force".to_string(),
            summary: "Multiple failed logins".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: Vec::new(),
            tags: vec!["T1110.001".to_string()],
            entities: vec![
                EntityRef::ip("185.1.1.1"),
                EntityRef::user("root"),
            ],
        };
        g.ingest_incident(&incident);

        assert!(g.find_by_incident("ssh_bruteforce:185.1.1.1:123").is_some());
        assert!(g.find_by_ip("185.1.1.1").is_some());
        assert!(g.find_by_user("root").is_some());
        // TriggeredBy edges to ip and user
        assert_eq!(g.edge_count(), 2);
    }

    #[test]
    fn test_full_attack_scenario() {
        let mut g = KnowledgeGraph::new();

        // 1. SSH brute force (3 failures + 1 success)
        for i in 0..3 {
            let event = Event {
                ts: Utc.with_ymd_and_hms(2026, 4, 9, 14, 0, i).unwrap(),
                host: "prod-01".into(),
                source: "auth.log".into(),
                kind: "ssh.login_failed".into(),
                severity: Severity::Low,
                summary: String::new(),
                details: serde_json::json!({"ip": "185.220.101.42", "user": "root", "reason": "invalid password", "method": "password"}),
                tags: vec![],
                entities: vec![],
            };
            g.ingest(&event);
        }

        let login_ok = Event {
            ts: Utc.with_ymd_and_hms(2026, 4, 9, 14, 0, 5).unwrap(),
            host: "prod-01".into(),
            source: "auth.log".into(),
            kind: "ssh.login_success".into(),
            severity: Severity::Medium,
            summary: String::new(),
            details: serde_json::json!({"ip": "185.220.101.42", "user": "root", "method": "password"}),
            tags: vec![],
            entities: vec![],
        };
        g.ingest(&login_ok);

        // 2. Shell spawn
        let bash = make_event(
            "shell.command_exec",
            serde_json::json!({"pid": 1234, "ppid": 800, "comm": "bash", "exe": "/bin/bash", "uid": 0}),
        );
        g.ingest(&bash);

        // 3. wget
        let wget = make_event(
            "shell.command_exec",
            serde_json::json!({"pid": 1235, "ppid": 1234, "comm": "wget", "exe": "/usr/bin/wget", "uid": 0}),
        );
        g.ingest(&wget);

        // 4. outbound connect
        let connect = make_event(
            "network.outbound_connect",
            serde_json::json!({"pid": 1235, "comm": "wget", "uid": 0, "dst_ip": "45.155.205.233", "dst_port": 80}),
        );
        g.ingest(&connect);

        // 5. payload downloaded
        let extract = make_event(
            "file.extracted_from_network",
            serde_json::json!({"filename": "/tmp/payload", "source_ip": "45.155.205.233", "size": 2400000, "entropy": 7.2}),
        );
        g.ingest(&extract);

        // 6. payload execution
        let exec_payload = make_event(
            "shell.command_exec",
            serde_json::json!({"pid": 1236, "ppid": 1234, "comm": "payload", "exe": "/tmp/payload", "uid": 0}),
        );
        g.ingest(&exec_payload);

        // 7. C2 callback
        let c2 = make_event(
            "network.outbound_connect",
            serde_json::json!({"pid": 1236, "comm": "payload", "uid": 0, "dst_ip": "93.184.216.34", "dst_port": 443}),
        );
        g.ingest(&c2);

        // 8. Persistence
        let cron = make_event(
            "file.write_access",
            serde_json::json!({"pid": 1236, "comm": "payload", "path": "/etc/cron.d/backdoor", "uid": 0}),
        );
        g.ingest(&cron);

        let ssh_key = make_event(
            "file.write_access",
            serde_json::json!({"pid": 1236, "comm": "payload", "path": "/root/.ssh/authorized_keys", "uid": 0}),
        );
        g.ingest(&ssh_key);

        // 9. Credential harvest
        let shadow = make_event(
            "file.read_access",
            serde_json::json!({"pid": 1236, "comm": "payload", "path": "/etc/shadow", "uid": 0}),
        );
        g.ingest(&shadow);

        // ── Assertions ──

        // Process tree
        let desc = g.descendants(1234); // bash children
        assert!(desc.len() >= 2); // wget(1235) + payload(1236)

        let anc = g.ancestors(1236); // payload ancestors
        assert!(anc.len() >= 1); // at least bash(1234)

        // Path exists from attacker IP to C2 IP
        let ip1 = g.find_by_ip("185.220.101.42").unwrap();
        let ip2 = g.find_by_ip("93.184.216.34").unwrap();
        let path = g.path_between(ip1, ip2, 10);
        assert!(path.is_some(), "path should exist from attacker to C2");

        // Sensitive files
        let shadow_id = g.find_by_path("/etc/shadow").unwrap();
        assert!(g.get_node(shadow_id).unwrap().is_sensitive_file());

        let cron_id = g.find_by_path("/etc/cron.d/backdoor").unwrap();
        assert!(g.get_node(cron_id).unwrap().is_sensitive_file());

        // Neighborhood of payload process
        let payload_id = g.find_by_pid(1236).unwrap();
        let sub = g.neighborhood(payload_id, 2);
        assert!(sub.nodes.len() >= 5); // payload + connected nodes + their connections
    }
}
