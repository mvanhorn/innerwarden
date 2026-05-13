//! VM detection probes — comprehensive scoring system.
//!
//! Each probe tests one specific VM indicator and returns a score (0-100)
//! with confidence. Scores are combined into a final verdict.
//! Inspired by VMAware's 94-technique approach but implemented for Linux
//! in Rust with real measurements.

use std::collections::HashSet;
use std::fs;
use std::path::Path;

/// Result of a single detection probe.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProbeResult {
    /// Probe identifier.
    pub id: &'static str,
    /// What this probe checks.
    pub description: &'static str,
    /// Score: 0 = no VM indicator, 100 = definitive VM indicator.
    pub score: u32,
    /// Confidence in this score (0.0-1.0).
    pub confidence: f64,
    /// Human-readable detail.
    pub detail: String,
    /// Detected VM brand (if identifiable).
    pub brand: Option<String>,
}

/// Run all detection probes and return results.
pub fn run_all_probes() -> Vec<ProbeResult> {
    let mut results = Vec::new();

    results.push(probe_dmi_product());
    results.push(probe_dmi_vendor());
    results.push(probe_dmi_chassis());
    results.push(probe_dmi_bios());
    results.push(probe_hypervisor_dir());
    results.push(probe_cpuinfo_hypervisor_flag());
    results.push(probe_systemd_detect_virt());
    results.push(probe_hwmon());
    results.push(probe_temperature());
    results.push(probe_mac_address());
    results.push(probe_device_tree());
    results.push(probe_pci_devices());
    results.push(probe_scsi());
    results.push(probe_kernel_modules());
    results.push(probe_dmesg());
    results.push(probe_proc_bus());
    results.push(probe_disk_model());
    results.push(probe_qemu_fw_cfg());
    results.push(probe_acpi_tables());
    results.push(probe_hostname());

    results
}

/// Compute final VM score from probe results.
/// Uses weighted combination: higher-confidence probes count more.
pub fn compute_verdict(probes: &[ProbeResult]) -> VmVerdict {
    if probes.is_empty() {
        return VmVerdict {
            is_vm: false,
            score: 0,
            brand: None,
            evidence_count: 0,
        };
    }

    // Weighted score: score * confidence.
    let total_weight: f64 = probes.iter().map(|p| p.confidence).sum();
    let weighted_score: f64 = probes.iter().map(|p| p.score as f64 * p.confidence).sum();
    let final_score = if total_weight > 0.0 {
        (weighted_score / total_weight) as u32
    } else {
        0
    };

    // Count probes that found VM indicators.
    let evidence_count = probes.iter().filter(|p| p.score >= 50).count();

    // Determine brand by most-voted.
    let mut brand_votes: std::collections::HashMap<&str, u32> = std::collections::HashMap::new();
    for p in probes {
        if let Some(ref b) = p.brand {
            *brand_votes.entry(b.as_str()).or_insert(0) += p.score;
        }
    }
    let brand = brand_votes
        .into_iter()
        .max_by_key(|(_, v)| *v)
        .map(|(b, _)| b.to_string());

    VmVerdict {
        is_vm: final_score >= 30 || evidence_count >= 3,
        score: final_score,
        brand,
        evidence_count,
    }
}

/// Final VM detection verdict.
#[derive(Debug, Clone, serde::Serialize)]
pub struct VmVerdict {
    pub is_vm: bool,
    pub score: u32,
    pub brand: Option<String>,
    pub evidence_count: usize,
}

// ── Individual probes ───────────────────────────────────────────────────

fn read_dmi(field: &str) -> Option<String> {
    let path = format!("/sys/class/dmi/id/{field}");
    fs::read_to_string(&path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

const VM_STRINGS: &[(&str, &str)] = &[
    ("qemu", "QEMU"),
    ("kvm", "KVM"),
    ("vmware", "VMware"),
    ("virtualbox", "VirtualBox"),
    ("vbox", "VirtualBox"),
    ("hyper-v", "Hyper-V"),
    ("microsoft", "Hyper-V"),
    ("xen", "Xen"),
    ("parallels", "Parallels"),
    ("bhyve", "bhyve"),
    ("bochs", "Bochs"),
    ("innotek", "VirtualBox"),
    ("amazon ec2", "AWS"),
    ("google compute", "Google Cloud"),
    ("digitalocean", "DigitalOcean"),
    ("oracle", "Oracle Cloud"),
    ("openstack", "OpenStack"),
    ("nutanix", "Nutanix"),
    ("hetzner", "Hetzner"),
    ("ovh", "OVH"),
    ("linode", "Linode"),
    ("vultr", "Vultr"),
];

fn match_vm_string(haystack: &str) -> Option<&'static str> {
    let lower = haystack.to_lowercase();
    VM_STRINGS
        .iter()
        .find(|(needle, _)| lower.contains(needle))
        .map(|(_, brand)| *brand)
}

/// DMI product name (most reliable single indicator).
fn probe_dmi_product() -> ProbeResult {
    probe_dmi_product_from_value(read_dmi("product_name").as_deref())
}

fn probe_dmi_product_from_value(value: Option<&str>) -> ProbeResult {
    match value {
        Some(val) => {
            if let Some(brand) = match_vm_string(val) {
                ProbeResult {
                    id: "dmi_product",
                    description: "DMI product name",
                    score: 95,
                    confidence: 0.95,
                    detail: format!("product_name='{val}' → {brand}"),
                    brand: Some(brand.into()),
                }
            } else {
                ProbeResult {
                    id: "dmi_product",
                    description: "DMI product name",
                    score: 0,
                    confidence: 0.7,
                    detail: format!("product_name='{val}' — no VM match"),
                    brand: None,
                }
            }
        }
        None => ProbeResult {
            id: "dmi_product",
            description: "DMI product name",
            score: 0,
            confidence: 0.3,
            detail: "DMI not available".into(),
            brand: None,
        },
    }
}

/// DMI sys vendor.
fn probe_dmi_vendor() -> ProbeResult {
    probe_dmi_vendor_from_value(read_dmi("sys_vendor").as_deref())
}

fn probe_dmi_vendor_from_value(value: Option<&str>) -> ProbeResult {
    match value {
        Some(val) => {
            let brand = match_vm_string(val);
            ProbeResult {
                id: "dmi_vendor",
                description: "DMI system vendor",
                score: if brand.is_some() { 90 } else { 0 },
                confidence: 0.9,
                detail: format!("sys_vendor='{val}'"),
                brand: brand.map(Into::into),
            }
        }
        None => ProbeResult {
            id: "dmi_vendor",
            description: "DMI system vendor",
            score: 0,
            confidence: 0.3,
            detail: "not available".into(),
            brand: None,
        },
    }
}

/// DMI chassis type (1=Other, 2=Unknown typical for VMs).
fn probe_dmi_chassis() -> ProbeResult {
    probe_dmi_chassis_from_value(read_dmi("chassis_type").as_deref())
}

fn probe_dmi_chassis_from_value(value: Option<&str>) -> ProbeResult {
    match value {
        Some(val) => {
            let chassis_type: u32 = val.parse().unwrap_or(0);
            // 1=Other, 2=Unknown — common VM chassis types.
            let is_vm_chassis = chassis_type == 1 || chassis_type == 2;
            ProbeResult {
                id: "dmi_chassis",
                description: "DMI chassis type",
                score: if is_vm_chassis { 50 } else { 0 },
                confidence: 0.6,
                detail: format!(
                    "chassis_type={chassis_type} ({})",
                    if is_vm_chassis {
                        "Other/Unknown — common in VMs"
                    } else {
                        "physical chassis"
                    }
                ),
                brand: None,
            }
        }
        None => ProbeResult {
            id: "dmi_chassis",
            description: "DMI chassis type",
            score: 0,
            confidence: 0.2,
            detail: "not available".into(),
            brand: None,
        },
    }
}

/// DMI BIOS vendor.
fn probe_dmi_bios() -> ProbeResult {
    probe_dmi_bios_from_value(read_dmi("bios_vendor").as_deref())
}

fn probe_dmi_bios_from_value(value: Option<&str>) -> ProbeResult {
    match value {
        Some(val) => {
            let brand = match_vm_string(val);
            // OVMF/SeaBIOS = QEMU/KVM.
            let bios_brand = brand.or_else(|| {
                let l = val.to_lowercase();
                if l.contains("edk ii") || l.contains("ovmf") || l.contains("seabios") {
                    Some("QEMU/KVM")
                } else {
                    None
                }
            });
            ProbeResult {
                id: "dmi_bios",
                description: "DMI BIOS vendor",
                score: if bios_brand.is_some() { 85 } else { 0 },
                confidence: 0.85,
                detail: format!("bios_vendor='{val}'"),
                brand: bios_brand.map(Into::into),
            }
        }
        None => ProbeResult {
            id: "dmi_bios",
            description: "DMI BIOS vendor",
            score: 0,
            confidence: 0.2,
            detail: "not available".into(),
            brand: None,
        },
    }
}

/// /sys/hypervisor directory presence.
fn probe_hypervisor_dir() -> ProbeResult {
    let exists = Path::new("/sys/hypervisor").exists();
    let hv_type = fs::read_to_string("/sys/hypervisor/type")
        .ok()
        .map(|s| s.trim().to_string());
    probe_hypervisor_dir_from_parts(exists, hv_type.as_deref())
}

fn probe_hypervisor_dir_from_parts(exists: bool, hv_type: Option<&str>) -> ProbeResult {
    if exists {
        ProbeResult {
            id: "hypervisor_dir",
            description: "/sys/hypervisor presence",
            score: 100,
            confidence: 0.99,
            detail: format!("/sys/hypervisor exists. type={:?}", hv_type),
            brand: hv_type.and_then(match_vm_string).map(Into::into),
        }
    } else {
        ProbeResult {
            id: "hypervisor_dir",
            description: "/sys/hypervisor presence",
            score: 0,
            confidence: 0.5,
            detail: "/sys/hypervisor not found".into(),
            brand: None,
        }
    }
}

/// /proc/cpuinfo hypervisor flag.
fn probe_cpuinfo_hypervisor_flag() -> ProbeResult {
    let cpuinfo = fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    probe_cpuinfo_hypervisor_flag_from(&cpuinfo)
}

fn probe_cpuinfo_hypervisor_flag_from(cpuinfo: &str) -> ProbeResult {
    let has_flag = cpuinfo.split_whitespace().any(|w| w == "hypervisor");
    ProbeResult {
        id: "cpuinfo_flag",
        description: "CPUID hypervisor flag in /proc/cpuinfo",
        score: if has_flag { 100 } else { 0 },
        confidence: if has_flag { 0.99 } else { 0.7 },
        detail: if has_flag {
            "hypervisor flag PRESENT in CPU flags".into()
        } else {
            "hypervisor flag absent".into()
        },
        brand: None,
    }
}

/// systemd-detect-virt output.
fn probe_systemd_detect_virt() -> ProbeResult {
    match std::process::Command::new("systemd-detect-virt").output() {
        Ok(out) if out.status.success() => {
            let virt = String::from_utf8_lossy(&out.stdout).trim().to_string();
            probe_systemd_detect_virt_from_value(Some(&virt))
        }
        _ => probe_systemd_detect_virt_from_value(None),
    }
}

fn probe_systemd_detect_virt_from_value(value: Option<&str>) -> ProbeResult {
    match value {
        Some("none") => ProbeResult {
            id: "systemd_virt",
            description: "systemd-detect-virt",
            score: 0,
            confidence: 0.9,
            detail: "systemd-detect-virt: none".into(),
            brand: None,
        },
        Some(virt) => ProbeResult {
            id: "systemd_virt",
            description: "systemd-detect-virt",
            score: 100,
            confidence: 0.95,
            detail: format!("systemd-detect-virt: {virt}"),
            brand: match_vm_string(virt).map(Into::into),
        },
        None => ProbeResult {
            id: "systemd_virt",
            description: "systemd-detect-virt",
            score: 0,
            confidence: 0.1,
            detail: "systemd-detect-virt not available".into(),
            brand: None,
        },
    }
}

/// /sys/class/hwmon absence (VMs rarely expose hardware monitors).
fn probe_hwmon() -> ProbeResult {
    let hwmon_dir = Path::new("/sys/class/hwmon");
    let count = if hwmon_dir.exists() {
        fs::read_dir(hwmon_dir).map(|d| d.count()).unwrap_or(0)
    } else {
        0
    };
    probe_hwmon_from_count(count)
}

fn probe_hwmon_from_count(count: usize) -> ProbeResult {
    ProbeResult {
        id: "hwmon",
        description: "hardware monitoring sensors",
        score: if count == 0 { 40 } else { 0 },
        confidence: 0.5,
        detail: format!("{count} hwmon device(s) — VMs typically have 0"),
        brand: None,
    }
}

/// Temperature sensor absence.
fn probe_temperature() -> ProbeResult {
    let thermal_dir = Path::new("/sys/class/thermal");
    let has_thermal = thermal_dir.exists()
        && fs::read_dir(thermal_dir)
            .map(|d| d.count() > 0)
            .unwrap_or(false);
    probe_temperature_from_presence(has_thermal)
}

fn probe_temperature_from_presence(has_thermal: bool) -> ProbeResult {
    ProbeResult {
        id: "temperature",
        description: "thermal sensors presence",
        score: if has_thermal { 0 } else { 30 },
        confidence: 0.4,
        detail: if has_thermal {
            "thermal zones present".into()
        } else {
            "no thermal zones — common in VMs".into()
        },
        brand: None,
    }
}

/// MAC address vendor prefix check.
fn probe_mac_address() -> ProbeResult {
    let mut macs = Vec::new();
    if let Ok(entries) = fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let addr_path = entry.path().join("address");
            if let Ok(mac) = fs::read_to_string(&addr_path) {
                macs.push(mac);
            }
        }
    }
    probe_mac_address_from_macs(macs.iter().map(String::as_str))
}

fn probe_mac_address_from_macs<'a, I>(macs: I) -> ProbeResult
where
    I: IntoIterator<Item = &'a str>,
{
    let vm_mac_prefixes: &[(&str, &str)] = &[
        ("00:0c:29", "VMware"),
        ("00:50:56", "VMware"),
        ("00:05:69", "VMware"),
        ("00:1c:14", "VMware"),
        ("08:00:27", "VirtualBox"),
        ("0a:00:27", "VirtualBox"),
        ("52:54:00", "QEMU/KVM"),
        ("00:16:3e", "Xen"),
        ("00:15:5d", "Hyper-V"),
        ("00:1a:4a", "KVM"),
        ("02:42:", "Docker"),
    ];

    let mut found = Vec::new();
    for mac in macs {
        let mac = mac.trim().to_lowercase();
        for (prefix, brand) in vm_mac_prefixes {
            if mac.starts_with(prefix) {
                found.push((*brand, mac.clone()));
            }
        }
    }

    if !found.is_empty() {
        let brand = found[0].0;
        ProbeResult {
            id: "mac_address",
            description: "MAC address vendor prefix",
            score: 80,
            confidence: 0.85,
            detail: format!(
                "VM MAC prefix: {} ({})",
                found
                    .iter()
                    .map(|(b, m)| format!("{b}: {m}"))
                    .collect::<Vec<_>>()
                    .join(", "),
                brand,
            ),
            brand: Some(brand.into()),
        }
    } else {
        ProbeResult {
            id: "mac_address",
            description: "MAC address vendor prefix",
            score: 0,
            confidence: 0.7,
            detail: "no VM MAC prefixes found".into(),
            brand: None,
        }
    }
}

/// Device tree (ARM-specific VM detection).
fn probe_device_tree() -> ProbeResult {
    let dt_model = fs::read_to_string("/proc/device-tree/model")
        .or_else(|_| fs::read_to_string("/sys/firmware/devicetree/base/model"))
        .ok()
        .map(|s| s.trim_end_matches('\0').trim().to_string());
    probe_device_tree_from_model(dt_model.as_deref())
}

fn probe_device_tree_from_model(model: Option<&str>) -> ProbeResult {
    match model {
        Some(model) => {
            let brand = match_vm_string(model);
            ProbeResult {
                id: "device_tree",
                description: "device tree model",
                score: if brand.is_some() { 90 } else { 0 },
                confidence: 0.85,
                detail: format!("device-tree model='{model}'"),
                brand: brand.map(Into::into),
            }
        }
        None => ProbeResult {
            id: "device_tree",
            description: "device tree model",
            score: 0,
            confidence: 0.2,
            detail: "no device tree".into(),
            brand: None,
        },
    }
}

/// PCI device IDs check for known VM vendors.
fn probe_pci_devices() -> ProbeResult {
    let pci_path = Path::new("/sys/bus/pci/devices");
    if !pci_path.exists() {
        return ProbeResult {
            id: "pci_devices",
            description: "PCI device vendor IDs",
            score: 0,
            confidence: 0.2,
            detail: "no PCI bus".into(),
            brand: None,
        };
    }

    // Known VM PCI vendor IDs.
    let vm_vendors: &[(&str, &str)] = &[
        ("0x1af4", "virtio (KVM/QEMU)"),
        ("0x1b36", "QEMU"),
        ("0x15ad", "VMware"),
        ("0x80ee", "VirtualBox"),
        ("0x1414", "Hyper-V"),
        ("0x5853", "Xen"),
    ];

    let mut vendors = Vec::new();
    if let Ok(entries) = fs::read_dir(pci_path) {
        for entry in entries.flatten() {
            let vendor = fs::read_to_string(entry.path().join("vendor"))
                .unwrap_or_default()
                .trim()
                .to_string();
            vendors.push(vendor);
        }
    }
    probe_pci_devices_from_vendor_ids(vendors.iter().map(String::as_str), vm_vendors)
}

fn probe_pci_devices_from_vendor_ids<'a, I>(vendors: I, vm_vendors: &[(&str, &str)]) -> ProbeResult
where
    I: IntoIterator<Item = &'a str>,
{
    let mut found = Vec::new();
    for vendor in vendors {
        for (vid, name) in vm_vendors {
            if vendor == *vid {
                found.push(*name);
            }
        }
    }

    let unique: HashSet<&&str> = found.iter().collect();
    if !unique.is_empty() {
        let names: Vec<&str> = unique.into_iter().copied().collect();
        ProbeResult {
            id: "pci_devices",
            description: "PCI device vendor IDs",
            score: 90,
            confidence: 0.95,
            detail: format!("VM PCI devices: {}", names.join(", ")),
            brand: match_vm_string(names[0]).map(Into::into),
        }
    } else {
        ProbeResult {
            id: "pci_devices",
            description: "PCI device vendor IDs",
            score: 0,
            confidence: 0.7,
            detail: "no VM PCI vendor IDs found".into(),
            brand: None,
        }
    }
}

/// SCSI devices check.
fn probe_scsi() -> ProbeResult {
    let scsi = fs::read_to_string("/proc/scsi/scsi").unwrap_or_default();
    probe_scsi_from_content(&scsi)
}

fn probe_scsi_from_content(scsi: &str) -> ProbeResult {
    let brand = match_vm_string(scsi);
    ProbeResult {
        id: "scsi",
        description: "SCSI device strings",
        score: if brand.is_some() { 85 } else { 0 },
        confidence: if brand.is_some() { 0.85 } else { 0.3 },
        detail: if let Some(b) = &brand {
            format!("SCSI contains VM string: {b}")
        } else {
            "no VM SCSI strings".into()
        },
        brand: brand.map(Into::into),
    }
}

/// Kernel modules check.
fn probe_kernel_modules() -> ProbeResult {
    let modules = fs::read_to_string("/proc/modules").unwrap_or_default();
    probe_kernel_modules_from_content(&modules)
}

fn probe_kernel_modules_from_content(modules: &str) -> ProbeResult {
    let vm_modules: &[(&str, &str)] = &[
        ("kvm", "KVM (host)"),
        ("vboxguest", "VirtualBox"),
        ("vboxsf", "VirtualBox"),
        ("vmw_", "VMware"),
        ("vmxnet", "VMware"),
        ("hv_vmbus", "Hyper-V"),
        ("xen_", "Xen"),
        ("virtio", "KVM/QEMU"),
    ];

    let mut found = Vec::new();
    for line in modules.lines() {
        let name = line.split_whitespace().next().unwrap_or("");
        for (prefix, brand) in vm_modules {
            if name.starts_with(prefix) {
                found.push((*brand, name.to_string()));
            }
        }
    }

    if !found.is_empty() {
        let brand = found[0].0;
        ProbeResult {
            id: "kernel_modules",
            description: "VM-specific kernel modules",
            score: 85,
            confidence: 0.9,
            detail: format!(
                "VM modules: {}",
                found
                    .iter()
                    .map(|(b, m)| format!("{m} ({b})"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            brand: Some(brand.into()),
        }
    } else {
        ProbeResult {
            id: "kernel_modules",
            description: "VM-specific kernel modules",
            score: 0,
            confidence: 0.6,
            detail: "no VM kernel modules".into(),
            brand: None,
        }
    }
}

/// Kernel log (dmesg) check.
fn probe_dmesg() -> ProbeResult {
    let dmesg = fs::read_to_string("/var/log/dmesg")
        .or_else(|_| fs::read_to_string("/var/log/kern.log"))
        .unwrap_or_default();
    probe_dmesg_from_content(&dmesg)
}

fn probe_dmesg_from_content(dmesg: &str) -> ProbeResult {
    let brand = match_vm_string(dmesg);
    ProbeResult {
        id: "dmesg",
        description: "kernel log VM strings",
        score: if brand.is_some() { 70 } else { 0 },
        confidence: if brand.is_some() { 0.7 } else { 0.3 },
        detail: if let Some(b) = &brand {
            format!("dmesg contains: {b}")
        } else {
            "no VM strings in kernel log".into()
        },
        brand: brand.map(Into::into),
    }
}

/// /proc/bus/pci existence check (ARM VMs often lack PCI).
fn probe_proc_bus() -> ProbeResult {
    let has_pci = Path::new("/proc/bus/pci").exists();
    probe_proc_bus_from_presence(has_pci)
}

fn probe_proc_bus_from_presence(has_pci: bool) -> ProbeResult {
    // Not having PCI isn't itself VM evidence on ARM.
    ProbeResult {
        id: "proc_bus",
        description: "/proc/bus/pci presence",
        score: 0,
        confidence: 0.2,
        detail: if has_pci {
            "PCI bus present".into()
        } else {
            "no PCI bus (normal on ARM)".into()
        },
        brand: None,
    }
}

/// Disk model check for VM strings.
fn probe_disk_model() -> ProbeResult {
    let block_dir = Path::new("/sys/block");
    if !block_dir.exists() {
        return probe_disk_model_from_models(None::<std::iter::Empty<&str>>, false);
    }

    let mut models = Vec::new();
    if let Ok(entries) = fs::read_dir(block_dir) {
        for entry in entries.flatten() {
            let model = fs::read_to_string(entry.path().join("device/model"))
                .unwrap_or_default()
                .trim()
                .to_string();
            if !model.is_empty() {
                models.push(model);
            }
        }
    }
    probe_disk_model_from_models(Some(models.iter().map(String::as_str)), true)
}

fn probe_disk_model_from_models<'a, I>(models: Option<I>, block_dir_exists: bool) -> ProbeResult
where
    I: IntoIterator<Item = &'a str>,
{
    if !block_dir_exists {
        return ProbeResult {
            id: "disk_model",
            description: "disk model strings",
            score: 0,
            confidence: 0.2,
            detail: "no block devices".into(),
            brand: None,
        };
    }

    let found_brand = models.and_then(|models| {
        models
            .into_iter()
            .find_map(|model| match_vm_string(model).map(|brand| (brand, model.to_string())))
    });

    match found_brand {
        Some((brand, model)) => ProbeResult {
            id: "disk_model",
            description: "disk model strings",
            score: 80,
            confidence: 0.8,
            detail: format!("disk model='{model}' → {brand}"),
            brand: Some(brand.into()),
        },
        None => ProbeResult {
            id: "disk_model",
            description: "disk model strings",
            score: 0,
            confidence: 0.5,
            detail: "no VM disk models".into(),
            brand: None,
        },
    }
}

/// QEMU fw_cfg interface.
fn probe_qemu_fw_cfg() -> ProbeResult {
    let exists = Path::new("/sys/firmware/qemu_fw_cfg").exists();
    probe_qemu_fw_cfg_from_presence(exists)
}

fn probe_qemu_fw_cfg_from_presence(exists: bool) -> ProbeResult {
    ProbeResult {
        id: "qemu_fw_cfg",
        description: "QEMU fw_cfg interface",
        score: if exists { 100 } else { 0 },
        confidence: if exists { 0.99 } else { 0.4 },
        detail: if exists {
            "QEMU fw_cfg present — definitive QEMU/KVM".into()
        } else {
            "no QEMU fw_cfg".into()
        },
        brand: if exists {
            Some("QEMU/KVM".into())
        } else {
            None
        },
    }
}

/// ACPI table signatures.
fn probe_acpi_tables() -> ProbeResult {
    let acpi_dir = Path::new("/sys/firmware/acpi/tables");
    if !acpi_dir.exists() {
        return probe_acpi_tables_from_match(None, false);
    }

    // Read first bytes of ACPI tables for VM signatures.
    let mut found_brand = None;
    if let Ok(entries) = fs::read_dir(acpi_dir) {
        for entry in entries.flatten() {
            if let Ok(data) = fs::read(entry.path()) {
                if let Some(match_) =
                    acpi_table_vm_signature(&entry.file_name().to_string_lossy(), &data)
                {
                    found_brand = Some(match_);
                    break;
                }
            }
        }
    }
    probe_acpi_tables_from_match(found_brand, true)
}

fn acpi_table_vm_signature(table_name: &str, data: &[u8]) -> Option<(&'static str, String)> {
    // Check OEM ID field in ACPI header (offset 10-15, 6 bytes).
    if data.len() > 16 {
        let oem = String::from_utf8_lossy(&data[10..16]);
        if let Some(brand) = match_vm_string(&oem) {
            return Some((brand, format!("{table_name} OEM={}", oem.trim())));
        }
    }

    let text = String::from_utf8_lossy(&data[..data.len().min(256)]);
    if let Some(brand) = match_vm_string(&text) {
        return Some((brand, table_name.to_string()));
    }

    None
}

fn probe_acpi_tables_from_match(
    found_brand: Option<(&'static str, String)>,
    acpi_dir_exists: bool,
) -> ProbeResult {
    if !acpi_dir_exists {
        return ProbeResult {
            id: "acpi_tables",
            description: "ACPI table signatures",
            score: 0,
            confidence: 0.2,
            detail: "no ACPI tables".into(),
            brand: None,
        };
    }

    match found_brand {
        Some((brand, table)) => ProbeResult {
            id: "acpi_tables",
            description: "ACPI table signatures",
            score: 75,
            confidence: 0.8,
            detail: format!("ACPI table '{table}' contains: {brand}"),
            brand: Some(brand.into()),
        },
        None => ProbeResult {
            id: "acpi_tables",
            description: "ACPI table signatures",
            score: 0,
            confidence: 0.5,
            detail: "no VM signatures in ACPI tables".into(),
            brand: None,
        },
    }
}

/// Default VM hostname patterns.
fn probe_hostname() -> ProbeResult {
    let hostname = fs::read_to_string("/etc/hostname")
        .unwrap_or_default()
        .trim()
        .to_string();
    probe_hostname_from_value(&hostname)
}

fn probe_hostname_from_value(hostname: &str) -> ProbeResult {
    // Known default VM hostnames.
    let vm_hostnames = ["localhost", "ubuntu", "debian", "centos", "instance-"];
    let is_default = vm_hostnames.iter().any(|h| hostname.starts_with(h));
    ProbeResult {
        id: "hostname",
        description: "default VM hostname",
        score: if is_default { 20 } else { 0 },
        confidence: 0.3,
        detail: format!("hostname='{hostname}'"),
        brand: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_probes_run() {
        let results = run_all_probes();
        assert!(!results.is_empty());
        // Each probe should have an id.
        for r in &results {
            assert!(!r.id.is_empty());
        }
    }

    #[test]
    fn verdict_from_empty() {
        let verdict = compute_verdict(&[]);
        assert!(!verdict.is_vm);
    }

    #[test]
    fn match_vm_strings() {
        assert_eq!(match_vm_string("KVM Virtual Machine"), Some("KVM"));
        assert_eq!(match_vm_string("VMware, Inc."), Some("VMware"));
        assert_eq!(match_vm_string("Dell PowerEdge"), None);
    }

    #[test]
    fn high_score_means_vm() {
        let probes = vec![
            ProbeResult {
                id: "test1",
                description: "test",
                score: 100,
                confidence: 0.99,
                detail: "definite".into(),
                brand: Some("KVM".into()),
            },
            ProbeResult {
                id: "test2",
                description: "test",
                score: 90,
                confidence: 0.9,
                detail: "strong".into(),
                brand: Some("KVM".into()),
            },
        ];
        let v = compute_verdict(&probes);
        assert!(v.is_vm);
        assert!(v.score > 80);
        assert_eq!(v.brand, Some("KVM".into()));
    }

    #[test]
    fn verdict_can_be_vm_from_three_medium_evidence_probes() {
        let probes = vec![
            ProbeResult {
                id: "a",
                description: "a",
                score: 50,
                confidence: 0.5,
                detail: "a".into(),
                brand: None,
            },
            ProbeResult {
                id: "b",
                description: "b",
                score: 50,
                confidence: 0.5,
                detail: "b".into(),
                brand: None,
            },
            ProbeResult {
                id: "c",
                description: "c",
                score: 50,
                confidence: 0.5,
                detail: "c".into(),
                brand: None,
            },
        ];
        let verdict = compute_verdict(&probes);
        assert!(verdict.is_vm);
        assert_eq!(verdict.evidence_count, 3);
    }

    #[test]
    fn verdict_handles_zero_confidence_without_dividing_by_zero() {
        let verdict = compute_verdict(&[ProbeResult {
            id: "zero",
            description: "zero",
            score: 100,
            confidence: 0.0,
            detail: "ignored".into(),
            brand: Some("KVM".into()),
        }]);
        assert_eq!(verdict.score, 0);
        assert_eq!(verdict.brand, Some("KVM".into()));
    }

    #[test]
    fn dmi_chassis_probe_classifies_vm_and_physical_values() {
        let other = probe_dmi_chassis_from_value(Some("1"));
        assert_eq!(other.score, 50);
        assert!(other.detail.contains("common in VMs"));

        let physical = probe_dmi_chassis_from_value(Some("3"));
        assert_eq!(physical.score, 0);
        assert!(physical.detail.contains("physical chassis"));

        let unavailable = probe_dmi_chassis_from_value(None);
        assert_eq!(unavailable.confidence, 0.2);
    }

    #[test]
    fn dmi_product_vendor_and_bios_helpers_classify_known_vm_strings() {
        let product = probe_dmi_product_from_value(Some("KVM Virtual Machine"));
        assert_eq!(product.score, 95);
        assert_eq!(product.brand, Some("KVM".into()));

        let physical_product = probe_dmi_product_from_value(Some("Dell PowerEdge"));
        assert_eq!(physical_product.score, 0);
        assert!(physical_product.detail.contains("no VM match"));

        let missing_product = probe_dmi_product_from_value(None);
        assert_eq!(missing_product.confidence, 0.3);

        let vendor = probe_dmi_vendor_from_value(Some("VMware, Inc."));
        assert_eq!(vendor.score, 90);
        assert_eq!(vendor.brand, Some("VMware".into()));

        let physical_vendor = probe_dmi_vendor_from_value(Some("Framework"));
        assert_eq!(physical_vendor.score, 0);
        assert!(physical_vendor.brand.is_none());

        let missing_vendor = probe_dmi_vendor_from_value(None);
        assert_eq!(missing_vendor.detail, "not available");

        let bios = probe_dmi_bios_from_value(Some("EDK II OVMF"));
        assert_eq!(bios.score, 85);
        assert_eq!(bios.brand, Some("QEMU/KVM".into()));

        let physical_bios = probe_dmi_bios_from_value(Some("American Megatrends"));
        assert_eq!(physical_bios.score, 0);

        let missing_bios = probe_dmi_bios_from_value(None);
        assert_eq!(missing_bios.confidence, 0.2);
    }

    #[test]
    fn hypervisor_dir_helper_reports_presence_type_and_absence() {
        let present = probe_hypervisor_dir_from_parts(true, Some("kvm"));
        assert_eq!(present.score, 100);
        assert_eq!(present.brand, Some("KVM".into()));
        assert!(present.detail.contains("Some(\"kvm\")"));

        let present_unknown = probe_hypervisor_dir_from_parts(true, None);
        assert_eq!(present_unknown.score, 100);
        assert!(present_unknown.brand.is_none());

        let absent = probe_hypervisor_dir_from_parts(false, Some("kvm"));
        assert_eq!(absent.score, 0);
        assert_eq!(absent.detail, "/sys/hypervisor not found");
    }

    #[test]
    fn cpuinfo_hypervisor_flag_probe_requires_exact_flag_token() {
        let present = probe_cpuinfo_hypervisor_flag_from("flags : fpu hypervisor smep");
        assert_eq!(present.score, 100);
        assert!(present.detail.contains("PRESENT"));

        let absent = probe_cpuinfo_hypervisor_flag_from("flags : fpu nothypervisor smep");
        assert_eq!(absent.score, 0);
        assert!(absent.detail.contains("absent"));
    }

    #[test]
    fn systemd_detect_virt_probe_distinguishes_none_vm_and_unavailable() {
        let none = probe_systemd_detect_virt_from_value(Some("none"));
        assert_eq!(none.score, 0);
        assert_eq!(none.confidence, 0.9);

        let kvm = probe_systemd_detect_virt_from_value(Some("kvm"));
        assert_eq!(kvm.score, 100);
        assert_eq!(kvm.brand, Some("KVM".into()));

        let unavailable = probe_systemd_detect_virt_from_value(None);
        assert_eq!(unavailable.confidence, 0.1);
    }

    #[test]
    fn hwmon_and_temperature_probe_score_absence_as_weak_vm_signal() {
        let no_hwmon = probe_hwmon_from_count(0);
        assert_eq!(no_hwmon.score, 40);
        assert!(no_hwmon.detail.contains("0 hwmon"));

        let has_hwmon = probe_hwmon_from_count(2);
        assert_eq!(has_hwmon.score, 0);

        let no_thermal = probe_temperature_from_presence(false);
        assert_eq!(no_thermal.score, 30);

        let has_thermal = probe_temperature_from_presence(true);
        assert_eq!(has_thermal.score, 0);
    }

    #[test]
    fn device_tree_helper_scores_vm_physical_and_missing_models() {
        let vm = probe_device_tree_from_model(Some("qemu,virt"));
        assert_eq!(vm.score, 90);
        assert_eq!(vm.brand, Some("QEMU".into()));

        let physical = probe_device_tree_from_model(Some("Raspberry Pi 5"));
        assert_eq!(physical.score, 0);
        assert!(physical.brand.is_none());

        let missing = probe_device_tree_from_model(None);
        assert_eq!(missing.confidence, 0.2);
    }

    #[test]
    fn mac_address_probe_reports_first_vm_brand_and_all_matching_macs() {
        let result = probe_mac_address_from_macs([
            "52:54:00:12:34:56\n",
            "00:0c:29:aa:bb:cc\n",
            "de:ad:be:ef:00:01\n",
        ]);
        assert_eq!(result.score, 80);
        assert_eq!(result.brand, Some("QEMU/KVM".into()));
        assert!(result.detail.contains("QEMU/KVM: 52:54:00:12:34:56"));
        assert!(result.detail.contains("VMware: 00:0c:29:aa:bb:cc"));
    }

    #[test]
    fn mac_address_probe_reports_no_match_for_physical_prefixes() {
        let result = probe_mac_address_from_macs(["de:ad:be:ef:00:01"]);
        assert_eq!(result.score, 0);
        assert!(result.brand.is_none());
    }

    #[test]
    fn pci_vendor_probe_deduplicates_vm_vendor_names() {
        let vm_vendors = &[("0x1af4", "virtio (KVM/QEMU)"), ("0x15ad", "VMware")];
        let result = probe_pci_devices_from_vendor_ids(["0x1af4", "0x1af4", "0x15ad"], vm_vendors);
        assert_eq!(result.score, 90);
        assert!(result.detail.contains("virtio (KVM/QEMU)"));
        assert!(result.detail.contains("VMware"));
    }

    #[test]
    fn pci_vendor_probe_reports_no_match_for_unknown_vendors() {
        let result = probe_pci_devices_from_vendor_ids(["0x8086"], &[("0x1af4", "virtio")]);
        assert_eq!(result.score, 0);
        assert_eq!(result.detail, "no VM PCI vendor IDs found");
    }

    #[test]
    fn scsi_and_dmesg_helpers_detect_vm_strings_and_absence() {
        let scsi = probe_scsi_from_content("Vendor: QEMU Model: QEMU HARDDISK");
        assert_eq!(scsi.score, 85);
        assert_eq!(scsi.brand, Some("QEMU".into()));

        let scsi_absent = probe_scsi_from_content("Vendor: ATA Model: Samsung SSD");
        assert_eq!(scsi_absent.score, 0);
        assert_eq!(scsi_absent.detail, "no VM SCSI strings");

        let dmesg = probe_dmesg_from_content("Hypervisor detected: VMware");
        assert_eq!(dmesg.score, 70);
        assert_eq!(dmesg.brand, Some("VMware".into()));

        let dmesg_absent = probe_dmesg_from_content("Linux version booted cleanly");
        assert_eq!(dmesg_absent.score, 0);
        assert_eq!(dmesg_absent.detail, "no VM strings in kernel log");
    }

    #[test]
    fn kernel_modules_helper_reports_vm_modules_and_clean_hosts() {
        let modules = "kvm_intel 4096 0 - Live 0x0\nvboxguest 1 0 - Live 0x0\next4 1 0 - Live 0x0";
        let result = probe_kernel_modules_from_content(modules);
        assert_eq!(result.score, 85);
        assert_eq!(result.brand, Some("KVM (host)".into()));
        assert!(result.detail.contains("kvm_intel"));
        assert!(result.detail.contains("vboxguest"));

        let clean = probe_kernel_modules_from_content("ext4 1 0 - Live 0x0");
        assert_eq!(clean.score, 0);
        assert_eq!(clean.detail, "no VM kernel modules");
    }

    #[test]
    fn proc_bus_and_qemu_fw_cfg_helpers_cover_presence_branches() {
        let pci_present = probe_proc_bus_from_presence(true);
        assert_eq!(pci_present.detail, "PCI bus present");

        let pci_absent = probe_proc_bus_from_presence(false);
        assert_eq!(pci_absent.detail, "no PCI bus (normal on ARM)");

        let qemu_present = probe_qemu_fw_cfg_from_presence(true);
        assert_eq!(qemu_present.score, 100);
        assert_eq!(qemu_present.brand, Some("QEMU/KVM".into()));

        let qemu_absent = probe_qemu_fw_cfg_from_presence(false);
        assert_eq!(qemu_absent.score, 0);
        assert!(qemu_absent.brand.is_none());
    }

    #[test]
    fn disk_model_helper_detects_vm_models_clean_models_and_missing_block_dir() {
        let vm = probe_disk_model_from_models(Some(["Samsung SSD", "QEMU HARDDISK"]), true);
        assert_eq!(vm.score, 80);
        assert_eq!(vm.brand, Some("QEMU".into()));

        let clean = probe_disk_model_from_models(Some(["Samsung SSD"]), true);
        assert_eq!(clean.score, 0);
        assert_eq!(clean.detail, "no VM disk models");

        let missing = probe_disk_model_from_models(None::<std::iter::Empty<&str>>, false);
        assert_eq!(missing.confidence, 0.2);
        assert_eq!(missing.detail, "no block devices");
    }

    #[test]
    fn acpi_helpers_detect_text_oem_absence_and_missing_tables() {
        let text = acpi_table_vm_signature("DSDT", b"header VMware virtual platform");
        assert_eq!(text, Some(("VMware", "DSDT".into())));

        let mut oem_data = vec![b' '; 20];
        oem_data[10..16].copy_from_slice(b"BOCHS ");
        let oem = acpi_table_vm_signature("FACP", &oem_data);
        assert_eq!(oem, Some(("Bochs", "FACP OEM=BOCHS".into())));

        assert!(acpi_table_vm_signature("DSDT", b"plain physical acpi").is_none());

        let found = probe_acpi_tables_from_match(Some(("Xen", "XSDT".into())), true);
        assert_eq!(found.score, 75);
        assert_eq!(found.brand, Some("Xen".into()));

        let clean = probe_acpi_tables_from_match(None, true);
        assert_eq!(clean.confidence, 0.5);
        assert_eq!(clean.detail, "no VM signatures in ACPI tables");

        let missing = probe_acpi_tables_from_match(None, false);
        assert_eq!(missing.confidence, 0.2);
        assert_eq!(missing.detail, "no ACPI tables");
    }

    #[test]
    fn hostname_helper_scores_default_vm_names_weakly() {
        let default = probe_hostname_from_value("instance-123");
        assert_eq!(default.score, 20);

        let custom = probe_hostname_from_value("prod-db-01");
        assert_eq!(custom.score, 0);
        assert_eq!(custom.detail, "hostname='prod-db-01'");
    }
}
