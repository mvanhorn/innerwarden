// Library re-exports for integration/property tests and for the
// cargo-fuzz harnesses in fuzz/.

pub mod collector_health;
pub mod collectors;
pub mod detectors;
pub mod event_pipeline;

pub fn event_pipeline_builtin_packs() -> &'static [(&'static str, &'static str)] {
    event_pipeline::BUILTIN_PACKS
}
