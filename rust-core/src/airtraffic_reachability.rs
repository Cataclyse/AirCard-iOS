//! Compatibility types for pre-existing unfinished instrumentation in exploit.rs.
//! There is deliberately no operation entry point or device access in this file.
#[derive(Default)]
pub(super) struct Observation {
    pub source: Option<String>,
    pub link: Option<String>,
    pub archive_sha256: Option<String>,
    pub filecomplete_sent: usize,
}

pub(super) fn observe(
    observation: &mut Option<&mut Observation>,
    logger: &super::Logger,
    step: &str,
    detail: String,
) {
    if observation.is_some() {
        logger.log(format!("airlift observation: {step}: {detail}"));
    }
}
