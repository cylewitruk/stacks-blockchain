use std::env;

fn inner_get_loglevel() -> slog::Level {
    if env::var("STACKS_LOG_TRACE") == Ok("1".into()) {
        slog::Level::Trace
    } else if env::var("STACKS_LOG_DEBUG") == Ok("1".into()) {
        slog::Level::Debug
    } else if env::var("BLOCKSTACK_DEBUG") == Ok("1".into()) {
        slog::Level::Debug
    } else {
        slog::Level::Info
    }
}

lazy_static! {
    static ref LOGLEVEL: slog::Level = inner_get_loglevel();
}

pub fn get_loglevel() -> slog::Level {
    *LOGLEVEL
}

// print debug statements while testing
#[allow(unused_macros)]
#[macro_export]
macro_rules! test_debug {
    ($($arg:tt)*) => (
        #[cfg(any(test, feature = "testing"))]
        {
            use std::env;
            if env::var("BLOCKSTACK_DEBUG") == Ok("1".to_string()) {
                debug!($($arg)*);
            }
        }
    )
}

#[macro_export]
macro_rules! trace {
    ($($arg:tt)*) => ({
        let cur_level = $crate::logging::get_loglevel();
        if slog::Level::Trace.is_at_least(cur_level) {
            slog_trace!($crate::logging::LOGGER, $($arg)*)
        }
    })
}

#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => ({
        let cur_level = $crate::util::log::get_loglevel();
        if slog::Level::Error.is_at_least(cur_level) {
            slog_error!($crate::logging::LOGGER, $($arg)*)
        }
    })
}

#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => ({
        let cur_level = $crate::util::log::get_loglevel();
        if slog::Level::Warning.is_at_least(cur_level) {
            slog_warn!($crate::logging::LOGGER, $($arg)*)
        }
    })
}

#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => ({
        let cur_level = $crate::util::log::get_loglevel();
        if slog::Level::Info.is_at_least(cur_level) {
            slog_info!($crate::logging::LOGGER, $($arg)*)
        }
    })
}

#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => ({
        let cur_level = $crate::util::log::get_loglevel();
        if slog::Level::Debug.is_at_least(cur_level) {
            slog_debug!($crate::logging, $($arg)*)
        }
    })
}

#[macro_export]
macro_rules! fatal {
    ($($arg:tt)*) => ({
        let cur_level = $crate::util::log::get_loglevel();
        if slog::Level::Critical.is_at_least(cur_level) {
            slog_crit!($crate::logging::LOGGER, $($arg)*)
        }
    })
}