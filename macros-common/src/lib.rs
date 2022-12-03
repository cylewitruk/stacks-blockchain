#[macro_use]
extern crate serde_json;

#[macro_use]
extern crate lazy_static;

#[macro_use(o, slog_log, slog_trace, slog_debug, slog_info, slog_warn, slog_error)]
extern crate slog;

mod arrays;
mod enums;
mod math;
mod strings;

pub mod logging;
pub mod utils;