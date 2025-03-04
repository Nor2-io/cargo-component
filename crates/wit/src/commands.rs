//! Module for CLI commands.

use cargo_component_core::terminal::{Color, Terminal, Verbosity};
use clap::{ArgAction, Args};

mod add;
mod build;
mod init;
mod key;
mod publish;
mod update;

pub use add::*;
pub use build::*;
pub use init::*;
pub use key::*;
pub use publish::*;
pub use update::*;

/// Common options for commands.
#[derive(Args)]
pub struct CommonOptions {
    /// Do not print log messages
    #[clap(long = "quiet", short = 'q')]
    pub quiet: bool,

    /// Use verbose output (-vv very verbose output)
    #[clap(
        long = "verbose",
        short = 'v',
        action = ArgAction::Count
    )]
    pub verbose: u8,

    /// Coloring: auto, always, never
    #[clap(long = "color", value_name = "WHEN")]
    pub color: Option<Color>,
}

impl CommonOptions {
    fn new_terminal(&self) -> Terminal {
        Terminal::new(
            if self.quiet {
                Verbosity::Quiet
            } else {
                match self.verbose {
                    0 => Verbosity::Normal,
                    _ => Verbosity::Verbose,
                }
            },
            self.color.unwrap_or_default(),
        )
    }
}
