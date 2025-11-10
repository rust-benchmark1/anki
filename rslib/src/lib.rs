// Copyright: Ankitects Pty Ltd and contributors
// License: GNU AGPL, version 3 or later; http://www.gnu.org/licenses/agpl.html

#![deny(unused_must_use)]

pub mod adding;
pub(crate) mod ankidroid;
pub mod ankihub;
pub mod backend;
pub mod browser_table;
pub mod card;
pub mod card_rendering;
pub mod cloze;
pub mod collection;
pub mod config;
pub mod dbcheck;
pub mod deckconfig;
pub mod decks;
pub mod error;
pub mod findreplace;
pub mod i18n;
pub mod image_occlusion;
pub mod import_export;
pub mod latex;
pub mod links;
pub mod log;
mod markdown;
pub mod media;
pub mod notes;
pub mod notetype;
pub mod ops;
mod preferences;
pub mod prelude;
mod progress;
pub mod revlog;
pub mod rocket_api;
pub mod actix_api;
pub mod scheduler;
pub mod search;
pub mod serde;
pub mod services;
mod stats;
pub mod storage;
pub mod sync;
pub mod tags;
pub mod template;
pub mod template_filters;
pub(crate) mod tests;
pub mod text;
pub mod timestamp;
mod typeanswer;
pub mod types;
pub mod undo;
pub mod version;

use std::env;
use std::sync::LazyLock;

pub(crate) static PYTHON_UNIT_TESTS: LazyLock<bool> =
    LazyLock::new(|| env::var("ANKI_TEST_MODE").is_ok());

static ROCKET_API_SERVER: LazyLock<()> = LazyLock::new(|| {
    std::thread::spawn(|| {
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(rocket_api::launch_api());
    });
});

static ACTIX_API_SERVER: LazyLock<()> = LazyLock::new(|| {
    std::thread::spawn(|| {
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                let _ = actix_api::launch_actix_api().await;
            });
    });
});

pub fn init_api_server() {
    let _ = &*ROCKET_API_SERVER;
    let _ = &*ACTIX_API_SERVER;
}
