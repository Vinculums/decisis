//! The shop pages; they read data through `crate::api`, never `crate::db`.
mod widgets;

use crate::db::models::Order;
use super::db::{self, models};
use shop_db::pool::Pool;
use std::collections::HashMap;
use crate::api::Client;

/* use crate::db::secret; /* a nested comment */ still the outer comment */
const RAW: &str = r#"use crate::db::raw; "quoted""#;
const QUOTE: char = '"';

fn first<'a>(x: &'a str) -> &'a str {
    x
}

use crate::db::models::Total;
