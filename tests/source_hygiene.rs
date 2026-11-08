//! Source hygiene tests for `static/app.js` and `static/index.html`.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use oxc_allocator::Allocator;
use oxc_parser::Parser;
use oxc_span::SourceType;
use regex::Regex;

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|e| panic!("{relative} must be readable: {e}"))
}

fn syntax_errors(relative: &str, source: &str) -> Vec<String> {
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, source, SourceType::cjs()).parse();
    parsed
        .diagnostics
        .iter()
        .map(|err| {
            let offset = (err.labels.first().map_or(0, oxc_span::LabeledSpan::offset) as usize)
                .min(source.len());
            let line = source[..offset].matches('\n').count() + 1;
            let col = source[..offset]
                .rfind('\n')
                .map_or(offset + 1, |nl| offset - nl);
            format!("{relative}:{line}:{col} {err}")
        })
        .collect()
}

#[test]
fn app_js_parses_without_syntax_errors() {
    let source = read("static/app.js");
    let errors = syntax_errors("static/app.js", &source);
    assert!(
        errors.is_empty(),
        "static/app.js has JavaScript syntax errors:\n  {}",
        errors.join("\n  ")
    );
}

#[test]
fn every_get_element_by_id_target_is_declared_in_html_or_rendered_by_js() {
    let index_html = read("static/index.html");
    let app_js = read("static/app.js");

    let id_decl = Regex::new(r#"id="([A-Za-z0-9_-]+)""#).expect("valid regex");
    let mut declared: HashSet<String> = HashSet::new();
    for src in [&index_html, &app_js] {
        for cap in id_decl.captures_iter(src) {
            declared.insert(cap[1].to_owned());
        }
    }

    let lookup =
        Regex::new(r#"getElementById\(\s*["']([A-Za-z0-9_-]+)["']\s*\)"#).expect("valid regex");
    let mut missing: Vec<String> = Vec::new();
    for cap in lookup.captures_iter(&app_js) {
        let id = &cap[1];
        if !declared.contains(id) {
            missing.push(id.to_owned());
        }
    }

    assert!(
        missing.is_empty(),
        "static/app.js calls getElementById(...) on ids never declared in index.html or app.js: {missing:?}"
    );
}

#[test]
fn every_tab_button_in_index_html_has_a_matching_panel() {
    let index_html = read("static/index.html");
    let tab_btn = Regex::new(r#"data-tab="([A-Za-z0-9_-]+)""#).expect("valid regex");
    let id_decl = Regex::new(r#"id="([A-Za-z0-9_-]+)""#).expect("valid regex");

    let ids: HashSet<String> = id_decl
        .captures_iter(&index_html)
        .map(|c| c[1].to_owned())
        .collect();

    for cap in tab_btn.captures_iter(&index_html) {
        let tab = &cap[1];
        let expected_panel_id = format!("tab-{tab}");
        assert!(
            ids.contains(&expected_panel_id),
            "tab button data-tab=\"{tab}\" has no matching #{expected_panel_id} panel in index.html"
        );
    }
}

#[test]
fn every_fetch_goes_through_the_mount_prefix_aware_request_base() {
    let app_js = read("static/app.js");
    let fetch_calls: Vec<&str> = Regex::new(r"fetch\([^)]*\)")
        .expect("valid regex")
        .find_iter(&app_js)
        .map(|m| m.as_str())
        .collect();
    assert_eq!(
        fetch_calls.len(),
        1,
        "expected exactly one fetch() call site in app.js: {fetch_calls:?}"
    );
    assert!(
        fetch_calls[0].contains("this.requestBase"),
        "the fetch() call must be prefixed with this.requestBase: {}",
        fetch_calls[0]
    );
}

#[test]
fn the_signed_message_includes_the_signing_base() {
    let app_js = read("static/app.js");
    assert!(
        app_js.contains("${method}\\n${this.signingBase}${path}\\n${timestamp}"),
        "the CANONICAL_V1 message must be built over this.signingBase"
    );
}

#[test]
fn login_form_exposes_an_optional_api_base_override_field() {
    let index_html = read("static/index.html");
    let input = Regex::new(r#"<input[^>]*id="login-api-base"[^>]*>"#)
        .expect("valid regex")
        .find(&index_html)
        .map_or_else(
            || panic!("static/index.html must have an #login-api-base input"),
            |m| m.as_str().to_owned(),
        );
    assert!(
        !input.contains("required"),
        "the API base override must be optional: {input}"
    );
}
