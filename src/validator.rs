//! 3-Stage Integrity Validator for `firewall.rules.special` and `firewall.tools` helper parser.
//!
//! Stage 1: `bash -n` syntax check.
//! Stage 2: `shellcheck` static analysis.
//! Stage 3: Variable resolution check verifying every `$VAR` / `${VAR}` referenced in
//!          `firewall.rules.special` is defined in `firewall.tools`, `firewall.settings`,
//!          or locally inside `firewall.rules.special`.

use std::collections::HashSet;
use std::path::Path;
use std::process::Command;

use regex::Regex;
use serde::{Deserialize, Serialize};

/// Documentation entry for a helper function parsed from `firewall.tools`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolFunctionDoc {
    /// Function name (e.g. `insert_rules_with_test_ok_ipv4`).
    pub name: String,
    /// Usage signature (e.g. `insert_rules_with_test_ok_ipv4 "<cmd_args>" ["<fallback_args>"]`).
    pub usage: String,
    /// French description of the helper function.
    pub description: String,
}

/// One undefined variable reference detected during Stage 3.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UndefinedVariableIssue {
    /// 1-based line number in `firewall.rules.special`.
    pub line: usize,
    /// Variable identifier without leading `$`.
    pub variable: String,
    /// Line snippet where the variable appears.
    pub context: String,
}

/// Complete report produced by the 3-stage validation pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationReport {
    /// Overall pass/fail (`bash_n_ok && undefined_variables.is_empty() && shellcheck_errors == 0`).
    pub valid: bool,
    /// Stage 1 (`bash -n`) pass/fail.
    pub bash_n_ok: bool,
    /// Stage 1 (`bash -n`) stderr output.
    pub bash_n_output: String,
    /// Whether the `shellcheck` binary was available on the host.
    pub shellcheck_available: bool,
    /// Stage 2 (`shellcheck`) pass/fail (no error-level findings).
    pub shellcheck_ok: bool,
    /// Stage 2 (`shellcheck`) formatted findings.
    pub shellcheck_issues: Vec<String>,
    /// Stage 3 variable resolution pass/fail.
    pub variables_ok: bool,
    /// Stage 3 list of undefined variables (`$CHAIN...`, `$IPS...`, etc.).
    pub undefined_variables: Vec<UndefinedVariableIssue>,
    /// Set of known system constants discovered from `firewall.tools` + `firewall.settings`.
    pub known_constants_count: usize,
}

/// Parses `@fn`, `@usage`, and `@desc` annotations (or function declarations) from `firewall.tools`.
#[must_use]
pub fn parse_tools_functions(tools_path: &Path) -> Vec<ToolFunctionDoc> {
    let raw = std::fs::read_to_string(tools_path)
        .or_else(|_| std::fs::read_to_string("scripts_etc/firewall.tools"))
        .unwrap_or_default();

    let mut docs = Vec::new();
    let mut current_fn: Option<String> = None;
    let mut current_usage: Option<String> = None;
    let mut current_desc: Option<String> = None;

    for line in raw.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("## @fn ") {
            current_fn = Some(rest.trim().to_owned());
        } else if let Some(rest) = trimmed.strip_prefix("## @usage ") {
            current_usage = Some(rest.trim().to_owned());
        } else if let Some(rest) = trimmed.strip_prefix("## @desc ") {
            current_desc = Some(rest.trim().to_owned());
        } else if trimmed.ends_with("()") || trimmed.contains("() #") {
            let fn_name = trimmed.split("()").next().unwrap_or("").trim().to_owned();
            if !fn_name.is_empty() {
                let name = current_fn.take().unwrap_or_else(|| fn_name.clone());
                let usage = current_usage
                    .take()
                    .unwrap_or_else(|| format!("{name} ..."));
                let description = current_desc.take().unwrap_or_else(|| {
                    "Fonction utilitaire définie dans firewall.tools.".to_owned()
                });
                docs.push(ToolFunctionDoc {
                    name,
                    usage,
                    description,
                });
            }
        }
    }
    docs
}

/// Extracts all variable names defined in `firewall.tools` plus standard `firewall.settings` arrays.
#[must_use]
pub fn collect_known_variables(tools_path: &Path) -> HashSet<String> {
    let mut known: HashSet<String> = [
        // Standard editable variables in firewall.settings
        "mainInter",
        "INTEROut",
        "interfaceToGoOutSide",
        "internInterfaceHaveAccessAsLocal",
        "interfaceLocal",
        "interfaceWithDHCP",
        "interfaceWithNoRules",
        "dockerNetworkWithInternetAccess",
        "dockerNetworkWithAccess",
        "dockerAccessBetweenThem",
        "IPAutor",
        "IPAutorDnatPortTCP",
        "IPAutorDnatPortUDP",
        "IPAutorDockerTCP",
        "IPAutorDockerUDP",
        "internalOpenPortsTCP",
        "internalOpenPortsUDP",
        "internalRedirectPortTCP",
        "internalRedirectPortUDP",
        "internalDnatPortTCP",
        "internalDnatPortUDP",
        "internalDockerTCP",
        "internalDockerUDP",
        "localOpenPortsTCP",
        "localOpenPortsUDP",
        "localRedirectPortTCP",
        "localRedirectPortUDP",
        "localDnatPortTCP",
        "localDnatPortUDP",
        "localDockerTCP",
        "localDockerUDP",
        "countryOpenPort",
        "openPortTCP",
        "openPortUDP",
        "redirectPortTCP",
        "redirectPortUDP",
        "dnatPortTCP",
        "dnatPortUDP",
        "openDockerTCP",
        "openDockerUDP",
        "WWopenPortTCP",
        "WWopenPortUDP",
        "WWredirectPortTCP",
        "WWredirectPortUDP",
        "WWdnatPortTCP",
        "WWdnatPortUDP",
        "WWDockerTCP",
        "WWDockerUDP",
        "blockedCountry",
        "blockedCountry2",
        // Standard Bash & environment variables
        "PATH",
        "HOME",
        "USER",
        "SHELL",
        "PWD",
        "IFS",
        "RANDOM",
        "SECONDS",
        "LINENO",
        "BASH_SOURCE",
        "FUNCNAME",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();

    let raw = std::fs::read_to_string(tools_path)
        .or_else(|_| std::fs::read_to_string("scripts_etc/firewall.tools"))
        .unwrap_or_default();

    extract_defined_variables_from_script(&raw, &mut known);
    known
}

fn extract_defined_variables_from_script(script: &str, out: &mut HashSet<String>) {
    let assign_re = Regex::new(
        r"(?:^|\s|;)(?:local\s+|declare\s+(?:-[a-zA-Z]+\s+)?|export\s+|readonly\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(?:=|\+=)",
    )
    .ok();
    let declare_bare_re =
        Regex::new(r"(?:^|\s)(?:local|declare(?:\s+-[a-zA-Z]+)?)\s+([A-Za-z_][A-Za-z0-9_]*)").ok();
    let for_re = Regex::new(r"(?:^|\s|;)for\s+([A-Za-z_][A-Za-z0-9_]*)\s+in\b").ok();
    let read_re = Regex::new(r"\bread\b[^;\n]*\s+([A-Za-z_][A-Za-z0-9_]*)\s*$").ok();

    for raw_line in script.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(re) = &assign_re {
            for cap in re.captures_iter(line) {
                if let Some(m) = cap.get(1) {
                    out.insert(m.as_str().to_owned());
                }
            }
        }
        if let Some(re) = &declare_bare_re {
            for cap in re.captures_iter(line) {
                if let Some(m) = cap.get(1) {
                    out.insert(m.as_str().to_owned());
                }
            }
        }
        if let Some(re) = &for_re {
            for cap in re.captures_iter(line) {
                if let Some(m) = cap.get(1) {
                    out.insert(m.as_str().to_owned());
                }
            }
        }
        if let Some(re) = &read_re
            && let Some(cap) = re.captures(line)
            && let Some(m) = cap.get(1)
        {
            out.insert(m.as_str().to_owned());
        }
    }
}

/// Runs the 3-stage validation pipeline on `script_content`.
#[must_use]
pub fn validate_special_rules(script_content: &str, tools_path: &Path) -> ValidationReport {
    let mut known = collect_known_variables(tools_path);
    let known_constants_count = known.len();
    extract_defined_variables_from_script(script_content, &mut known);

    // Stage 1: `bash -n`
    let (bash_n_ok, bash_n_output) = run_bash_n(script_content);

    // Stage 2: `shellcheck`
    let (shellcheck_available, shellcheck_ok, shellcheck_issues) = run_shellcheck(script_content);

    // Stage 3: Variable resolution check
    let undefined_variables = check_variable_references(script_content, &known);
    let variables_ok = undefined_variables.is_empty();

    let valid = bash_n_ok && variables_ok && shellcheck_ok;

    ValidationReport {
        valid,
        bash_n_ok,
        bash_n_output,
        shellcheck_available,
        shellcheck_ok,
        shellcheck_issues,
        variables_ok,
        undefined_variables,
        known_constants_count,
    }
}

fn run_bash_n(script_content: &str) -> (bool, String) {
    let tmp_path =
        std::env::temp_dir().join(format!("fw_special_check_{}.sh", uuid::Uuid::new_v4()));
    if let Err(e) = std::fs::write(&tmp_path, script_content) {
        return (
            false,
            format!("Failed to write temporary script for bash -n: {e}"),
        );
    }
    let output = Command::new("bash").arg("-n").arg(&tmp_path).output();
    let _ = std::fs::remove_file(&tmp_path);

    match output {
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_owned();
            (out.status.success(), stderr)
        }
        Err(e) => (false, format!("Failed to invoke bash -n: {e}")),
    }
}

fn run_shellcheck(script_content: &str) -> (bool, bool, Vec<String>) {
    let tmp_path = std::env::temp_dir().join(format!("fw_shellcheck_{}.sh", uuid::Uuid::new_v4()));
    if std::fs::write(&tmp_path, script_content).is_err() {
        return (false, true, Vec::new());
    }

    let output = Command::new("shellcheck")
        .args([
            "-s",
            "bash",
            "-S",
            "error",
            "-e",
            "SC1091,SC2086,SC2154,SC2155",
            "-f",
            "gcc",
        ])
        .arg(&tmp_path)
        .output();
    let _ = std::fs::remove_file(&tmp_path);

    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let issues: Vec<String> = stdout
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(str::to_owned)
                .collect();
            (true, out.status.success(), issues)
        }
        Err(_) => {
            // shellcheck binary not installed in minimal container environment
            (false, true, Vec::new())
        }
    }
}

fn check_variable_references(
    script_content: &str,
    known: &HashSet<String>,
) -> Vec<UndefinedVariableIssue> {
    let mut issues = Vec::new();
    let Ok(var_re) = Regex::new(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?") else {
        return issues;
    };

    for (idx, raw_line) in script_content.lines().enumerate() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // Strip trailing comment if preceded by whitespace
        let code_part = trimmed.split(" #").next().unwrap_or(trimmed);
        for cap in var_re.captures_iter(code_part) {
            if let Some(m) = cap.get(1) {
                let var_name = m.as_str();
                if !known.contains(var_name) {
                    issues.push(UndefinedVariableIssue {
                        line: idx + 1,
                        variable: var_name.to_owned(),
                        context: code_part.to_owned(),
                    });
                }
            }
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validator_catches_syntax_and_undefined_chain_variables() {
        let tools_path = Path::new("scripts_etc/firewall.tools");
        let valid_script = "#!/bin/bash\nsource /etc/firewall/firewall.tools\ninsert_rules_with_test_ok_ipv4 \"-I $CHAINMAINOUTINTERWW 1 -m set --match-set $IPSLISTGOODIP src -j ACCEPT\"\n";
        let report_ok = validate_special_rules(valid_script, tools_path);
        assert!(report_ok.bash_n_ok);
        assert!(
            report_ok.variables_ok,
            "expected no undefined vars, got {:?}",
            report_ok.undefined_variables
        );

        let bad_var_script = "#!/bin/bash\ninsert_rules_with_test_ok_ipv4 \"-I $CHAIN_DOES_NOT_EXIST 1 -j ACCEPT\"\n";
        let report_bad_var = validate_special_rules(bad_var_script, tools_path);
        assert!(!report_bad_var.variables_ok);
        assert_eq!(
            report_bad_var.undefined_variables[0].variable,
            "CHAIN_DOES_NOT_EXIST"
        );

        let bad_syntax_script = "#!/bin/bash\nif [ -n \"$IPT\" ; then\necho hi\n";
        let report_bad_syn = validate_special_rules(bad_syntax_script, tools_path);
        assert!(!report_bad_syn.bash_n_ok);
    }
}
