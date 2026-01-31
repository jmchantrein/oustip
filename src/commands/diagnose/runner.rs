//! Diagnostic test runner that orchestrates all test categories.

use std::path::{Path, PathBuf};
use std::time::Instant;

use super::output::{DiagnosticReport, SystemInfo, TestCategory};
use super::{backend, config, connectivity, functional, resilience, smoke};

/// Diagnostic test runner
pub struct DiagnosticRunner {
    config_path: PathBuf,
    verbose: bool,
}

impl DiagnosticRunner {
    /// Create a new diagnostic runner
    pub fn new(config_path: &Path, verbose: bool) -> Self {
        Self {
            config_path: config_path.to_path_buf(),
            verbose,
        }
    }

    /// Run all diagnostic tests
    ///
    /// Optionally filter by category name (smoke, config, connectivity, backend, functional, resilience)
    pub async fn run_all(&self, category_filter: Option<&str>) -> DiagnosticReport {
        let start = Instant::now();
        let mut results = Vec::new();

        // Collect system info first
        let system_info = SystemInfo::collect();

        // Determine which categories to run
        let categories = match category_filter {
            Some(filter) => self.parse_category_filter(filter),
            None => vec![
                TestCategory::Smoke,
                TestCategory::Config,
                TestCategory::Connectivity,
                TestCategory::Backend,
                TestCategory::Functional,
                TestCategory::Resilience,
            ],
        };

        // Run tests in order (some categories depend on others)
        for category in categories {
            if self.verbose {
                eprintln!("Running {} tests...", category);
            }

            let category_results = match category {
                TestCategory::Smoke => smoke::run_tests(&self.config_path).await,
                TestCategory::Config => config::run_tests(&self.config_path).await,
                TestCategory::Connectivity => connectivity::run_tests(&self.config_path).await,
                TestCategory::Backend => backend::run_tests(&self.config_path).await,
                TestCategory::Functional => functional::run_tests(&self.config_path).await,
                TestCategory::Resilience => resilience::run_tests(&self.config_path).await,
            };

            results.extend(category_results);
        }

        let duration_ms = start.elapsed().as_millis() as u64;
        DiagnosticReport::new(results, duration_ms).with_system_info(system_info)
    }

    /// Parse category filter string into TestCategory list
    fn parse_category_filter(&self, filter: &str) -> Vec<TestCategory> {
        filter
            .split(',')
            .filter_map(|s| match s.trim().to_lowercase().as_str() {
                "smoke" => Some(TestCategory::Smoke),
                "config" => Some(TestCategory::Config),
                "connectivity" => Some(TestCategory::Connectivity),
                "backend" => Some(TestCategory::Backend),
                "functional" => Some(TestCategory::Functional),
                "resilience" => Some(TestCategory::Resilience),
                _ => None,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_category_filter_single() {
        let runner = DiagnosticRunner::new(Path::new("/etc/oustip/config.yaml"), false);
        let categories = runner.parse_category_filter("smoke");
        assert_eq!(categories.len(), 1);
        assert_eq!(categories[0], TestCategory::Smoke);
    }

    #[test]
    fn test_parse_category_filter_multiple() {
        let runner = DiagnosticRunner::new(Path::new("/etc/oustip/config.yaml"), false);
        let categories = runner.parse_category_filter("smoke,config,backend");
        assert_eq!(categories.len(), 3);
        assert!(categories.contains(&TestCategory::Smoke));
        assert!(categories.contains(&TestCategory::Config));
        assert!(categories.contains(&TestCategory::Backend));
    }

    #[test]
    fn test_parse_category_filter_with_spaces() {
        let runner = DiagnosticRunner::new(Path::new("/etc/oustip/config.yaml"), false);
        let categories = runner.parse_category_filter(" smoke , config ");
        assert_eq!(categories.len(), 2);
    }

    #[test]
    fn test_parse_category_filter_case_insensitive() {
        let runner = DiagnosticRunner::new(Path::new("/etc/oustip/config.yaml"), false);
        let categories = runner.parse_category_filter("SMOKE,Config,BACKEND");
        assert_eq!(categories.len(), 3);
    }

    #[test]
    fn test_parse_category_filter_invalid_ignored() {
        let runner = DiagnosticRunner::new(Path::new("/etc/oustip/config.yaml"), false);
        let categories = runner.parse_category_filter("smoke,invalid,config");
        assert_eq!(categories.len(), 2);
    }
}
