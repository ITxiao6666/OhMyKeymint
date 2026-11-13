use std::sync::OnceLock;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use ureq::http::Uri;

/// Shared agent for every WebUI download. Building an agent parses the TLS root
/// store and creates a connection pool, which is wasted work per request; the
/// per-policy timeouts are applied on each request instead, where the ureq config
/// scope supports both `timeout_connect` and `timeout_global`.
static AGENT: OnceLock<ureq::Agent> = OnceLock::new();

fn webui_agent() -> &'static ureq::Agent {
    AGENT.get_or_init(|| {
        ureq::Agent::config_builder().https_only(true).max_redirects(0).build().into()
    })
}

pub(crate) struct DownloadPolicy {
    pub resource: &'static str,
    pub redirect_allowlist: &'static str,
    pub max_bytes: usize,
    pub max_size_label: &'static str,
    pub max_redirects: usize,
    pub timeout: Duration,
    pub connect_timeout: Duration,
}

pub(crate) fn download_https_utf8<F>(
    requested_uri: Uri,
    policy: &DownloadPolicy,
    is_allowed: F,
) -> Result<String>
where
    F: Fn(&Uri) -> bool,
{
    if !is_allowed(&requested_uri) {
        bail!("{} URL is not allowed", policy.resource);
    }

    let started = Instant::now();
    let mut current_uri = requested_uri;
    for redirect_count in 0..=policy.max_redirects {
        let remaining = policy
            .timeout
            .checked_sub(started.elapsed())
            .ok_or_else(|| anyhow!("{} request timed out", policy.resource))?;
        let mut response = webui_agent()
            .get(current_uri.clone())
            .config()
            .timeout_connect(Some(policy.connect_timeout))
            .timeout_global(Some(remaining))
            .build()
            .header("User-Agent", concat!("OhMyKeymint/", env!("CARGO_PKG_VERSION")))
            .header("Accept-Encoding", "identity")
            .call()
            .with_context(|| format!("failed to download the {}", policy.resource))?;

        if response.status().is_redirection() {
            if redirect_count == policy.max_redirects {
                bail!("{} exceeded the {} redirect limit", policy.resource, policy.max_redirects);
            }
            let location = response
                .headers()
                .get("location")
                .ok_or_else(|| anyhow!("{} redirect has no Location header", policy.resource))?
                .to_str()
                .with_context(|| {
                    format!("{} redirect Location is not valid UTF-8", policy.resource)
                })?;
            let next_uri = resolve_redirect(&current_uri, location, policy.resource)?;
            if !is_allowed(&next_uri) {
                bail!("{} redirected outside {}", policy.resource, policy.redirect_allowlist);
            }
            current_uri = next_uri;
            continue;
        }

        if !response.status().is_success() {
            bail!("{} returned HTTP status {}", policy.resource, response.status());
        }

        let bytes = response
            .body_mut()
            .with_config()
            .limit((policy.max_bytes + 1) as u64)
            .read_to_vec()
            .with_context(|| format!("failed to read the {} response", policy.resource))?;
        if bytes.len() > policy.max_bytes {
            bail!("{} response exceeds the {} limit", policy.resource, policy.max_size_label);
        }
        return String::from_utf8(bytes)
            .with_context(|| format!("{} response is not UTF-8", policy.resource));
    }

    unreachable!("redirect loop always returns or errors")
}

pub(crate) fn resolve_redirect(base: &Uri, location: &str, resource: &str) -> Result<Uri> {
    let location = location.trim();
    if location.is_empty() {
        bail!("{resource} redirect has an empty Location header");
    }
    if location.contains('#') {
        bail!("{resource} redirect Location contains a fragment");
    }

    if location.starts_with("//") {
        let scheme = base.scheme().ok_or_else(|| anyhow!("{resource} base URI has no scheme"))?;
        return format!("{scheme}:{location}")
            .parse()
            .with_context(|| format!("{resource} redirect URI is invalid"));
    }

    let scheme = base.scheme().ok_or_else(|| anyhow!("{resource} base URI has no scheme"))?;
    let authority =
        base.authority().ok_or_else(|| anyhow!("{resource} base URI has no authority"))?;
    if location.starts_with('?') {
        return format!("{}://{}{}{}", scheme, authority, base.path(), location)
            .parse()
            .with_context(|| format!("{resource} redirect URI is invalid"));
    }

    if has_uri_scheme(location) {
        return location
            .parse()
            .with_context(|| format!("{resource} redirect Location is invalid"));
    }

    // `http::Uri` models HTTP request targets rather than general RFC URI
    // references. In particular, it rejects a query-only reference and
    // interprets a single path segment as an authority. Resolve the original
    // Location text against the base before parsing the complete URI, and
    // remove dot segments first: an allowlist entry that matches the resolved
    // target would otherwise reject a legitimate `../` redirect.
    let raw_path = if location.starts_with('/') {
        location.to_string()
    } else {
        let base_directory =
            base.path().rsplit_once('/').map(|(directory, _)| directory).unwrap_or("");
        let separator = if base_directory.ends_with('/') { "" } else { "/" };
        format!("{base_directory}{separator}{location}")
    };
    let (path, query) = match raw_path.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (raw_path.as_str(), None),
    };
    let mut absolute = format!("{scheme}://{authority}{}", remove_dot_segments(path));
    if let Some(query) = query {
        absolute.push('?');
        absolute.push_str(query);
    }

    absolute.parse().with_context(|| format!("{resource} redirect URI is invalid"))
}

/// Remove `.` and `..` segments from an absolute path, clamping at the root.
fn remove_dot_segments(path: &str) -> String {
    let mut segments: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            segment => segments.push(segment),
        }
    }
    let trailing_slash =
        path.ends_with('/') || path.ends_with("/.") || path.ends_with("/..") || path.is_empty();
    let mut normalized = String::with_capacity(path.len().min(1024));
    for segment in segments {
        normalized.push('/');
        normalized.push_str(segment);
    }
    if normalized.is_empty() || trailing_slash {
        normalized.push('/');
    }
    normalized
}

fn has_uri_scheme(value: &str) -> bool {
    let mut characters = value.chars();
    if !characters.next().is_some_and(|first| first.is_ascii_alphabetic()) {
        return false;
    }
    for character in characters {
        match character {
            ':' => return true,
            '+' | '-' | '.' => {}
            character if character.is_ascii_alphanumeric() => {}
            _ => return false,
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_resolution_handles_absolute_and_relative_forms() {
        let base: Uri = "https://example.com/path/file?old=1".parse().unwrap();
        for (location, expected) in [
            ("https://other.example/path/file", "https://other.example/path/file"),
            ("//other.example/path/file", "https://other.example/path/file"),
            ("/other/file", "https://example.com/other/file"),
            ("?new=1", "https://example.com/path/file?new=1"),
            ("next", "https://example.com/path/next"),
        ] {
            assert_eq!(resolve_redirect(&base, location, "test").unwrap().to_string(), expected);
        }
    }

    #[test]
    fn redirect_resolution_removes_dot_segments() {
        let base: Uri = "https://example.com/path/file?old=1".parse().unwrap();
        for (location, expected) in [
            ("../next", "https://example.com/next"),
            ("./next", "https://example.com/path/next"),
            ("/a/b/../c?x=1", "https://example.com/a/c?x=1"),
            ("/a/./b/", "https://example.com/a/b/"),
            ("/../../x", "https://example.com/x"),
            ("next?y=2", "https://example.com/path/next?y=2"),
            ("..", "https://example.com/"),
        ] {
            assert_eq!(resolve_redirect(&base, location, "test").unwrap().to_string(), expected);
        }
    }

    #[test]
    fn redirect_resolution_rejects_empty_or_fragment_locations() {
        let base: Uri = "https://example.com/path/file".parse().unwrap();
        for location in ["", "   ", "#fragment", "/path/file#fragment"] {
            assert!(resolve_redirect(&base, location, "test").is_err());
        }
    }
}
