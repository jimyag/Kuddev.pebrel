//! OpenSSH host discovery inside a WSL distribution, on the guest's own terms.
//!
//! The guest names the files to read (`res/shell/ssh-config-guests.sh`, run with
//! `sh -s`); the host then reads those files through the 9P share. Nothing is
//! executed and no `Match` condition is evaluated - the script only prints
//! `path=` lines, and `ssh -G` is never run.
//!
//! Why both sides: the host cannot know the guest's `$HOME`, `Include` order or
//! globbing, while the guest cannot hand back contents without a second round
//! trip. A distribution whose share is unavailable, whose probe fails or times
//! out, or that is not running reports *no* hosts. It never reports an empty
//! config as if it were complete, and it never falls back to the host's own
//! `~/.ssh/config`, whose host spelling does not identify the same machine.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use crate::shell_detect;

/// A cold WSL 2 VM has to boot before the probe can answer.
const PROBE_BUDGET: Duration = Duration::from_secs(15);
/// A failed or timed-out probe is not repeated before this.
const RETRY_AFTER: Duration = Duration::from_secs(300);
const MAX_LISTING: usize = 64 * 1024;
const MAX_FILES: usize = 64;
const MAX_BYTES: usize = 1024 * 1024;
const MAX_TARGETS: usize = 32;

const LISTING_SCRIPT: &str = include_str!("../../res/shell/ssh-config-guests.sh");

/// One distribution, optionally as a specific guest user.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct Target {
    pub(crate) distro: String,
    pub(crate) user: Option<String>,
}

impl Target {
    pub(crate) fn new(distro: impl Into<String>, user: Option<String>) -> Self {
        Self { distro: distro.into(), user }
    }
}

/// The guest's answer for one [`Target`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct GuestHosts {
    /// Literal `Host` aliases in OpenSSH file order, already de-duplicated.
    pub(crate) hosts: Vec<String>,
    /// The distribution that answered, so a connection can re-enter that guest
    /// instead of resolving the alias against the Windows configuration.
    pub(crate) distro: String,
    /// The guest user the scan ran as, when one was named explicitly.
    pub(crate) user: Option<String>,
}

/// Both halves of one scan: the listing from the guest, contents from the share.
fn scan(target: &Target, cancelled: &dyn Fn() -> bool) -> Option<GuestHosts> {
    let listing = directories(target, cancelled)?;
    let mut files = Vec::with_capacity(listing.paths.len());
    let mut used = 0usize;
    for path in &listing.paths {
        if cancelled() || used >= MAX_BYTES {
            break;
        }
        let Some(unc) = guest_unc(&target.distro, path) else { continue };
        let Ok(metadata) = std::fs::metadata(&unc) else { continue };
        if !metadata.is_file() || metadata.len() > (MAX_BYTES - used) as u64 {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&unc) else { continue };
        used += text.len();
        files.push((path.clone(), text));
    }
    if cancelled() || files.is_empty() {
        return None;
    }
    // Include entries are already expanded by the guest, so an empty Include
    // root is enough here; `~/` resolution is likewise finished on the guest.
    let no_root = PathBuf::new();
    let hosts = crate::ssh::hosts::collect(
        files.iter().map(|(path, text)| (path.clone(), text.as_str())),
        &no_root,
        &no_root,
        cancelled,
    );
    Some(GuestHosts { hosts, distro: target.distro.clone(), user: target.user.clone() })
}

struct Listing {
    /// Where the guest's config lives; kept for diagnostics and future `~/` work.
    #[allow(dead_code)]
    home: String,
    paths: Vec<String>,
}

fn directories(target: &Target, cancelled: &dyn Fn() -> bool) -> Option<Listing> {
    let mut command = shell_detect::wsl_exec_command(&target.distro, target.user.as_deref());
    command.args(["sh", "-s"]);
    crate::platform::process::hidden_command(&mut command);
    let output = crate::platform::process_output::read_with_input(
        command,
        LISTING_SCRIPT.as_bytes(),
        PROBE_BUDGET,
        MAX_LISTING,
        cancelled,
    )
    .ok()?;
    parse_listing(&String::from_utf8(output).ok()?)
}

/// `home=` first, then one `path=` per file. Other lines are ignored.
fn parse_listing(text: &str) -> Option<Listing> {
    let mut home = None;
    let mut paths: Vec<String> = Vec::new();
    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        if let Some(value) = line.strip_prefix("home=") {
            home = guest_absolute(value).map(str::to_owned);
        } else if let Some(value) = line.strip_prefix("path=") {
            if paths.len() >= MAX_FILES {
                break;
            }
            let Some(path) = guest_absolute(value) else { continue };
            if !paths.iter().any(|seen| seen == path) {
                paths.push(path.to_owned());
            }
        }
    }
    let home = home?;
    if paths.is_empty() { None } else { Some(Listing { home, paths }) }
}

/// An absolute posix path without a control character.
fn guest_absolute(value: &str) -> Option<&str> {
    let value = value.trim();
    (value.starts_with('/') && !value.chars().any(char::is_control)).then_some(value)
}

/// Guest absolute path to the share path Windows can open.
fn guest_unc(distro: &str, guest: &str) -> Option<PathBuf> {
    // The distribution name becomes a share component, so it may carry neither
    // separators nor the characters Windows resolves itself.
    let name_is_safe = !distro.is_empty()
        && !distro.chars().any(char::is_control)
        && !distro.contains(['\\', '/', ':', '"', '|', '<', '>', '?', '*']);
    // A guest path only needs the characters that would end or split the share
    // component; control characters are refused separately below.
    let path_is_safe = !guest.chars().any(|character| {
        character.is_control() || matches!(character, '"' | '|' | '<' | '>' | '?' | '*')
    }) && guest.starts_with('/');
    (name_is_safe && path_is_safe).then(|| shell_detect::wsl_unc_path(distro, guest))
}

/// Process-lifetime cache. The UI thread only ever reads it; a miss starts one
/// worker per target, following the probe pattern of `wsl_guest_shell`.
pub(crate) fn cached(target: &Target, cancelled: &dyn Fn() -> bool) -> Option<GuestHosts> {
    if cancelled() {
        return None;
    }
    let mut cache = cache().lock().unwrap_or_else(PoisonError::into_inner);
    let now = Instant::now();
    if let Some(entry) = cache.get(target) {
        if let Some(answer) = entry.verdict.get() {
            if answer.is_some() {
                return answer.clone();
            }
            // A failure keeps the target quiet until its cooldown ends, so a
            // stopped distribution is not restarted on every keystroke.
            if now.saturating_duration_since(entry.started) < RETRY_AFTER {
                return None;
            }
        } else {
            return None;
        }
    }
    if cache.len() >= MAX_TARGETS && !make_room(&mut cache, now) {
        return None;
    }
    let verdict = Arc::new(OnceLock::new());
    cache.insert(target.clone(), Entry { verdict: verdict.clone(), started: now });
    drop(cache);
    start_worker(target.clone(), verdict);
    // The first sighting answers on the next completion; this one reports only
    // what was already known, which keeps the UI thread off the guest.
    None
}

/// Every alias declared by a cached guest answer, host aliases first per
/// distribution and de-duplicated across them. A cache miss starts one
/// worker per distribution and contributes nothing this time.
pub(crate) fn cached_hosts(cancelled: &dyn Fn() -> bool) -> Vec<String> {
    let mut hosts = Vec::new();
    for distro in crate::platform::shell::registered_wsl_distros(cancelled) {
        if cancelled() {
            return Vec::new();
        }
        let target = Target::new(distro, None);
        let Some(answer) = cached(&target, cancelled) else { continue };
        for host in answer.hosts {
            if !hosts.contains(&host) {
                hosts.push(host);
            }
        }
    }
    hosts
}
/// Which distribution owns `host`, if any cached answer declares it.
///
/// A connection to such a host must re-enter that guest: the Windows `ssh`
/// would resolve the alias against the host configuration, where the
/// spelling may name a different machine, and the guest private key that
/// makes it work never leaves the guest.
pub(crate) fn owner(host: &str, cancelled: &dyn Fn() -> bool) -> Option<Target> {
    if cancelled() {
        return None;
    }
    let cache = cache().lock().unwrap_or_else(PoisonError::into_inner);
    cache.iter().find_map(|(target, entry)| {
        let answer = entry.verdict.get()?;
        let answer = answer.as_ref()?;
        answer.hosts.iter().any(|declared| declared == host).then(|| target.clone())
    })
}
fn start_worker(target: Target, verdict: Arc<OnceLock<Option<GuestHosts>>>) {
    std::thread::spawn(move || {
        let answer = scan(&target, &|| false);
        let _ = verdict.set(answer);
    });
}

/// Drop one settled entry (oldest successful or expired failure) for a new
/// target. Running probes and recent failures are never evicted.
fn make_room(cache: &mut std::collections::HashMap<Target, Entry>, now: Instant) -> bool {
    let victim = cache
        .iter()
        .filter_map(|(key, entry)| match entry.verdict.get() {
            Some(Some(_)) => Some((key.clone(), entry.started)),
            Some(None) if now.saturating_duration_since(entry.started) >= RETRY_AFTER => {
                Some((key.clone(), entry.started))
            },
            _ => None,
        })
        .min_by_key(|(_, started)| *started)
        .map(|(key, _)| key);
    victim.is_some_and(|key| cache.remove(&key).is_some())
}

struct Entry {
    /// Empty while the worker runs; `Some(None)` records a failure.
    verdict: Arc<OnceLock<Option<GuestHosts>>>,
    started: Instant,
}

fn cache() -> &'static Mutex<std::collections::HashMap<Target, Entry>> {
    static CACHE: OnceLock<Mutex<std::collections::HashMap<Target, Entry>>> = OnceLock::new();
    CACHE.get_or_init(Default::default)
}

/// Test seam: the same scan without the cache, so fixtures can assert the
/// listing parser and the UNC mapping against a real guest or a temp tree.
#[cfg(test)]
pub(crate) fn scan_now(target: &Target) -> Option<GuestHosts> {
    scan(target, &|| false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listing_requires_home_and_ignores_foreign_lines() {
        let text =
            "noise\nhome=/home/dev\npath=/home/dev/.ssh/config\npath=/home/dev/.ssh/config.d/a\n";
        let listing = parse_listing(text).unwrap();
        assert_eq!(listing.home, "/home/dev");
        assert_eq!(listing.paths, ["/home/dev/.ssh/config", "/home/dev/.ssh/config.d/a"]);

        assert!(parse_listing("path=/a\n").is_none(), "no home is an unusable answer");
        assert!(parse_listing("home=/home/dev\n").is_none(), "no files is not an empty config");
        assert!(parse_listing("home=relative\npath=/a\n").is_none(), "a relative home is refused");
    }

    #[test]
    fn listing_rejects_control_characters_and_duplicates() {
        let text = "home=/home/dev\npath=/home/dev/.ssh/config\npath=/home/dev/.ssh/config\n";
        let listing = parse_listing(text).unwrap();
        assert_eq!(listing.paths, ["/home/dev/.ssh/config"]);
        assert!(
            parse_listing("home=/h\npath=/a\u{7}\n").is_none(),
            "a control character is refused"
        );
    }

    #[test]
    fn share_paths_refuse_a_distro_name_that_could_escape() {
        assert!(guest_unc("Ubuntu", "/home/a/.ssh/config").is_some());
        assert!(guest_unc("Debian", "/home/a").is_some());
        assert!(guest_unc("..\\Windows", "/home/a").is_none());
        assert!(guest_unc("Debian:1", "/home/a").is_none());
        assert!(guest_unc("", "/home/a").is_none());
        assert!(guest_unc("Debian", "relative/path").is_none());
        assert!(guest_unc("Debian", "/home/a\u{7}").is_none());
        assert!(guest_unc("Debian", "/home/a|b").is_none());
    }

    #[test]
    fn make_room_never_evicts_a_running_probe_or_a_fresh_failure() {
        let mut cache = std::collections::HashMap::new();
        let now = Instant::now();
        let running = Arc::new(OnceLock::new());
        cache.insert(Target::new("Busy", None), Entry { verdict: running, started: now });
        let failed = Arc::new(OnceLock::new());
        let _ = failed.set(None);
        cache.insert(Target::new("Cold", None), Entry { verdict: failed, started: now });
        assert!(!make_room(&mut cache, now), "nothing is eligible right after a failure");
        assert_eq!(cache.len(), 2);
        assert!(make_room(&mut cache, now + RETRY_AFTER), "an expired failure is eligible");
        assert_eq!(cache.len(), 1);
    }
}

#[cfg(test)]
mod guest_pipeline_tests {
    use super::*;

    /// The exact text the guest hands back for the fixture below.
    #[test]
    fn guest_listing_text_resolves_hosts_through_the_shared_scan() {
        let listing = parse_listing(
            "home=/home/dev\npath=/home/dev/.ssh/config\npath=/home/dev/.ssh/config.d/a\n",
        )
        .unwrap();
        let files = [
            ("/home/dev/.ssh/config".to_owned(), "Include config.d/a\nHost github.com\n"),
            ("/home/dev/.ssh/config.d/a".to_owned(), "Host alpha beta\nHost *\nHost neg-!x\n"),
        ];
        assert_eq!(listing.paths.len(), 2);
        let no_root = PathBuf::new();
        let hosts = crate::ssh::hosts::collect(
            files.iter().map(|(p, t)| (p.clone(), *t)),
            &no_root,
            &no_root,
            &|| false,
        );
        assert_eq!(hosts, ["github.com", "alpha", "beta"]);
    }
}

#[cfg(test)]
mod live_debian_tests {
    use super::*;

    /// Runs the real guest tree through the project pipeline. Skipped unless
    /// PEBREL_QA_GUEST_HOME names a home directory laid out like the guest.
    #[test]
    fn real_guest_tree_resolves_literal_hosts() {
        let Ok(home) = std::env::var("PEBREL_QA_GUEST_HOME") else { return };
        let text =
            format!("home={home}\npath={home}/.ssh/config\npath={home}/.ssh/config.d/public\n");
        let listing = parse_listing(&text).unwrap();
        let files: Vec<(String, String)> = listing
            .paths
            .iter()
            .map(|p| (p.clone(), std::fs::read_to_string(p).unwrap()))
            .collect();
        let no_root = PathBuf::new();
        let hosts = crate::ssh::hosts::collect(
            files.iter().map(|(p, t)| (p.clone(), t.as_str())),
            &no_root,
            &no_root,
            &|| false,
        );
        eprintln!("REAL_HOSTS={hosts:?}");
        assert_eq!(hosts.first().map(String::as_str), Some("github.com"));
    }
}

#[cfg(all(test, windows))]
mod live_windows_tests {
    use super::*;

    /// Runs the whole Windows path: the wsl.exe probe, the 9P share read and
    /// the parser, against a distribution the caller names.
    #[test]
    fn the_real_guest_answers_through_the_windows_share() {
        let Ok(distro) = std::env::var("PEBREL_QA_WSL_DISTRO") else { return };
        let answer = scan_now(&Target::new(distro, None)).expect("guest answered");
        eprintln!("REAL_HOSTS={:?}", answer.hosts);
        assert!(answer.hosts.iter().any(|h| h == "github.com"));
        assert!(!answer.hosts.iter().any(|h| h.contains('*')));
    }
}
#[cfg(all(test, windows))]
mod cache_warm_tests {
    use super::*;

    /// The GUI asks on a render path and must never block: the first call only
    /// starts a worker, and a later call reads what it published.
    #[test]
    fn the_first_call_warms_and_the_next_one_answers() {
        let Ok(distro) = std::env::var("PEBREL_QA_WSL_DISTRO") else { return };
        let target = Target::new(distro.clone(), None);
        let first = cached_hosts(&|| false);
        eprintln!("FIRST_CALL={}", first.len());
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut answer = Vec::new();
        while Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(200));
            answer = cached_hosts(&|| false);
            if !answer.is_empty() {
                break;
            }
        }
        eprintln!("SECOND_CALL={:?}", answer.len());
        assert!(answer.iter().any(|h| h == "github.com"), "the worker published the guest hosts");
        assert!(owner("github.com", &|| false).is_some(), "the owner is recorded");
    }
}
