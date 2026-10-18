# Guest OpenSSH aliases come from the guest, never from the host

## Status
Implemented and unit-tested on Debian 13 (WSL 2, `dash`). Native Windows
acceptance of the rendered host list is not recorded here.

## Context
Windows-side `~/.ssh/config` aliases already reached the SSH host library and the
`ssh` completion source. Identical hosts declared inside a WSL distribution did
not, and a pane that runs in the guest is what the user usually means. Earlier
work recorded the absence explicitly: guest SSH configuration and `known_hosts`
discovery were not implemented, and the reason given was that no authenticated,
owned query boundary existed.

## Evidence
`nebula_app/src/ssh/hosts.rs` scanned one host path with a 1 MiB / 64 file /
8 level / 250 ms budget and reported literal `Host` names only. Its Include
resolution was host-filesystem specific: `canonicalize`, `Path::join`, `glob`,
and `crate::platform::local_paths`. The completion source
(`completion/connections.rs`) already ran on a worker with a two-second cache,
and `platform::wsl_guest_shell` already established the owned-probe pattern
(`wsl.exe -d X --exec`, stdin script, bounded output, process-lifetime verdict).

## Decision
- `res/shell/ssh-config-guests.sh` runs through
  `wsl.exe -d <distro> [-u <user>] --exec sh -s` with the script on stdin. It
  prints `home=` and one `path=` per regular file, in OpenSSH read order:
  the config first, then its `Include` targets depth first. It never runs
  `ssh -G`, never evaluates `Match`, and never expands a command substitution.
- `platform::wsl_ssh` reads those files through the 9P share, then hands the
  `(guest path, text)` pairs to `ssh::hosts::collect`, so parsing, de-duplication
  and the 1024 alias cap are the same code the host path uses.
- A guest listing is already flattened: its `Include` directives were expanded
  in the guest, and their paths do not exist on the host. `Scan::follow_includes`
  is therefore false for `collect` and true for `discover`; without that
  distinction the shared scanner silently dropped every Included file and
  reported only the top-level config (observed: 2 aliases instead of 43).
- `ssh_config_hosts` appends guest aliases after the host ones and only when the
  answer is already cached; a miss starts one worker. `completion/connections.rs`
  calls the same accessor on its existing worker and cache.
- A failed, timed-out, stopped or share-less distribution yields no aliases, and
  is retried after five minutes. It is never presented as an empty config and
  never falls back to the host's own `~/.ssh/config`.

## Rejected alternatives
- Reading `\\wsl.localhost\<distro>\home\<user>\.ssh\config` directly: the guest
  home is not the Windows home, the share is not always mounted, and the failure
  would be indistinguishable from an empty configuration.
- Running `ssh -G` per alias: `Match exec` would execute user code during typing.
- Returning file contents from the guest script: it would make the script a
  general file reader, and on this machine the guest's stdout through `wsl.exe`
  is not reliable enough for bodies. Paths plus a host-side share read keep both
  sides doing only what they can prove.
- Starting the distribution when the UI asks: the host library is built while
  rendering, so a cold boot there would freeze the window.

## Consequences
- The first call after launch contributes no guest aliases; the next render or
  completion request does, once the worker answers.
- `--distribution-id` and `--system` launches name no distribution the scan can
  enter, so they contribute nothing. Only the explicit user is probed; the
  default user of a distribution is the one its `wsl.exe` entry starts.
- A guest alias and a host alias with the same spelling remain two rows only if
  they differ; the list de-duplicates by string, as it already did across
  `saved` and `config`.

## Validation
`platform::wsl_ssh` unit tests cover the listing contract (home required, empty
listing is not an empty configuration, control characters and duplicates
refused, unsafe distribution names rejected), cache admission (a running probe
and a fresh failure are never evicted), and the full listing-to-alias pipeline.
A fixture test runs the real Debian home through the same code path. `cargo check
-p nebula --bin pebrel` and the `ssh::`, `completion::` and `platform::wsl_ssh::`
suites pass.

## Supersedes
The "not implemented" consequence recorded in
`architecture/notes/nebula_app/completion/2026-09-30-common-command-sources.md`.

## Connecting a guest host

An alias declared by a guest is re-entered through that guest, not resolved on
Windows. `add_ssh_terminal` asks `ssh::guest_distro_for`; when a cached guest
answer declares the host, the pane launches
`wsl.exe -d <distro> --exec ssh <host>` as an ordinary local shell. Every other
host keeps the native `TerminalLaunch::Ssh` path.

`--exec` keeps the guest login shell out of the path, so the guest's own
`ssh`, `~/.ssh/config`, `known_hosts`, `ProxyJump` and agent all apply. The
alias is one literal argv entry, so no guest shell ever parses it.

### Rejected alternatives
- Copying guest private keys to Windows and authenticating natively: moves a key
  out of the guest on every connection and defeats its protection model.
- Bridging `SSH_AUTH_SOCK` over the 9P share: the share does not carry Unix
  sockets reliably.
- Resolving the alias with the Windows `ssh -G`: the same spelling may name a
  different machine there, and the key that makes it work is in the guest.

### Consequences
A guest pane is a guest `ssh`, so the native pane features that depend on the
russh transport (SFTP browser, native port forwarding, remote hooks) do not apply
to it; the tab carries the guest terminal instead. Host-key trust stays the
guest's own decision: an unknown key stops the connection as `ssh` always has.

## What the pane reports, and how

A guest pane is not a native SSH pane, so nothing about it is discovered by
accident. Three pieces make it behave like one where it can:

1. `shell_detect::wsl_ssh_shell` launches
   `wsl.exe -d <distro> --exec ssh -t <host> <launcher>`. `-t` gives the remote
   side a PTY, which is what an interactive integration needs.
2. `<launcher>` is `ssh::integration_launcher()` - the same base64 bootstrap
   `nebula ssh` already appends for native panes: the remote decodes it, writes
   an rcfile and execs an integrated bash/zsh. Its fallback is
   `exec "${SHELL:-/bin/sh}" -i`, so a host without `base64` or `bash` still
   lands in an interactive shell instead of dropping the session.
3. The remote then emits OSC 133 and `OSC 2 ; NEBULA|<cwd>|<branch>|<program>`.
   `cwd_report::apply` already understands that title, so the pane learns the
   far-side directory without any SSH-specific parser.

`TerminalView::guest_dir` holds that directory. It is deliberately *not*
`TerminalView::cwd`: that field is a Windows path that the file panel, local
completion, directory history and session restore all read as this machine's.
For a guest pane the reported path belongs to the host the guest connected to,
so `process_event` moves it into `guest_dir` and leaves `cwd` empty. The tab
label shows the last component of `guest_dir`, falling back to the alias before
the first report.

### Rejected alternatives
- Letting the NEBULA title write `cwd` directly: it would hand a POSIX path to
  the local file panel, directory history and session restore, which all mean a
  Windows path by that field.
- Marking the pane with `ssh_destination`: `remote_cwd`, SFTP, native port
  forwarding and remote hooks all key off it and expect the russh transport,
  which this pane does not have.
- Re-implementing the remote bootstrap for guests: the native one already
  exists and is the behaviour users get from `nebula ssh`.

### Consequences
- A guest pane now inherits the native wrapper's trade: the remote shell starts
  from a generated rcfile (`bash --rcfile`, or `ZDOTDIR` for zsh) rather than the
  login shell's own files. This is exactly what a native Pebrel SSH pane does.
- The saved tab stores the launcher in its args, so `session.json` grows by the
  size of one bootstrap (about 16 KB) per guest tab. In return a restored tab
  replays byte-for-byte and never depends on a warm guest cache.
- The tab shows the far-side directory, not the host name, once the guest
  reports one; a native SSH tab still shows its saved host name.

## Revisit when
The share read proves unreliable enough to justify streaming bodies from the
guest, generated `config.d` files need a refresh signal rather than the current
worker cache, or the host library needs per-distro sections instead of one list.
