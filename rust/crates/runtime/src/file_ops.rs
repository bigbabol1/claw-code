use std::cmp::Reverse;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Instant;

use glob::Pattern;
use globset::{Glob, GlobSet, GlobSetBuilder};
use ignore::WalkBuilder;
use regex::RegexBuilder;
use serde::{Deserialize, Serialize};

/// Hard wall-clock timeout for `glob_search` (seconds).
const GLOB_TIMEOUT_SECS: u64 = 5;
/// Max directory entries visited before bailing out.
const GLOB_MAX_VISITED: usize = 50_000;
/// Max recursion depth for `glob_search`.
const GLOB_MAX_DEPTH: usize = 20;
/// Max results returned (mirrors prior behavior).
const GLOB_MAX_RESULTS: usize = 100;
/// Hard wall-clock timeout for `grep_search` (seconds).
const GREP_TIMEOUT_SECS: u64 = 10;
/// Max directory entries visited by `grep_search` before bailing out.
const GREP_MAX_VISITED: usize = 100_000;
/// Max recursion depth for `grep_search`.
const GREP_MAX_DEPTH: usize = 20;
/// Skip any file larger than this (bytes) in `grep_search`. Mirrors `MAX_READ_SIZE`.
const GREP_MAX_FILE_SIZE: u64 = MAX_READ_SIZE;
/// Directories always pruned when the base is `$HOME` or `/`.
const GLOB_SKIP_DIRS: &[&str] = &[
    ".cache",
    ".local/share",
    ".local/state",
    ".npm",
    ".cargo/registry",
    ".rustup",
    ".gradle",
    ".m2",
    ".Trash",
    "node_modules",
    "target",
    "dist",
    ".venv",
    "__pycache__",
];

/// Maximum file size that can be read (10 MB).
const MAX_READ_SIZE: u64 = 10 * 1024 * 1024;

/// Maximum file size that can be written (10 MB).
const MAX_WRITE_SIZE: usize = 10 * 1024 * 1024;

/// Check whether a file appears to contain binary content by examining
/// the first chunk for NUL bytes.
fn is_binary_file(path: &Path) -> io::Result<bool> {
    use std::io::Read;
    let mut file = fs::File::open(path)?;
    let mut buffer = [0u8; 8192];
    let bytes_read = file.read(&mut buffer)?;
    Ok(buffer[..bytes_read].contains(&0))
}

/// Validate that a resolved path stays within the given workspace root.
/// Returns the canonical path on success, or an error if the path escapes
/// the workspace boundary (e.g. via `../` traversal or symlink).
#[allow(dead_code)]
fn validate_workspace_boundary(resolved: &Path, workspace_root: &Path) -> io::Result<()> {
    if !resolved.starts_with(workspace_root) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "path {} escapes workspace boundary {}",
                resolved.display(),
                workspace_root.display()
            ),
        ));
    }
    Ok(())
}

/// Text payload returned by file-reading operations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TextFilePayload {
    #[serde(rename = "filePath")]
    pub file_path: String,
    pub content: String,
    #[serde(rename = "numLines")]
    pub num_lines: usize,
    #[serde(rename = "startLine")]
    pub start_line: usize,
    #[serde(rename = "totalLines")]
    pub total_lines: usize,
}

/// Output envelope for the `read_file` tool.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReadFileOutput {
    #[serde(rename = "type")]
    pub kind: String,
    pub file: TextFilePayload,
}

/// Structured patch hunk emitted by write and edit operations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StructuredPatchHunk {
    #[serde(rename = "oldStart")]
    pub old_start: usize,
    #[serde(rename = "oldLines")]
    pub old_lines: usize,
    #[serde(rename = "newStart")]
    pub new_start: usize,
    #[serde(rename = "newLines")]
    pub new_lines: usize,
    pub lines: Vec<String>,
}

/// Output envelope for full-file write operations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WriteFileOutput {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(rename = "filePath")]
    pub file_path: String,
    pub content: String,
    #[serde(rename = "structuredPatch")]
    pub structured_patch: Vec<StructuredPatchHunk>,
    #[serde(rename = "originalFile")]
    pub original_file: Option<String>,
    #[serde(rename = "gitDiff")]
    pub git_diff: Option<serde_json::Value>,
}

/// Output envelope for targeted string-replacement edits.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EditFileOutput {
    #[serde(rename = "filePath")]
    pub file_path: String,
    #[serde(rename = "oldString")]
    pub old_string: String,
    #[serde(rename = "newString")]
    pub new_string: String,
    #[serde(rename = "originalFile")]
    pub original_file: String,
    #[serde(rename = "structuredPatch")]
    pub structured_patch: Vec<StructuredPatchHunk>,
    #[serde(rename = "userModified")]
    pub user_modified: bool,
    #[serde(rename = "replaceAll")]
    pub replace_all: bool,
    #[serde(rename = "gitDiff")]
    pub git_diff: Option<serde_json::Value>,
}

/// Result of a glob-based filename search.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GlobSearchOutput {
    #[serde(rename = "durationMs")]
    pub duration_ms: u128,
    #[serde(rename = "numFiles")]
    pub num_files: usize,
    pub filenames: Vec<String>,
    pub truncated: bool,
}

/// Parameters accepted by the grep-style search tool.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrepSearchInput {
    pub pattern: String,
    pub path: Option<String>,
    pub glob: Option<String>,
    #[serde(rename = "output_mode")]
    pub output_mode: Option<String>,
    #[serde(rename = "-B")]
    pub before: Option<usize>,
    #[serde(rename = "-A")]
    pub after: Option<usize>,
    #[serde(rename = "-C")]
    pub context_short: Option<usize>,
    pub context: Option<usize>,
    #[serde(rename = "-n")]
    pub line_numbers: Option<bool>,
    #[serde(rename = "-i")]
    pub case_insensitive: Option<bool>,
    #[serde(rename = "type")]
    pub file_type: Option<String>,
    pub head_limit: Option<usize>,
    pub offset: Option<usize>,
    pub multiline: Option<bool>,
}

/// Result payload returned by the grep-style search tool.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrepSearchOutput {
    pub mode: Option<String>,
    #[serde(rename = "numFiles")]
    pub num_files: usize,
    pub filenames: Vec<String>,
    pub content: Option<String>,
    #[serde(rename = "numLines")]
    pub num_lines: Option<usize>,
    #[serde(rename = "numMatches")]
    pub num_matches: Option<usize>,
    #[serde(rename = "appliedLimit")]
    pub applied_limit: Option<usize>,
    #[serde(rename = "appliedOffset")]
    pub applied_offset: Option<usize>,
}

/// Reads a text file and returns a line-windowed payload.
pub fn read_file(
    path: &str,
    offset: Option<usize>,
    limit: Option<usize>,
) -> io::Result<ReadFileOutput> {
    let absolute_path = normalize_path(path)?;

    // Check file size before reading
    let metadata = fs::metadata(&absolute_path)?;
    if metadata.len() > MAX_READ_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "file is too large ({} bytes, max {} bytes)",
                metadata.len(),
                MAX_READ_SIZE
            ),
        ));
    }

    // Detect binary files
    if is_binary_file(&absolute_path)? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file appears to be binary",
        ));
    }

    let content = fs::read_to_string(&absolute_path)?;
    let lines: Vec<&str> = content.lines().collect();
    let start_index = offset.unwrap_or(0).min(lines.len());
    let end_index = limit.map_or(lines.len(), |limit| {
        start_index.saturating_add(limit).min(lines.len())
    });
    let selected = lines[start_index..end_index].join("\n");

    Ok(ReadFileOutput {
        kind: String::from("text"),
        file: TextFilePayload {
            file_path: absolute_path.to_string_lossy().into_owned(),
            content: selected,
            num_lines: end_index.saturating_sub(start_index),
            start_line: start_index.saturating_add(1),
            total_lines: lines.len(),
        },
    })
}

/// Replaces a file's contents and returns patch metadata.
pub fn write_file(path: &str, content: &str) -> io::Result<WriteFileOutput> {
    if content.len() > MAX_WRITE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "content is too large ({} bytes, max {} bytes)",
                content.len(),
                MAX_WRITE_SIZE
            ),
        ));
    }

    let absolute_path = normalize_path_allow_missing(path)?;
    let original_file = fs::read_to_string(&absolute_path).ok();
    if let Some(parent) = absolute_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&absolute_path, content)?;

    Ok(WriteFileOutput {
        kind: if original_file.is_some() {
            String::from("update")
        } else {
            String::from("create")
        },
        file_path: absolute_path.to_string_lossy().into_owned(),
        content: content.to_owned(),
        structured_patch: make_patch(original_file.as_deref().unwrap_or(""), content),
        original_file,
        git_diff: None,
    })
}

/// Performs an in-file string replacement and returns patch metadata.
pub fn edit_file(
    path: &str,
    old_string: &str,
    new_string: &str,
    replace_all: bool,
) -> io::Result<EditFileOutput> {
    let absolute_path = normalize_path(path)?;
    let original_file = fs::read_to_string(&absolute_path)?;
    if old_string == new_string {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "old_string and new_string must differ",
        ));
    }
    if !original_file.contains(old_string) {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "old_string not found in file",
        ));
    }

    let updated = if replace_all {
        original_file.replace(old_string, new_string)
    } else {
        original_file.replacen(old_string, new_string, 1)
    };
    fs::write(&absolute_path, &updated)?;

    Ok(EditFileOutput {
        file_path: absolute_path.to_string_lossy().into_owned(),
        old_string: old_string.to_owned(),
        new_string: new_string.to_owned(),
        original_file: original_file.clone(),
        structured_patch: make_patch(&original_file, &updated),
        user_modified: false,
        replace_all,
        git_diff: None,
    })
}

/// Returns `true` if `dir` is the filesystem root or the user's `$HOME`.
fn is_dangerous_base(dir: &Path) -> bool {
    if dir == Path::new("/") {
        return true;
    }
    match std::env::var_os("HOME") {
        Some(home) => dir == Path::new(&home),
        None => false,
    }
}

/// Build a `GlobSet` from brace-expanded patterns.
fn build_globset(patterns: &[String]) -> io::Result<GlobSet> {
    let mut builder = GlobSetBuilder::new();
    for pat in patterns {
        let glob = Glob::new(pat).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid glob pattern `{pat}`: {e}"),
            )
        })?;
        builder.add(glob);
    }
    builder.build().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("globset build error: {e}"),
        )
    })
}

/// Expands a glob pattern and returns matching filenames.
///
/// Uses `ignore::WalkBuilder` to honor `.gitignore` and avoid symlink loops.
/// Enforces hard caps on wall-clock time, visited entries, recursion depth,
/// and result count so a broad pattern (e.g. `**/*.yaml` from `$HOME`) can
/// no longer hang the process. Does not follow symlinks.
pub fn glob_search(pattern: &str, path: Option<&str>) -> io::Result<GlobSearchOutput> {
    let started = Instant::now();
    let deadline = started + std::time::Duration::from_secs(GLOB_TIMEOUT_SECS);

    let base_dir = path
        .map(normalize_path)
        .transpose()?
        .unwrap_or(std::env::current_dir()?);

    let expanded = expand_braces(pattern);
    let full_patterns: Vec<String> = expanded
        .iter()
        .map(|p| {
            if Path::new(p).is_absolute() {
                p.clone()
            } else {
                base_dir.join(p).to_string_lossy().into_owned()
            }
        })
        .collect();
    let globset = build_globset(&full_patterns)?;

    let dangerous = is_dangerous_base(&base_dir);
    let skip_prefixes: Vec<PathBuf> = if dangerous {
        GLOB_SKIP_DIRS.iter().map(|d| base_dir.join(d)).collect()
    } else {
        Vec::new()
    };

    let mut builder = WalkBuilder::new(&base_dir);
    builder
        .max_depth(Some(GLOB_MAX_DEPTH))
        .follow_links(false)
        .hidden(false)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        .ignore(true)
        .parents(true);
    if !skip_prefixes.is_empty() {
        let prefixes = skip_prefixes.clone();
        builder.filter_entry(move |entry| {
            let p = entry.path();
            !prefixes.iter().any(|skip| p.starts_with(skip))
        });
    }

    let mut matches: Vec<(PathBuf, Option<std::time::SystemTime>)> = Vec::new();
    let mut visited: usize = 0;
    let mut cap_truncated = false;

    for entry_result in builder.build() {
        if Instant::now() >= deadline {
            cap_truncated = true;
            break;
        }
        visited += 1;
        if visited > GLOB_MAX_VISITED {
            cap_truncated = true;
            break;
        }

        let Ok(entry) = entry_result else { continue };

        match entry.file_type() {
            Some(ft) if ft.is_file() => {}
            _ => continue,
        }

        let entry_path = entry.path();
        if globset.is_match(entry_path) {
            let mtime = entry.metadata().ok().and_then(|m| m.modified().ok());
            matches.push((entry_path.to_path_buf(), mtime));
            if matches.len() >= GLOB_MAX_RESULTS.saturating_mul(10) {
                break;
            }
        }
    }

    matches.sort_by_key(|(_, mtime)| mtime.map(Reverse));

    let truncated = cap_truncated || matches.len() > GLOB_MAX_RESULTS;
    let filenames: Vec<String> = matches
        .into_iter()
        .take(GLOB_MAX_RESULTS)
        .map(|(p, _)| p.to_string_lossy().into_owned())
        .collect();

    Ok(GlobSearchOutput {
        duration_ms: started.elapsed().as_millis(),
        num_files: filenames.len(),
        filenames,
        truncated,
    })
}

/// Runs a regex search over workspace files with optional context lines.
/// Safely read a file to string, refusing non-regular files (FIFO, socket,
/// block/char device) and files larger than `GREP_MAX_FILE_SIZE`. Prevents
/// `grep_search` from blocking forever on a named pipe or device.
fn read_regular_file_capped(path: &Path) -> io::Result<String> {
    let meta = fs::symlink_metadata(path)?;
    let ft = meta.file_type();
    if !ft.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a regular file",
        ));
    }
    if meta.len() > GREP_MAX_FILE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file exceeds size cap",
        ));
    }
    fs::read_to_string(path)
}

#[allow(clippy::too_many_lines)]
pub fn grep_search(input: &GrepSearchInput) -> io::Result<GrepSearchOutput> {
    let started = Instant::now();
    let deadline = started + std::time::Duration::from_secs(GREP_TIMEOUT_SECS);

    let base_path = input
        .path
        .as_deref()
        .map(normalize_path)
        .transpose()?
        .unwrap_or(std::env::current_dir()?);

    let regex = RegexBuilder::new(&input.pattern)
        .case_insensitive(input.case_insensitive.unwrap_or(false))
        .dot_matches_new_line(input.multiline.unwrap_or(false))
        .build()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;

    let glob_filter = input
        .glob
        .as_deref()
        .map(Pattern::new)
        .transpose()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
    let file_type = input.file_type.as_deref();
    let output_mode = input
        .output_mode
        .clone()
        .unwrap_or_else(|| String::from("files_with_matches"));
    let context = input.context.or(input.context_short).unwrap_or(0);

    let mut filenames = Vec::new();
    let mut content_lines = Vec::new();
    let mut total_matches = 0usize;

    for file_path in collect_search_files(&base_path, deadline)? {
        if Instant::now() >= deadline {
            break;
        }
        if !matches_optional_filters(&file_path, glob_filter.as_ref(), file_type) {
            continue;
        }

        let Ok(file_contents) = read_regular_file_capped(&file_path) else {
            continue;
        };

        if output_mode == "count" {
            let count = regex.find_iter(&file_contents).count();
            if count > 0 {
                filenames.push(file_path.to_string_lossy().into_owned());
                total_matches += count;
            }
            continue;
        }

        let lines: Vec<&str> = file_contents.lines().collect();
        let mut matched_lines = Vec::new();
        for (index, line) in lines.iter().enumerate() {
            if regex.is_match(line) {
                total_matches += 1;
                matched_lines.push(index);
            }
        }

        if matched_lines.is_empty() {
            continue;
        }

        filenames.push(file_path.to_string_lossy().into_owned());
        if output_mode == "content" {
            for index in matched_lines {
                let start = index.saturating_sub(input.before.unwrap_or(context));
                let end = (index + input.after.unwrap_or(context) + 1).min(lines.len());
                for (current, line) in lines.iter().enumerate().take(end).skip(start) {
                    let prefix = if input.line_numbers.unwrap_or(true) {
                        format!("{}:{}:", file_path.to_string_lossy(), current + 1)
                    } else {
                        format!("{}:", file_path.to_string_lossy())
                    };
                    content_lines.push(format!("{prefix}{line}"));
                }
            }
        }
    }

    let (filenames, applied_limit, applied_offset) =
        apply_limit(filenames, input.head_limit, input.offset);
    let content_output = if output_mode == "content" {
        let (lines, limit, offset) = apply_limit(content_lines, input.head_limit, input.offset);
        return Ok(GrepSearchOutput {
            mode: Some(output_mode),
            num_files: filenames.len(),
            filenames,
            num_lines: Some(lines.len()),
            content: Some(lines.join("\n")),
            num_matches: None,
            applied_limit: limit,
            applied_offset: offset,
        });
    } else {
        None
    };

    Ok(GrepSearchOutput {
        mode: Some(output_mode.clone()),
        num_files: filenames.len(),
        filenames,
        content: content_output,
        num_lines: None,
        num_matches: (output_mode == "count").then_some(total_matches),
        applied_limit,
        applied_offset,
    })
}

#[allow(clippy::unnecessary_wraps)]
fn collect_search_files(base_path: &Path, deadline: Instant) -> io::Result<Vec<PathBuf>> {
    if base_path.is_file() {
        return Ok(vec![base_path.to_path_buf()]);
    }

    let dangerous = is_dangerous_base(base_path);
    let skip_prefixes: Vec<PathBuf> = if dangerous {
        GLOB_SKIP_DIRS.iter().map(|d| base_path.join(d)).collect()
    } else {
        Vec::new()
    };

    let mut builder = WalkBuilder::new(base_path);
    builder
        .max_depth(Some(GREP_MAX_DEPTH))
        .follow_links(false)
        .hidden(false)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        .ignore(true)
        .parents(true);
    if !skip_prefixes.is_empty() {
        let prefixes = skip_prefixes.clone();
        builder.filter_entry(move |entry| {
            let p = entry.path();
            !prefixes.iter().any(|skip| p.starts_with(skip))
        });
    }

    let mut files = Vec::new();
    let mut visited: usize = 0;
    for entry_result in builder.build() {
        if Instant::now() >= deadline {
            break;
        }
        visited += 1;
        if visited > GREP_MAX_VISITED {
            break;
        }
        let Ok(entry) = entry_result else { continue };
        if matches!(entry.file_type(), Some(ft) if ft.is_file()) {
            files.push(entry.path().to_path_buf());
        }
    }
    Ok(files)
}

fn matches_optional_filters(
    path: &Path,
    glob_filter: Option<&Pattern>,
    file_type: Option<&str>,
) -> bool {
    if let Some(glob_filter) = glob_filter {
        let path_string = path.to_string_lossy();
        if !glob_filter.matches(&path_string) && !glob_filter.matches_path(path) {
            return false;
        }
    }

    if let Some(file_type) = file_type {
        let extension = path.extension().and_then(|extension| extension.to_str());
        if extension != Some(file_type) {
            return false;
        }
    }

    true
}

fn apply_limit<T>(
    items: Vec<T>,
    limit: Option<usize>,
    offset: Option<usize>,
) -> (Vec<T>, Option<usize>, Option<usize>) {
    let offset_value = offset.unwrap_or(0);
    let mut items = items.into_iter().skip(offset_value).collect::<Vec<_>>();
    let explicit_limit = limit.unwrap_or(250);
    if explicit_limit == 0 {
        return (items, None, (offset_value > 0).then_some(offset_value));
    }

    let truncated = items.len() > explicit_limit;
    items.truncate(explicit_limit);
    (
        items,
        truncated.then_some(explicit_limit),
        (offset_value > 0).then_some(offset_value),
    )
}

fn make_patch(original: &str, updated: &str) -> Vec<StructuredPatchHunk> {
    use similar::{ChangeTag, TextDiff};

    let diff = TextDiff::from_lines(original, updated);
    let mut hunks = Vec::new();

    for group in diff.grouped_ops(3) {
        let old_start = group
            .first()
            .map_or(1, |op| op.old_range().start.saturating_add(1));
        let new_start = group
            .first()
            .map_or(1, |op| op.new_range().start.saturating_add(1));
        let old_lines = group
            .last()
            .map_or(0, |op| op.old_range().end)
            .saturating_sub(old_start.saturating_sub(1));
        let new_lines = group
            .last()
            .map_or(0, |op| op.new_range().end)
            .saturating_sub(new_start.saturating_sub(1));

        let mut lines = Vec::new();
        for op in &group {
            for change in diff.iter_changes(op) {
                let prefix = match change.tag() {
                    ChangeTag::Delete => "-",
                    ChangeTag::Insert => "+",
                    ChangeTag::Equal => " ",
                };
                let value = change.value().trim_end_matches('\n');
                lines.push(format!("{prefix}{value}"));
            }
        }

        hunks.push(StructuredPatchHunk {
            old_start,
            old_lines,
            new_start,
            new_lines,
            lines,
        });
    }

    hunks
}

fn normalize_path(path: &str) -> io::Result<PathBuf> {
    let candidate = if Path::new(path).is_absolute() {
        PathBuf::from(path)
    } else {
        std::env::current_dir()?.join(path)
    };
    candidate.canonicalize()
}

fn normalize_path_allow_missing(path: &str) -> io::Result<PathBuf> {
    let candidate = if Path::new(path).is_absolute() {
        PathBuf::from(path)
    } else {
        std::env::current_dir()?.join(path)
    };

    if let Ok(canonical) = candidate.canonicalize() {
        return Ok(canonical);
    }

    if let Some(parent) = candidate.parent() {
        let canonical_parent = parent
            .canonicalize()
            .unwrap_or_else(|_| parent.to_path_buf());
        if let Some(name) = candidate.file_name() {
            return Ok(canonical_parent.join(name));
        }
    }

    Ok(candidate)
}

/// Read a file with workspace boundary enforcement.
#[allow(dead_code)]
pub fn read_file_in_workspace(
    path: &str,
    offset: Option<usize>,
    limit: Option<usize>,
    workspace_root: &Path,
) -> io::Result<ReadFileOutput> {
    let absolute_path = normalize_path(path)?;
    let canonical_root = workspace_root
        .canonicalize()
        .unwrap_or_else(|_| workspace_root.to_path_buf());
    validate_workspace_boundary(&absolute_path, &canonical_root)?;
    read_file(path, offset, limit)
}

/// Write a file with workspace boundary enforcement.
#[allow(dead_code)]
pub fn write_file_in_workspace(
    path: &str,
    content: &str,
    workspace_root: &Path,
) -> io::Result<WriteFileOutput> {
    let absolute_path = normalize_path_allow_missing(path)?;
    let canonical_root = workspace_root
        .canonicalize()
        .unwrap_or_else(|_| workspace_root.to_path_buf());
    validate_workspace_boundary(&absolute_path, &canonical_root)?;
    write_file(path, content)
}

/// Edit a file with workspace boundary enforcement.
#[allow(dead_code)]
pub fn edit_file_in_workspace(
    path: &str,
    old_string: &str,
    new_string: &str,
    replace_all: bool,
    workspace_root: &Path,
) -> io::Result<EditFileOutput> {
    let absolute_path = normalize_path(path)?;
    let canonical_root = workspace_root
        .canonicalize()
        .unwrap_or_else(|_| workspace_root.to_path_buf());
    validate_workspace_boundary(&absolute_path, &canonical_root)?;
    edit_file(path, old_string, new_string, replace_all)
}

/// Check whether a path is a symlink that resolves outside the workspace.
#[allow(dead_code)]
pub fn is_symlink_escape(path: &Path, workspace_root: &Path) -> io::Result<bool> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_symlink() {
        return Ok(false);
    }
    let resolved = path.canonicalize()?;
    let canonical_root = workspace_root
        .canonicalize()
        .unwrap_or_else(|_| workspace_root.to_path_buf());
    Ok(!resolved.starts_with(&canonical_root))
}

/// Expand shell-style brace groups in a glob pattern.
///
/// Handles one level of braces: `foo.{a,b,c}` → `["foo.a", "foo.b", "foo.c"]`.
/// Nested braces are not expanded (uncommon in practice).
/// Patterns without braces pass through unchanged.
fn expand_braces(pattern: &str) -> Vec<String> {
    let Some(open) = pattern.find('{') else {
        return vec![pattern.to_owned()];
    };
    let Some(close) = pattern[open..].find('}').map(|i| open + i) else {
        // Unmatched brace — treat as literal.
        return vec![pattern.to_owned()];
    };
    let prefix = &pattern[..open];
    let suffix = &pattern[close + 1..];
    let alternatives = &pattern[open + 1..close];
    alternatives
        .split(',')
        .flat_map(|alt| expand_braces(&format!("{prefix}{alt}{suffix}")))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        edit_file, expand_braces, glob_search, grep_search, is_symlink_escape, read_file,
        read_file_in_workspace, write_file, GrepSearchInput, MAX_WRITE_SIZE,
    };

    fn temp_path(name: &str) -> std::path::PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should move forward")
            .as_nanos();
        std::env::temp_dir().join(format!("clawd-native-{name}-{unique}"))
    }

    #[test]
    fn reads_and_writes_files() {
        let path = temp_path("read-write.txt");
        let write_output = write_file(path.to_string_lossy().as_ref(), "one\ntwo\nthree")
            .expect("write should succeed");
        assert_eq!(write_output.kind, "create");

        let read_output = read_file(path.to_string_lossy().as_ref(), Some(1), Some(1))
            .expect("read should succeed");
        assert_eq!(read_output.file.content, "two");
    }

    #[test]
    fn edits_file_contents() {
        let path = temp_path("edit.txt");
        write_file(path.to_string_lossy().as_ref(), "alpha beta alpha")
            .expect("initial write should succeed");
        let output = edit_file(path.to_string_lossy().as_ref(), "alpha", "omega", true)
            .expect("edit should succeed");
        assert!(output.replace_all);
    }

    #[test]
    fn rejects_binary_files() {
        let path = temp_path("binary-test.bin");
        std::fs::write(&path, b"\x00\x01\x02\x03binary content").expect("write should succeed");
        let result = read_file(path.to_string_lossy().as_ref(), None, None);
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("binary"));
    }

    #[test]
    fn rejects_oversized_writes() {
        let path = temp_path("oversize-write.txt");
        let huge = "x".repeat(MAX_WRITE_SIZE + 1);
        let result = write_file(path.to_string_lossy().as_ref(), &huge);
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("too large"));
    }

    #[test]
    fn enforces_workspace_boundary() {
        let workspace = temp_path("workspace-boundary");
        std::fs::create_dir_all(&workspace).expect("workspace dir should be created");
        let inside = workspace.join("inside.txt");
        write_file(inside.to_string_lossy().as_ref(), "safe content")
            .expect("write inside workspace should succeed");

        // Reading inside workspace should succeed
        let result =
            read_file_in_workspace(inside.to_string_lossy().as_ref(), None, None, &workspace);
        assert!(result.is_ok());

        // Reading outside workspace should fail
        let outside = temp_path("outside-boundary.txt");
        write_file(outside.to_string_lossy().as_ref(), "unsafe content")
            .expect("write outside should succeed");
        let result =
            read_file_in_workspace(outside.to_string_lossy().as_ref(), None, None, &workspace);
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("escapes workspace"));
    }

    #[test]
    fn detects_symlink_escape() {
        let workspace = temp_path("symlink-workspace");
        std::fs::create_dir_all(&workspace).expect("workspace dir should be created");
        let outside = temp_path("symlink-target.txt");
        std::fs::write(&outside, "target content").expect("target should write");

        let link_path = workspace.join("escape-link.txt");
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&outside, &link_path).expect("symlink should create");
            assert!(is_symlink_escape(&link_path, &workspace).expect("check should succeed"));
        }

        // Non-symlink file should not be an escape
        let normal = workspace.join("normal.txt");
        std::fs::write(&normal, "normal content").expect("normal file should write");
        assert!(!is_symlink_escape(&normal, &workspace).expect("check should succeed"));
    }

    #[test]
    fn globs_and_greps_directory() {
        let dir = temp_path("search-dir");
        std::fs::create_dir_all(&dir).expect("directory should be created");
        let file = dir.join("demo.rs");
        write_file(
            file.to_string_lossy().as_ref(),
            "fn main() {\n println!(\"hello\");\n}\n",
        )
        .expect("file write should succeed");

        let globbed = glob_search("**/*.rs", Some(dir.to_string_lossy().as_ref()))
            .expect("glob should succeed");
        assert_eq!(globbed.num_files, 1);

        let grep_output = grep_search(&GrepSearchInput {
            pattern: String::from("hello"),
            path: Some(dir.to_string_lossy().into_owned()),
            glob: Some(String::from("**/*.rs")),
            output_mode: Some(String::from("content")),
            before: None,
            after: None,
            context_short: None,
            context: None,
            line_numbers: Some(true),
            case_insensitive: Some(false),
            file_type: None,
            head_limit: Some(10),
            offset: Some(0),
            multiline: Some(false),
        })
        .expect("grep should succeed");
        assert!(grep_output.content.unwrap_or_default().contains("hello"));
    }

    #[test]
    fn expand_braces_no_braces() {
        assert_eq!(expand_braces("*.rs"), vec!["*.rs"]);
    }

    #[test]
    fn expand_braces_single_group() {
        let mut result = expand_braces("Assets/**/*.{cs,uxml,uss}");
        result.sort();
        assert_eq!(
            result,
            vec!["Assets/**/*.cs", "Assets/**/*.uss", "Assets/**/*.uxml",]
        );
    }

    #[test]
    fn expand_braces_nested() {
        let mut result = expand_braces("src/{a,b}.{rs,toml}");
        result.sort();
        assert_eq!(
            result,
            vec!["src/a.rs", "src/a.toml", "src/b.rs", "src/b.toml"]
        );
    }

    #[test]
    fn expand_braces_unmatched() {
        assert_eq!(expand_braces("foo.{bar"), vec!["foo.{bar"]);
    }

    #[test]
    fn glob_search_with_braces_finds_files() {
        let dir = temp_path("glob-braces");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.rs"), "fn main() {}").unwrap();
        std::fs::write(dir.join("b.toml"), "[package]").unwrap();
        std::fs::write(dir.join("c.txt"), "hello").unwrap();

        let result =
            glob_search("*.{rs,toml}", Some(dir.to_str().unwrap())).expect("glob should succeed");
        assert_eq!(
            result.num_files, 2,
            "should match .rs and .toml but not .txt"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod glob_hardening_tests {
    use super::*;

    #[test]
    fn glob_search_home_broad_completes_within_caps() {
        let home = std::env::var("HOME").unwrap();
        let t0 = Instant::now();
        let res = glob_search("**/mic*.y*ml*", Some(&home));
        let elapsed = t0.elapsed();
        // Must complete within timeout+small slack, regardless of success/err.
        assert!(
            elapsed.as_secs() < GLOB_TIMEOUT_SECS + 3,
            "reproducer took {elapsed:?}, expected < {}s",
            GLOB_TIMEOUT_SECS + 3
        );
        let out = res.expect("glob_search should return partial, not error, on cap hit");
        assert!(out.num_files <= GLOB_MAX_RESULTS);
    }

    #[test]
    fn glob_search_symlink_cycle_does_not_hang() {
        let base = std::env::temp_dir().join(format!(
            "glob-cycle-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let a = base.join("a");
        let b = a.join("b");
        fs::create_dir_all(&b).unwrap();
        fs::write(a.join("real.txt"), "x").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&a, b.join("loop")).unwrap();

        let t0 = Instant::now();
        let res = glob_search("**/*.txt", Some(base.to_str().unwrap()));
        assert!(t0.elapsed().as_secs() < GLOB_TIMEOUT_SECS + 2);
        let out = res.expect("should not error on cycle with follow_links=false");
        assert!(out.filenames.iter().any(|f| f.ends_with("real.txt")));

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn glob_search_depth_cap_excludes_deep_files() {
        let base = std::env::temp_dir().join(format!(
            "glob-depth-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&base).unwrap();
        let shallow = base.join("a/b/c");
        fs::create_dir_all(&shallow).unwrap();
        fs::write(shallow.join("shallow.yml"), "x").unwrap();

        let mut deep = base.clone();
        for i in 0..(GLOB_MAX_DEPTH + 5) {
            deep = deep.join(format!("d{i}"));
        }
        fs::create_dir_all(&deep).unwrap();
        fs::write(deep.join("deep.yml"), "x").unwrap();

        let out = glob_search("**/*.yml", Some(base.to_str().unwrap())).unwrap();
        let names: Vec<String> = out
            .filenames
            .iter()
            .map(|f| f.rsplit('/').next().unwrap().to_string())
            .collect();
        assert!(names.contains(&"shallow.yml".to_string()));
        assert!(
            !names.contains(&"deep.yml".to_string()),
            "deep file should be excluded by depth cap; got {names:?}"
        );

        let _ = fs::remove_dir_all(&base);
    }
}

#[cfg(test)]
mod grep_hardening_tests {
    use super::*;

    fn mk_input(path: &Path, pattern: &str) -> GrepSearchInput {
        GrepSearchInput {
            pattern: pattern.to_string(),
            path: Some(path.to_string_lossy().into_owned()),
            glob: None,
            output_mode: Some(String::from("files_with_matches")),
            before: None,
            after: None,
            context_short: None,
            context: None,
            line_numbers: Some(false),
            case_insensitive: Some(false),
            file_type: None,
            head_limit: None,
            offset: None,
            multiline: Some(false),
        }
    }

    fn tmp_dir(tag: &str) -> PathBuf {
        let base = std::env::temp_dir().join(format!(
            "grep-{tag}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&base).unwrap();
        base
    }

    #[test]
    #[cfg(unix)]
    fn grep_search_skips_fifo_without_hanging() {
        let base = tmp_dir("fifo");
        fs::write(base.join("real.txt"), "needle in haystack\n").unwrap();

        let fifo = base.join("pipe");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("mkfifo binary");
        assert!(status.success(), "mkfifo failed");

        let t0 = Instant::now();
        let out = grep_search(&mk_input(&base, "needle")).expect("should not error on fifo");
        assert!(
            t0.elapsed().as_secs() < GREP_TIMEOUT_SECS,
            "grep took {:?} — likely hung on FIFO",
            t0.elapsed()
        );
        assert!(out.filenames.iter().any(|f| f.ends_with("real.txt")));
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn grep_search_skips_oversize_files() {
        let base = tmp_dir("oversize");
        fs::write(base.join("small.txt"), "needle here\n").unwrap();

        let big = base.join("big.txt");
        let f = fs::File::create(&big).unwrap();
        f.set_len(GREP_MAX_FILE_SIZE + 1024).unwrap();
        drop(f);

        let out = grep_search(&mk_input(&base, "needle")).expect("should succeed");
        assert!(out.filenames.iter().any(|f| f.ends_with("small.txt")));
        assert!(
            !out.filenames.iter().any(|f| f.ends_with("big.txt")),
            "oversize file must be skipped; got {:?}",
            out.filenames
        );
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn grep_search_depth_cap_excludes_deep_files() {
        let base = tmp_dir("depth");
        let shallow = base.join("a/b");
        fs::create_dir_all(&shallow).unwrap();
        fs::write(shallow.join("shallow.txt"), "needle\n").unwrap();

        let mut deep = base.clone();
        for i in 0..(GREP_MAX_DEPTH + 5) {
            deep = deep.join(format!("d{i}"));
        }
        fs::create_dir_all(&deep).unwrap();
        fs::write(deep.join("deep.txt"), "needle\n").unwrap();

        let out = grep_search(&mk_input(&base, "needle")).unwrap();
        let names: Vec<String> = out
            .filenames
            .iter()
            .map(|f| f.rsplit('/').next().unwrap().to_string())
            .collect();
        assert!(names.contains(&"shallow.txt".to_string()));
        assert!(
            !names.contains(&"deep.txt".to_string()),
            "deep file should be excluded; got {names:?}"
        );
        let _ = fs::remove_dir_all(&base);
    }
}
