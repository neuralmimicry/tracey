#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionInfo {
    pub build_version: &'static str,
    pub release_version: &'static str,
    pub build_number: u64,
    pub commit: &'static str,
    pub commit_short: &'static str,
    pub source: &'static str,
}

pub fn build_version() -> &'static str {
    env!("TRACEY_BUILD_VERSION")
}

pub fn release_version() -> &'static str {
    env!("TRACEY_RELEASE_VERSION")
}

pub fn build_number() -> u64 {
    env!("TRACEY_BUILD_NUMBER").parse::<u64>().unwrap_or(0)
}

pub fn git_commit() -> &'static str {
    env!("TRACEY_GIT_COMMIT")
}

pub fn git_commit_short() -> &'static str {
    let commit = git_commit();
    if commit == "unknown" {
        "unknown"
    } else {
        &commit[..commit.len().min(8)]
    }
}

pub fn version_source() -> &'static str {
    env!("TRACEY_VERSION_SOURCE")
}

pub fn version_info() -> VersionInfo {
    VersionInfo {
        build_version: build_version(),
        release_version: release_version(),
        build_number: build_number(),
        commit: git_commit(),
        commit_short: git_commit_short(),
        source: version_source(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_version_uses_major_minor_build_format() {
        let version = build_version();
        let parts: Vec<&str> = version.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert!(parts[0].chars().all(|ch| ch.is_ascii_digit()));
        assert!(parts[1].chars().all(|ch| ch.is_ascii_digit()));
        assert!(parts[2].len() >= 4);
        assert!(parts[2].chars().all(|ch| ch.is_ascii_digit()));
    }

    #[test]
    fn release_version_matches_cargo_package_version() {
        assert_eq!(release_version(), env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn version_info_is_self_consistent() {
        let info = version_info();
        assert_eq!(info.build_version, build_version());
        assert_eq!(info.release_version, release_version());
        assert_eq!(info.build_number, build_number());
        assert_eq!(info.commit, git_commit());
        assert_eq!(info.commit_short, git_commit_short());
        assert_eq!(info.source, version_source());
    }
}
