//! Render the ordered Seatbelt policy after native path and grant validation.
use vstd::prelude::*;

verus! {

pub(super) const HEADER: &str = "(version 1)\n(deny default)\n(allow process-exec*)\n(allow process-fork)\n";
pub(super) const NETWORK: &str = "(allow network*)";
pub(super) const BASE_RULES: &str = r#"
(allow sysctl-read)
(allow ipc-posix-shm)
(allow mach*)
(allow file-read*
    (subpath "/usr")
    (subpath "/bin")
    (subpath "/sbin")
    (subpath "/System")
    (subpath "/Library")
    (subpath "/opt")
    (subpath "/dev")
    (subpath "/private/tmp")
    (subpath "/var/folders")
    (literal "/")
)
(allow file-write*
    (subpath "/private/tmp")
    (subpath "/var/folders")
    (literal "/dev/null")
)
"#;

pub(super) enum PathRule {
    Subpath,
    Literal,
    DenyWrite,
    Hide,
}

impl PathRule {
    pub(super) fn render(&self, path: &str) -> (rule: String)
        ensures rule@ == match self {
            Self::Subpath => "    (subpath \""@ + path@ + "\")"@,
            Self::Literal => "    (literal \""@ + path@ + "\")"@,
            Self::DenyWrite => "(deny file-write* (literal \""@ + path@ + "\"))"@,
            Self::Hide => "(deny file-read* (subpath \""@ + path@ +
                "\"))\n(deny file-write* (subpath \""@ + path@ + "\"))"@,
        },
    {
        let mut rule = match self {
            Self::Subpath => "    (subpath \"",
            Self::Literal => "    (literal \"",
            Self::DenyWrite => "(deny file-write* (literal \"",
            Self::Hide => "(deny file-read* (subpath \"",
        }.to_string();
        rule.push_str(path);
        if let Self::Hide = self {
            rule.push_str("\"))\n(deny file-write* (subpath \"");
            rule.push_str(path);
        }
        match self {
            Self::Subpath | Self::Literal => rule.push_str("\")"),
            Self::DenyWrite | Self::Hide => rule.push_str("\"))"),
        }
        rule
    }
}

pub(super) struct Rules<'a> {
    pub(super) scoped_denies: &'a str,
    pub(super) ancestors: &'a str,
    pub(super) writable_root: &'a str,
    pub(super) extra_reads: &'a str,
    pub(super) injected_reads: &'a str,
    pub(super) extra_writes: &'a str,
    pub(super) hidden_denies: &'a str,
    pub(super) injected_denies: &'a str,
}

impl Rules<'_> {
    pub(super) open spec fn remaining_rules(&self) -> Seq<char> {
        BASE_RULES@ +
        self.scoped_denies@ +
        "\n(allow file-read-metadata\n"@ +
        self.ancestors@ +
        "\n)\n(allow file-read*\n    (subpath \""@ +
        self.writable_root@ +
        "\")\n"@ +
        self.extra_reads@ +
        seq!['\n'] +
        self.injected_reads@ +
        "\n)\n(allow file-write*\n    (subpath \""@ +
        self.writable_root@ +
        "\")\n"@ +
        self.extra_writes@ +
        "\n)\n"@ +
        self.hidden_denies@ +
        seq!['\n'] +
        self.injected_denies@
    }

    pub(super) fn render(&self, network: bool) -> (profile: String)
        ensures profile@ == HEADER@ + (if network { NETWORK@ } else { seq![] }) + self.remaining_rules(),
    {
        let mut profile = HEADER.to_string();
        if network { profile.push_str(NETWORK); }
        profile.push_str(BASE_RULES);
        profile.push_str(self.scoped_denies);
        profile.push_str("\n(allow file-read-metadata\n");
        profile.push_str(self.ancestors);
        profile.push_str("\n)\n(allow file-read*\n    (subpath \"");
        profile.push_str(self.writable_root);
        profile.push_str("\")\n");
        profile.push_str(self.extra_reads);
        profile.push('\n');
        profile.push_str(self.injected_reads);
        profile.push_str("\n)\n(allow file-write*\n    (subpath \"");
        profile.push_str(self.writable_root);
        profile.push_str("\")\n");
        profile.push_str(self.extra_writes);
        profile.push_str("\n)\n");
        profile.push_str(self.hidden_denies);
        profile.push('\n');
        profile.push_str(self.injected_denies);
        profile
    }
}

}
