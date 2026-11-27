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
    pub(super) open spec fn fragment(&self, path: &str) -> Seq<char> {
        match self {
            Self::Subpath => "    (subpath \""@ + path@ + "\")"@,
            Self::Literal => "    (literal \""@ + path@ + "\")"@,
            Self::DenyWrite => "(deny file-write* (literal \""@ + path@ + "\"))"@,
            Self::Hide => "(deny file-read* (subpath \""@ + path@ +
                "\"))\n(deny file-write* (subpath \""@ + path@ + "\"))"@,
        }
    }

    pub(super) fn render(&self, path: &str) -> (rule: String)
        ensures rule@ == self.fragment(path),
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

    #[verifier::opaque]
    pub(super) open spec fn group(&self, paths: Seq<&str>, count: nat) -> Seq<char>
        recommends count <= paths.len()
        decreases count,
    {
        if count == 0 { seq![] } else {
            self.group(paths, (count - 1) as nat)
                + (if count == 1 { seq![] } else { seq!['\n'] })
                + self.fragment(paths[count - 1])
        }
    }

    fn append_group(&self, profile: &mut String, paths: &[&str])
        ensures final(profile)@ == old(profile)@ + self.group(paths@, paths@.len()),
    {
        reveal(PathRule::group);
        let mut i = 0;
        while i < paths.len()
            invariant
                i <= paths.len(),
                profile@ == old(profile)@ + self.group(paths@, i as nat),
            decreases paths.len() - i,
        {
            reveal(PathRule::group);
            if i > 0 { profile.push('\n'); }
            profile.push_str(self.render(paths[i]).as_str());
            i = i.saturating_add(1);
        }
    }
}

#[verifier::opaque]
pub(super) open spec fn hidden_group<'a>(paths: Seq<(&'a str, bool)>, scoped: bool, count: nat) -> Seq<&'a str>
    recommends count <= paths.len()
    decreases count,
{
    if count == 0 { seq![] } else {
        let before = hidden_group(paths, scoped, (count - 1) as nat);
        let (path, grant_below) = paths[count - 1];
        if grant_below == scoped { before.push(path) } else { before }
    }
}

/// Platform interpretation of lexical path components for a single comparison.
pub(super) trait Components {
    spec fn parts(path: &str) -> Seq<Seq<u8>>;

    fn below(path: &str, root: &str) -> (yes: bool)
        ensures yes == Self::parts(root).is_prefix_of(Self::parts(path));
}

pub(super) open spec fn any_below<C: Components>(paths: Seq<&str>, root: &str) -> bool {
    exists|i:int| 0 <= i < paths.len() &&
        C::parts(root).is_prefix_of(C::parts(#[trigger] paths[i]))
}

fn includes_grant<C: Components>(paths: &[&str], root: &str) -> (found: bool)
    ensures found == any_below::<C>(paths@, root),
{
    let mut i = 0;
    while i < paths.len()
        invariant
            i <= paths.len(),
            forall|j:int| 0 <= j < i ==>
                !C::parts(root).is_prefix_of(C::parts(#[trigger] paths@[j])),
        decreases paths.len() - i,
    {
        if C::below(paths[i], root) { return true; }
        i = i.saturating_add(1);
    }
    false
}

pub(super) struct Rules<'a> {
    pub(super) hidden: &'a [&'a str],
    pub(super) ancestors: &'a [&'a str],
    pub(super) writable_root: &'a str,
    pub(super) extra_reads: &'a [&'a str],
    pub(super) injections: &'a [&'a str],
    pub(super) extra_writes: &'a [&'a str],
}

impl<'a> Rules<'a> {
    pub(super) open spec fn scoped<C: Components>(&self, root: &str) -> bool {
        C::parts(root).is_prefix_of(C::parts(self.writable_root)) ||
        any_below::<C>(self.extra_reads@, root) ||
        any_below::<C>(self.extra_writes@, root) ||
        any_below::<C>(self.injections@, root)
    }

    pub(super) open spec fn classified<C: Components>(&self) -> Seq<(&'a str, bool)> {
        self.hidden@.map(|_, path| (path, self.scoped::<C>(path)))
    }

    /// Containing-root denies precede explicit child grants. All other denies follow them.
    fn partition_hidden<C: Components>(&self) -> (groups: (Vec<&'a str>, Vec<&'a str>))
        ensures groups.0@ == hidden_group(self.classified::<C>(), true, self.hidden@.len()),
                groups.1@ == hidden_group(self.classified::<C>(), false, self.hidden@.len()),
    {
        reveal(hidden_group);
        let mut scoped = Vec::new();
        let mut trailing = Vec::new();
        let mut i = 0;
        while i < self.hidden.len()
            invariant
                i <= self.hidden.len(),
                scoped@ == hidden_group(self.classified::<C>(), true, i as nat),
                trailing@ == hidden_group(self.classified::<C>(), false, i as nat),
            decreases self.hidden.len() - i,
        {
            reveal(hidden_group);
            let path = self.hidden[i];
            let grant_below = C::below(self.writable_root, path) ||
                includes_grant::<C>(self.extra_reads, path) ||
                includes_grant::<C>(self.extra_writes, path) ||
                includes_grant::<C>(self.injections, path);
            if grant_below { scoped.push(path); } else { trailing.push(path); }
            i = i.saturating_add(1);
        }
        (scoped, trailing)
    }

    pub(super) open spec fn remaining_rules<C: Components>(&self) -> Seq<char> {
        let scoped = hidden_group(self.classified::<C>(), true, self.hidden@.len());
        let trailing = hidden_group(self.classified::<C>(), false, self.hidden@.len());
        BASE_RULES@ +
        PathRule::Hide.group(scoped, scoped.len()) +
        "\n(allow file-read-metadata\n"@ +
        PathRule::Literal.group(self.ancestors@, self.ancestors@.len()) +
        "\n)\n(allow file-read*\n    (subpath \""@ +
        self.writable_root@ +
        "\")\n"@ +
        PathRule::Subpath.group(self.extra_reads@, self.extra_reads@.len()) +
        seq!['\n'] +
        PathRule::Literal.group(self.injections@, self.injections@.len()) +
        "\n)\n(allow file-write*\n    (subpath \""@ +
        self.writable_root@ +
        "\")\n"@ +
        PathRule::Subpath.group(self.extra_writes@, self.extra_writes@.len()) +
        "\n)\n"@ +
        PathRule::Hide.group(trailing, trailing.len()) +
        seq!['\n'] +
        PathRule::DenyWrite.group(self.injections@, self.injections@.len())
    }

    pub(super) fn render<C: Components>(&self, network: bool) -> (profile: String)
        ensures profile@ == HEADER@ + (if network { NETWORK@ } else { seq![] }) + self.remaining_rules::<C>(),
    {
        let (scoped, trailing) = self.partition_hidden::<C>();
        let mut profile = HEADER.to_string();
        if network { profile.push_str(NETWORK); }
        profile.push_str(BASE_RULES);
        PathRule::Hide.append_group(&mut profile, &scoped);
        profile.push_str("\n(allow file-read-metadata\n");
        PathRule::Literal.append_group(&mut profile, self.ancestors);
        profile.push_str("\n)\n(allow file-read*\n    (subpath \"");
        profile.push_str(self.writable_root);
        profile.push_str("\")\n");
        PathRule::Subpath.append_group(&mut profile, self.extra_reads);
        profile.push('\n');
        PathRule::Literal.append_group(&mut profile, self.injections);
        profile.push_str("\n)\n(allow file-write*\n    (subpath \"");
        profile.push_str(self.writable_root);
        profile.push_str("\")\n");
        PathRule::Subpath.append_group(&mut profile, self.extra_writes);
        profile.push_str("\n)\n");
        PathRule::Hide.append_group(&mut profile, &trailing);
        profile.push('\n');
        PathRule::DenyWrite.append_group(&mut profile, self.injections);
        profile
    }
}

}
