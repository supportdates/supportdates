"""Published support policies of upstream projects that have no dated release lines, checked by hand at the
primary source (date and URLs kept). Used to say *why* a component has no end-of-support date, instead of
"not covered". Re-check before relying on an entry older than ~6 months.

Each entry: SBOM name pattern (lowercase, full match), status, statement, checked date, URLs checked.
  status 'rule'      the project publishes a support rule but no dates per release line
  status 'partial'   the project says who gets fixes, but no period or dates
  status 'no-policy' no support period found at the listed URLs on the checked date
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Policy:
    pattern: str
    project: str
    status: str
    statement: str
    checked: str
    urls: tuple[str, ...]


POLICIES = [
    Policy(r"rust|rustc|cargo|rust-std", "Rust", "rule",
           "only provides support and security updates for the most recent stable release", "2026-10-19",
           ("https://www.rust-lang.org/policies/security",)),
    Policy(r"go|golang|go-runtime", "Go", "rule",
           "Each major Go release is supported until there are two newer major releases.", "2026-10-19",
           ("https://go.dev/doc/devel/release",)),
    Policy(r"protobuf|libprotobuf\d*|protobuf-c?", "Protocol Buffers", "rule",
           "Releasing a new minor version immediately ends support for the previous minor version.", "2026-10-19",
           ("https://protobuf.dev/support/version-support/",)),
    Policy(r"libressl", "LibreSSL", "rule",
           "stable branches are updated for 1 year after their corresponding OpenBSD branch is tagged for release",
           "2026-10-19", ("https://www.libressl.org/releases.html",)),
    Policy(r"sqlite3?|libsqlite3[\w-]*", "SQLite", "rule",
           "The intent of the developers is to support SQLite through the year 2050.", "2026-10-19",
           ("https://sqlite.org/lts.html",)),
    Policy(r"qt[56]?-?(base|declarative|tools|multimedia|webengine|serialport|svg|wayland)\w*", "Qt", "rule",
           "Starting with version 6.8.0, the LTS versions are supported for five years.", "2026-10-19",
           ("https://doc.qt.io/qt-6/qt-releases.html",)),
    Policy(r"curl|libcurl\d*", "curl", "partial",
           "Low or Medium severity vulnerability reports restricted to releases older than three years are out of "
           "scope", "2026-10-19", ("https://curl.se/dev/vuln-disclosure.html",)),
    Policy(r"nginx(-[\w-]+)?", "nginx", "partial",
           "Security fixes will be applied to all supported stable releases, as well as the mainline version",
           "2026-10-19", ("https://raw.githubusercontent.com/nginx/nginx/master/SECURITY.md",)),
    Policy(r"musl", "musl", "partial", "releases page labels the 1.1 series 'End-of-life'; no period stated",
           "2026-10-19", ("https://musl.libc.org/", "https://musl.libc.org/releases.html")),
    Policy(r"expat|libexpat\d*", "Expat", "no-policy",
           "README warns: 'Expat has unfixed security issues!'", "2026-10-19",
           ("https://raw.githubusercontent.com/libexpat/libexpat/master/expat/README.md",)),
    Policy(r"dnsmasq(-[\w-]+)?", "dnsmasq", "no-policy", "", "2026-10-19",
           ("https://thekelleys.org.uk/dnsmasq/doc.html",)),
    Policy(r"wpa[-_]supplicant|hostapd|wpad(-[\w-]+)?", "hostapd/wpa_supplicant", "no-policy", "", "2026-10-19",
           ("https://w1.fi/wpa_supplicant/", "https://w1.fi/security/")),
    Policy(r"iptables(-[\w-]+)?|libiptc\d*|libxtables\d*", "iptables", "no-policy", "", "2026-10-19",
           ("https://netfilter.org/projects/iptables/", "https://netfilter.org/security/")),
    Policy(r"nftables(-[\w-]+)?", "nftables", "no-policy", "", "2026-10-19",
           ("https://netfilter.org/projects/nftables/", "https://netfilter.org/security/")),
    Policy(r"mosquitto(-[\w-]+)?|libmosquitto\d*", "Mosquitto", "no-policy", "", "2026-10-19",
           ("https://mosquitto.org/security/",)),
    Policy(r"lighttpd(-[\w-]+)?", "lighttpd", "no-policy", "", "2026-10-19", ("https://www.lighttpd.net/",)),
    Policy(r"rauc", "RAUC", "no-policy", "", "2026-10-19", ("https://raw.githubusercontent.com/rauc/rauc/master/README.rst",)),
    Policy(r"swupdate", "SWUpdate", "no-policy", "", "2026-10-19",
           ("https://raw.githubusercontent.com/sbabic/swupdate/master/README.md",)),
    Policy(r"boost|libboost[\w-]*", "Boost", "no-policy", "", "2026-10-19", ("https://www.boost.org/",)),
    Policy(r"busybox", "BusyBox", "no-policy", "", "2026-10-19", ("https://busybox.net/", "https://busybox.net/FAQ.html")),
    Policy(r"zlib", "zlib", "no-policy", "", "2026-10-19", ("https://zlib.net/",)),
    Policy(r"dropbear", "Dropbear", "no-policy", "", "2026-10-19",
           ("https://matt.ucc.asn.au/dropbear/dropbear.html",)),
    Policy(r"openssh|openssh-\w+", "OpenSSH", "no-policy", "", "2026-10-19", ("https://www.openssh.com/security.html",)),
    Policy(r"u-boot|uboot|u-boot-\w+", "U-Boot", "no-policy",
           "release cadence only (about every 3 months), no support period", "2026-10-19",
           ("https://docs.u-boot.org/en/latest/develop/release_cycle.html",)),
]


def basis(policy: Policy) -> str:
    """Addendum text for a component without dated lines."""
    if policy.status in ("rule", "partial"):
        kind = "a rule" if policy.status == "rule" else "a partial policy"
        return f"{policy.project} publishes {kind}, no dates per line: '{policy.statement}' (checked {policy.checked})"
    extra = f"; {policy.statement}" if policy.statement else ""
    return f"{policy.project}: no support period found at the URLs checked on {policy.checked}{extra}"
