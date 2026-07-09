package i18n

// Message IDs for CONST-046 migrated call sites in this submodule.
// Conventions:
//   - prefix `security_` namespaces this submodule.
//   - <subpkg>_<file>_<purpose> identifies the call site.
//   - English default strings are NOT stored here — they live in
//     a consumer-supplied bundle file (e.g. YAML); NoopTranslator
//     returns the message ID verbatim when no consumer is wired.
const (
	// Scanner package
	MsgScannerReportSummary = "security_scanner_report_summary"

	// Security package — privilege-escalation scan
	MsgPrivescPrivContainerDesc              = "security_privesc_priv_container_desc"
	MsgPrivescPrivContainerUnknownProcStatus = "security_privesc_priv_container_unknown_proc_status"
	MsgPrivescPrivContainerFullCaps          = "security_privesc_priv_container_full_caps"
	MsgPrivescPrivContainerOK                = "security_privesc_priv_container_ok"
	MsgPrivescWritableRootDesc               = "security_privesc_writable_root_desc"
	MsgPrivescWritableRootFail               = "security_privesc_writable_root_fail"
	MsgPrivescWritableRootOK                 = "security_privesc_writable_root_ok"
	MsgPrivescDangerousCapsDesc              = "security_privesc_dangerous_caps_desc"
	MsgPrivescDangerousCapsUnknownProcStatus = "security_privesc_dangerous_caps_unknown_proc_status"
	MsgPrivescDangerousCapsFail              = "security_privesc_dangerous_caps_fail"
	MsgPrivescDangerousCapsOK                = "security_privesc_dangerous_caps_ok"
	MsgPrivescHostNamespaceDesc              = "security_privesc_host_namespace_desc"
	MsgPrivescHostNamespaceUnknownCgroup     = "security_privesc_host_namespace_unknown_cgroup"
	MsgPrivescHostNamespaceFail              = "security_privesc_host_namespace_fail"
	MsgPrivescHostNamespaceOK                = "security_privesc_host_namespace_ok"
	MsgPrivescSUIDDesc                       = "security_privesc_suid_desc"
	MsgPrivescSUIDFail                       = "security_privesc_suid_fail"
	MsgPrivescSUIDOK                         = "security_privesc_suid_ok"
)
