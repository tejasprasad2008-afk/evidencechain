"""Enumerations for EvidenceChain forensic data types."""

from enum import Enum


class ArtifactType(str, Enum):
    """Types of forensic artifacts that can be extracted from evidence."""

    # Disk artifacts
    SHIMCACHE = "shimcache"
    PREFETCH = "prefetch"
    AMCACHE = "amcache"
    MFT_ENTRY = "mft_entry"
    USNJRNL = "usnjrnl"
    EVTX_EVENT = "evtx_event"
    REGISTRY_KEY = "registry_key"
    FILESYSTEM_ENTRY = "filesystem_entry"
    TIMELINE_EVENT = "timeline_event"
    SRUM_ENTRY = "srum_entry"

    # Memory artifacts
    MEMORY_PROCESS = "memory_process"
    MEMORY_NETWORK = "memory_network"
    MEMORY_MALFIND = "memory_malfind"
    MEMORY_SERVICE = "memory_service"
    MEMORY_CMDLINE = "memory_cmdline"
    MEMORY_DUMP = "memory_dump"

    # Enrichment artifacts
    YARA_HIT = "yara_hit"
    FILE_HASH = "file_hash"
    THREAT_INTEL = "threat_intel"


class EvidenceSemantics(str, Enum):
    """What a piece of evidence can prove, suggest, or cannot prove."""

    # Provable facts
    PRESENCE = "presence"
    EXECUTION = "execution"
    NETWORK_CONNECTION = "network_connection"
    USER_INTERACTION = "user_interaction"
    PERSISTENCE = "persistence"
    FILE_MODIFICATION = "file_modification"
    KNOWN_MALWARE = "known_malware"
    KNOWN_C2_INFRASTRUCTURE = "known_c2_infrastructure"

    # Suggestions (not proof)
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"
    CREDENTIAL_ACCESS = "credential_access"
    LIVING_OFF_THE_LAND = "living_off_the_land"
    PREVIOUSLY_UNSEEN = "previously_unseen"
    CODE_INJECTION = "code_injection"
    TIMESTOMPING = "timestomping"
    LOG_CLEARING = "log_clearing"

    # Explicitly unprovable
    MALICIOUS_INTENT = "malicious_intent"
    INTERACTIVE_SESSION = "interactive_session"
    PROCESS_CURRENTLY_RUNNING = "process_currently_running"
    CONNECTION_ACTIVE_NOW = "connection_active_now"


class FindingCategory(str, Enum):
    """Categories of investigative findings."""

    MALWARE_EXECUTION = "malware_execution"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE = "persistence"
    DATA_EXFILTRATION = "data_exfiltration"
    CREDENTIAL_ACCESS = "credential_access"
    DEFENSE_EVASION = "defense_evasion"
    ANTI_FORENSICS = "anti_forensics"
    COMMAND_AND_CONTROL = "command_and_control"
    INITIAL_ACCESS = "initial_access"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    RECONNAISSANCE = "reconnaissance"
    BENIGN_ACTIVITY = "benign_activity"


class FindingStatus(str, Enum):
    """Lifecycle status of a forensic finding."""

    DRAFT = "draft"
    CONFIRMED = "confirmed"
    RETRACTED = "retracted"
    UNDER_REVIEW = "under_review"


class EvidenceType(str, Enum):
    """How strongly evidence supports a finding."""

    DIRECT = "direct"
    CORROBORATED = "corroborated"
    CIRCUMSTANTIAL = "circumstantial"
    INFERRED = "inferred"


class Severity(str, Enum):
    """Severity levels for contradictions and findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ContradictionPattern(str, Enum):
    """Types of contradictions the self-correction engine detects."""

    TIMESTAMP_PARADOX = "timestamp_paradox"
    EXECUTION_OVERCLAIM = "execution_overclaim"
    GHOST_PROCESS = "ghost_process"
    TIMELINE_GAP = "timeline_gap"
    ATTRIBUTION_MISMATCH = "attribution_mismatch"
    ANTI_FORENSIC_INDICATOR = "anti_forensic_indicator"
    PHANTOM_ARTIFACT = "phantom_artifact"


class ContradictionResolution(str, Enum):
    """How a contradiction was resolved."""

    UNRESOLVED = "unresolved"
    RESOLVED_ATOM_A_CORRECT = "resolved_atom_a_correct"
    RESOLVED_ATOM_B_CORRECT = "resolved_atom_b_correct"
    RESOLVED_BOTH_VALID = "resolved_both_valid"
    RESOLVED_ANTI_FORENSICS = "resolved_anti_forensics_detected"
    ESCALATED = "escalated_to_analyst"


class ThreatIntelVerdict(str, Enum):
    """Verdict from threat intelligence sources."""

    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    CLEAN = "clean"
    UNKNOWN = "unknown"
    NOT_FOUND = "not_found"


class ThreatIntelSource(str, Enum):
    """Supported threat intelligence sources."""

    VIRUSTOTAL = "virustotal"
    ABUSEIPDB = "abuseipdb"
    MALWAREBAZAAR = "malwarebazaar"
    LOLBAS = "lolbas"
    ALIENVAULT_OTX = "alienvault_otx"


class TimestampSemanticType(str, Enum):
    """Semantic meaning of a timestamp in a forensic artifact."""

    CREATED = "created"
    MODIFIED = "modified"
    ACCESSED = "accessed"
    MFT_MODIFIED = "mft_modified"
    ENTRY_MODIFIED = "entry_modified"
    LAST_RUN = "last_run"
    FIRST_RUN = "first_run"
    EVENT_TIME = "event_time"
    PROCESS_START = "process_start"
    PROCESS_EXIT = "process_exit"
    CONNECTION_TIME = "connection_time"


class ToolStatus(str, Enum):
    """Status of a tool execution."""

    SUCCESS = "success"
    ERROR = "error"
    PARTIAL = "partial"
