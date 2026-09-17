"""Enumerations mirrored from the SecObserve backend.

These are the values the API validates against; declaring them here turns a
would-be 400 into a schema error the agent sees before the call is made.
"""

from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    UNKNOWN = "Unknown"
    NONE = "None"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class Status(str, Enum):
    OPEN = "Open"
    AFFECTED = "Affected"
    RESOLVED = "Resolved"
    DUPLICATE = "Duplicate"
    FALSE_POSITIVE = "False positive"
    IN_REVIEW = "In review"
    NOT_AFFECTED = "Not affected"
    NOT_SECURITY = "Not security"
    RISK_ACCEPTED = "Risk accepted"


class ApprovalStatus(str, Enum):
    """The three verdicts an approver may record on a pending assessment."""

    APPROVED = "Approved"
    APPROVED_WITH_EDITS = "Approved with edits"
    REJECTED = "Rejected"


class VexJustification(str, Enum):
    COMPONENT_NOT_PRESENT = "component_not_present"
    VULNERABLE_CODE_NOT_PRESENT = "vulnerable_code_not_present"
    VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY = "vulnerable_code_cannot_be_controlled_by_adversary"
    VULNERABLE_CODE_NOT_IN_EXECUTE_PATH = "vulnerable_code_not_in_execute_path"
    INLINE_MITIGATIONS_ALREADY_EXIST = "inline_mitigations_already_exist"
    CODE_NOT_PRESENT = "code_not_present"
    CODE_NOT_REACHABLE = "code_not_reachable"
    REQUIRES_CONFIGURATION = "requires_configuration"
    REQUIRES_DEPENDENCY = "requires_dependency"
    REQUIRES_ENVIRONMENT = "requires_environment"
    PROTECTED_BY_COMPILER = "protected_by_compiler"
    PROTECTED_AT_RUNTIME = "protected_at_runtime"
    PROTECTED_AT_PERIMETER = "protected_at_perimeter"
    PROTECTED_BY_MITIGATING_CONTROL = "protected_by_mitigating_control"


class MetricsAge(str, Enum):
    """Windows accepted by the metrics timeline endpoint (it has no 'Today')."""

    WEEK = "Past 7 days"
    MONTH = "Past 30 days"
    QUARTER = "Past 90 days"
    YEAR = "Past 365 days"


class ObservationAge(str, Enum):
    """Windows accepted by the observation and product list filters."""

    TODAY = "Today"
    WEEK = "Past 7 days"
    MONTH = "Past 30 days"
    QUARTER = "Past 90 days"
    YEAR = "Past 365 days"


#: Statuses that keep an observation on the active worklist.
ACTIVE_STATUSES = (Status.OPEN, Status.AFFECTED, Status.IN_REVIEW)

#: Statuses that require a VEX justification to be meaningful in a VEX document.
JUSTIFIABLE_STATUSES = (Status.NOT_AFFECTED, Status.FALSE_POSITIVE, Status.RESOLVED)
