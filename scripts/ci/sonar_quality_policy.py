"""Fail closed on findings; permit only non-worsening, inherited main coverage debt."""

from __future__ import annotations

from decimal import Decimal, InvalidOperation

REQUIRED_METRICS = {
    "new_reliability_rating",
    "new_security_rating",
    "new_maintainability_rating",
    "new_duplicated_lines_density",
    "new_security_hotspots_reviewed",
}


def number(value: object) -> Decimal:
    """Reject missing, nonnumeric and nonfinite API measurements."""
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError("Missing or invalid Sonar measurement")
    try:
        result = Decimal(value)
    except InvalidOperation as error:
        raise ValueError("Invalid Sonar measurement") from error
    if not result.is_finite():
        raise ValueError("Nonfinite Sonar measurement")
    return result


def conditions(gate: dict) -> dict[str, dict]:
    """Require complete, unambiguous gate results, including security findings."""
    if gate.get("status") not in {"OK", "ERROR"} or not isinstance(gate.get("conditions"), list):
        raise ValueError("Sonar gate is missing or incomplete")
    result = {}
    for condition in gate["conditions"]:
        if not isinstance(condition, dict):
            raise ValueError("Malformed Sonar condition")
        metric = condition.get("metricKey")
        if not isinstance(metric, str) or not metric or len(metric) > 128 or metric in result:
            raise ValueError("Duplicate or invalid Sonar metric")
        if condition.get("status") not in {"OK", "ERROR"}:
            raise ValueError("Sonar condition has not completed")
        if condition.get("comparator") not in {"LT", "GT"}:
            raise ValueError("Unknown Sonar comparator")
        actual, threshold = number(condition.get("actualValue")), number(condition.get("errorThreshold"))
        maximums = {
            "new_reliability_rating": 1,
            "new_security_rating": 1,
            "new_maintainability_rating": 1,
            "new_duplicated_lines_density": 3,
        }
        if metric in maximums and (condition["comparator"] != "GT" or threshold > maximums[metric]):
            raise ValueError("Security or quality threshold was weakened")
        minimums = {"new_security_hotspots_reviewed": 100, "new_coverage": 80}
        if metric in minimums and (condition["comparator"] != "LT" or threshold < minimums[metric]):
            raise ValueError("Coverage or hotspot review threshold was weakened")
        failed = actual < threshold if condition["comparator"] == "LT" else actual > threshold
        if failed != (condition["status"] == "ERROR"):
            raise ValueError("Inconsistent Sonar condition")
        result[metric] = condition
    if not result.keys() >= REQUIRED_METRICS:
        raise ValueError("Required security or quality conditions are missing")
    if (gate["status"] == "ERROR") != any(c["status"] == "ERROR" for c in result.values()):
        raise ValueError("Inconsistent Sonar gate status")
    return result


def inherited_coverage_allowed(current: dict, baseline: dict) -> bool:
    """A red coverage ancestor is debt, not permission for a further regression.

    Callers must bind every compared ancestor to the authenticated main-push
    history. PRs, releases and manual runs remain strict.
    """
    current_conditions, previous_conditions = conditions(current), conditions(baseline)
    failures = {key for key, value in current_conditions.items() if value["status"] == "ERROR"}
    previous_failures = {key for key, value in previous_conditions.items() if value["status"] == "ERROR"}
    if failures != {"new_coverage"} or previous_failures != {"new_coverage"}:
        return False
    if current.get("ignoredConditions") is not False or baseline.get("ignoredConditions") is not False:
        return False
    periods = current.get("periods")
    if not isinstance(periods, list) or len(periods) != 1 or periods != baseline.get("periods"):
        return False
    if not isinstance(periods[0], dict) or not all(periods[0].get(key) for key in ("index", "mode", "date")):
        return False
    if current_conditions.keys() != previous_conditions.keys():
        return False
    for metric, condition in current_conditions.items():
        previous = previous_conditions[metric]
        if any(condition.get(key) != previous.get(key) for key in ("comparator", "errorThreshold", "periodIndex")):
            return False
    coverage, previous_coverage = current_conditions["new_coverage"], previous_conditions["new_coverage"]
    threshold = number(coverage["errorThreshold"])
    actual, old_actual = number(coverage["actualValue"]), number(previous_coverage["actualValue"])
    return (
        coverage["comparator"] == "LT"
        and Decimal(80) <= threshold <= Decimal(100)
        and Decimal(0) <= old_actual <= actual <= Decimal(100)
    )
