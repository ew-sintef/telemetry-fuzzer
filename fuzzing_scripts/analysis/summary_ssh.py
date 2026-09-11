import os


def capped_score(count, max_points):
    """
    Convert an event count into a capped score.

    0 events      -> 0%
    1 event       -> 25%
    2-9 events    -> 50%
    10-99 events  -> 75%
    100+ events   -> 100%
    """

    if count <= 0:
        return 0

    if count == 1:
        return max(1, round(max_points * 0.25))

    if count < 10:
        return max(1, round(max_points * 0.50))

    if count < 100:
        return max(1, round(max_points * 0.75))

    return max_points


def summarize(session_dir):

    findings = []
    recommendations = []
    score = 0

    fuzz_log = os.path.join(
        session_dir,
        "FuzzingLog.txt"
    )

    if not os.path.exists(fuzz_log):

        return {
            "findings": [
                "FuzzingLog.txt not found."
            ],
            "score": 0,
            "recommendations": [
                "Verify that the fuzzing session completed successfully."
            ]
        }

    counts = {
        "target_connection_reset": 0,
        "target_unavailable": 0,
        "target_restart": 0,
        "connection_refused": 0,
        "socket_error": 0,
        "timeout": 0,
        "exception": 0,
        "check_failed": 0,
        "target_crashed": 0,
        "procmon": 0,
        "service_disruption": 0,
    }

    #
    # Detect:
    #
    # Target connection reset
    #     ->
    # Cannot connect to target
    #

    recent_reset = False

    with open(
        fuzz_log,
        "r",
        encoding="utf-8",
        errors="ignore"
    ) as f:

        for line in f:

            lower = line.lower()

            #
            # Skip giant packet dump lines.
            #

            if "transmitted " in lower:
                continue

            #
            # Reset disruption tracking
            # on new testcase.
            #

            if "test case:" in lower:
                recent_reset = False

            #
            # Connection reset
            #

            if "target connection reset" in lower:

                counts["target_connection_reset"] += 1
                recent_reset = True
                continue

            #
            # Service unavailable
            #

            if "cannot connect to target" in lower:

                counts["target_unavailable"] += 1

                if recent_reset:
                    counts["service_disruption"] += 1
                    recent_reset = False

                continue

            #
            # Restart attempts
            #

            if "restarting target" in lower:

                counts["target_restart"] += 1
                continue

            #
            # Connection refused
            #

            if "connection refused" in lower:

                counts["connection_refused"] += 1
                continue

            #
            # Timeouts
            #

            if (
                "timeout" in lower
                or "timed out" in lower
            ):

                counts["timeout"] += 1
                continue

            #
            # Socket errors
            #

            if "socket error" in lower:

                counts["socket_error"] += 1
                continue

            #
            # Exceptions
            #

            if (
                "unexpected exception" in lower
                or "traceback" in lower
                or "exception:" in lower
            ):

                counts["exception"] += 1
                continue

            #
            # Failed checks
            #

            if "check failed" in lower:

                counts["check_failed"] += 1
                continue

            #
            # Confirmed crashes
            #

            if (
                (
                    "target crashed" in lower
                    or "crash detected" in lower
                )
                and
                "no crash detected" not in lower
            ):

                counts["target_crashed"] += 1
                continue

            #
            # Process monitor indicators
            #

            if (
                "procmon" in lower
                or "process monitor" in lower
                or "crash synopsis" in lower
                or "target down" in lower
            ):

                counts["procmon"] += 1

    #
    # Capped scoring model
    #

    scoring = {

        "target_connection_reset": {
            "max_score": 10,
            "description": "target connection resets - not uncommon for malformed SSH inputs."
        },

        "target_unavailable": {
            "max_score": 25,
            "description": "target unavailable events"
        },

        "target_restart": {
            "max_score": 50,
            "description": "target restart attempts"
        },

        "connection_refused": {
            "max_score": 20,
            "description": "connection refusals"
        },

        "socket_error": {
            "max_score": 30,
            "description": "socket errors"
        },

        "timeout": {
            "max_score": 15,
            "description": "timeouts"
        },

        "exception": {
            "max_score": 75,
            "description": "exceptions"
        },

        "check_failed": {
            "max_score": 100,
            "description": "failed monitor checks"
        },

        "target_crashed": {
            "max_score": 250,
            "description": "confirmed crashes"
        },

        "procmon": {
            "max_score": 100,
            "description": "ProcessMonitor indicators"
        },

        "service_disruption": {
            "max_score": 75,
            "description": "service disruption events"
        },
    }

    for key, config in scoring.items():

        count = counts[key]

        if not count:
            continue

        contribution = capped_score(
            count,
            config["max_score"]
        )

        findings.append(
            f"{count} {config['description']} "
            f"(Score contribution: {contribution})"
        )

        score += contribution

    #
    # Recommendations
    #

    if counts["service_disruption"]:
        recommendations.append("Review test cases that caused connection resets followed by loss of service availability.")

    if counts["target_restart"]:
        recommendations.append("Investigate why the service required repeated restarts.")

    if counts["target_crashed"]:
        recommendations.append("Prioritize reproduction and root-cause analysis of crash-inducing test cases.")

    if counts["exception"]:
        recommendations.append("Inspect exception paths and failed protocol handling logic.")

    #
    # Verdict guidance
    #

    if score == 0:
        findings.append("No significant SSH stability issues detected.")
        recommendations.append("Consider expanding SSH protocol coverage (KEX algorithms, authentication paths, MACs and compression methods).")

    elif score < 20:
        findings.append("Only minor SSH anomalies detected.")

    elif score < 50:
        findings.append("Low-impact SSH stability issues detected.")

    elif score < 100:
        findings.append("Moderate SSH stability issues detected.")

    elif score < 200:
        recommendations.append("High-value finding(s) detected. Review affected test cases.")

    else:
        recommendations.append("Critical findings detected. Prioritize reproduction and root-cause analysis.")

    return {
        "findings": findings,
        "score": score,
        "recommendations": recommendations
    }
