import json
import os
import re


def load_json(path):
    if not os.path.exists(path):
        return {}

    with open(path, "r") as f:
        return json.load(f)


def determine_verdict(score):

    if score >= 200:
        return "CRITICAL"

    if score >= 100:
        return "HIGH_PRIORITY"

    if score >= 50:
        return "REVIEW_RECOMMENDED"

    if score >= 20:
        return "LOW_PRIORITY"

    return "NO_IMMEDIATE_INDICATION"


def determine_confidence(indicators):

    strong = indicators.get("strong", 0)
    moderate = indicators.get("moderate", 0)

    if strong:
        return "HIGH"

    if moderate:
        return "MEDIUM"

    return "LOW"


def scan_target_logs(target_log_dir):

    findings = []
    recommendations = []

    score = 0

    indicators = {
        "strong": 0,
        "moderate": 0
    }

    if not os.path.isdir(target_log_dir):

        return {
            "findings": [],
            "score": 0,
            "recommendations": [],
            "indicators": indicators
        }

    #
    # Strong crash indicators
    #
    strong_patterns = {
        "kernel panic": 100,
        "segfault": 80,
        "oops": 60,
        "assert": 40,
        "crash": 30
    }

    aggregated = {}

    for keyword in strong_patterns:
        aggregated[keyword] = {
            "count": 0,
            "files": set()
        }

    watchdog_count = 0
    watchdog_files = set()

    restart_events = 0
    restart_files = set()
    services_restarted = set()

    restart_regex = re.compile(
        r"restarting service:\s+(.+?)\s+restart",
        re.IGNORECASE
    )

    for root, _, files in os.walk(target_log_dir):

        for filename in files:

            path = os.path.join(root, filename)

            try:

                text = open(
                    path,
                    "r",
                    errors="ignore"
                ).read()

                lower_text = text.lower()

                #
                # Strong indicators
                #
                for keyword in strong_patterns:

                    count = lower_text.count(keyword)

                    if count:
                        aggregated[keyword]["count"] += count
                        aggregated[keyword]["files"].add(
                            filename
                        )

                #
                # Watchdog presence
                #
                #wd_count = lower_text.count("watchdog")
                wd_count = lower_text.count("failure threshold reached")

                if wd_count:
                    watchdog_count += wd_count
                    watchdog_files.add(filename)

                #
                # Explicit restart events
                #
                matches = restart_regex.findall(text)

                if matches:

                    restart_events += len(matches)

                    restart_files.add(filename)

                    for service in matches:
                        services_restarted.add(
                            service.strip()
                        )

            except Exception:
                pass

    #
    # Strong crash indicators
    #
    for keyword, result in aggregated.items():

        if result["count"] == 0:
            continue

        findings.append(
            f"{keyword} detected "
            f"({result['count']} occurrence(s) "
            f"in {len(result['files'])} file(s))"
        )

        score += strong_patterns[keyword]

        indicators["strong"] += 1

    #
    # Restart behaviour analysis
    #
    if restart_events:

        service_list = ", ".join(
            sorted(services_restarted)
        )

        findings.append(
            f"Explicit service restart events detected - "
            f"{restart_events} restart event(s) "
            f"across {len(restart_files)} file(s)."
        )

        if service_list:
            findings.append(
                f"Affected service(s): {service_list}"
            )

        indicators["moderate"] += 1

        if restart_events > 100:
            score += 20

            findings.append(
                "Repeated restart behaviour indicates possible service instability."
            )

        elif restart_events > 10:
            score += 10

        else:
            score += 5

    #
    # Watchdog activity
    #
    if watchdog_count:

        findings.append(
            f"Watchdog activity detected "
            f"({watchdog_count} occurrence(s) "
            f"in {len(watchdog_files)} file(s))"
        )

        score += 10
        indicators["moderate"] += 1

    #
    # Recommendations
    #
    recommendation_added = False

    if indicators["strong"]:

        recommendations.append(
            "Investigate crash indicators immediately."
        )

        recommendations.append(
            "Review logs around the first crash event."
        )

        recommendation_added = True

    if restart_events:

        recommendations.append(
            "Review logs around restart events."
        )

        recommendations.append(
            "Investigate why the service required repeated restarts."
        )

        recommendation_added = True

    if watchdog_count:

        recommendations.append(
            "Review watchdog activity for signs of service instability."
        )

        recommendation_added = True

    if not recommendation_added:

        findings.append(
            "No significant target-side crash indicators detected."
        )

    return {
        "findings": findings,
        "score": score,
        "recommendations": recommendations,
        "indicators": indicators
    }
