import os

def summarize(session_dir):

    findings = []
    recommendations = []
    score = 0

    rcode_file = os.path.join(
        session_dir,
        "dns_rcode_counts.txt"
    )

    if os.path.exists(rcode_file):

        counts = {}

        with open(
            rcode_file,
            encoding="utf-8",
            errors="ignore"
        ) as f:

            for line in f:

                line = line.strip()

                if not line or ":" not in line:
                    continue

                try:
                    code, count = line.split(":", 1)

                    counts[code.strip()] = int(
                        count.strip()
                    )

                except Exception:
                    continue

        findings.append(
            "DNS response distribution:\n"
            f"  - NOERROR = {counts.get('NOERROR',0)}\n"
            f"  - NXDOMAIN = {counts.get('NXDOMAIN',0)}\n"
            f"  - SERVFAIL = {counts.get('SERVFAIL',0)}\n"
            f"  - REFUSED = {counts.get('REFUSED',0)}"
        )

        servfail = counts.get("SERVFAIL", 0)

        if servfail:

            findings.append(
                f"SERVFAIL responses detected "
                f"({servfail})"
            )

            score += 20

            recommendations.append(
                "Inspect DNS daemon logs for parsing "
                "or backend resolver failures."
            )

        refused = counts.get("REFUSED", 0)

        if refused:

            findings.append(
                f"REFUSED responses detected "
                f"({refused})"
            )

            score += 5

        return {
            "findings": findings,
            "score": score,
            "recommendations": recommendations
        }

    #
    # Backward compatibility
    #

    dns_log = os.path.join(
        session_dir,
        "DNS.txt"
    )

    if os.path.exists(dns_log):

        text = open(
            dns_log,
            errors="ignore"
        ).read().lower()

        timeout_count = text.count("timeout")
        malformed_count = text.count("malformed")

        if timeout_count:

            findings.append(
                f"{timeout_count} timeout indications"
            )

            score += timeout_count * 2

        if malformed_count:

            findings.append(
                f"{malformed_count} malformed responses"
            )

            score += malformed_count * 5

    return {
        "findings": findings,
        "score": score,
        "recommendations": recommendations
    }
