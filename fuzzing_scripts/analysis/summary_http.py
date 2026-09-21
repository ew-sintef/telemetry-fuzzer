import os


def summarize(session_dir):

    findings = []

    score = 0

    status_file = os.path.join(
        session_dir,
        "status_code_counts.txt"
    )

    if not os.path.exists(status_file):

        return {
            "findings": findings,
            "score": score,
            "recommendations": []
        }

    groups = {
        "2xx": 0,
        "3xx": 0,
        "4xx": 0,
        "5xx": 0
    }

    with open(status_file) as f:

        for line in f:

            line = line.strip()

            if not line:
                continue

            try:

                code, count = line.split(":")
                code = code.strip()
                count = int(count.strip())

            except Exception:
                continue

            if code.startswith("2"):
                groups["2xx"] += count

            elif code.startswith("3"):
                groups["3xx"] += count

            elif code.startswith("4"):
                groups["4xx"] += count

            elif code.startswith("5"):
                groups["5xx"] += count

    findings.append(
        "HTTP response distribution:\n"
        f"   - 2xx = {groups['2xx']}\n"
        f"   - 3xx = {groups['3xx']}\n"
        f"   - 4xx = {groups['4xx']}\n"
        f"   - 5xx = {groups['5xx']}"
    )

    if groups["5xx"]:

        findings.append(
            f"Server-side error responses detected - "
            f"{groups['5xx']} 5xx responses"
        )

        score += 30

    if groups["4xx"]:

        findings.append(
            f"Client error responses detected (expected for malformed requests) - "
            f"{groups['4xx']} 4xx responses"
        )

        score += 0

    recommendations = []

    if groups["5xx"]:

        recommendations.append(
            "Review server logs for internal errors."
        )

    return {
        "findings": findings,
        "score": score,
        "recommendations": recommendations
    }
