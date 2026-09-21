import argparse
import json
import os

from summary_http import summarize as summarize_http
from summary_dns import summarize as summarize_dns
from summary_ssh import summarize as summarize_ssh

from summary_common import (
    determine_verdict,
    determine_confidence,
    scan_target_logs,
    load_json,
)

def deduplicate_preserve_order(items):
    """
    Remove duplicates while preserving order.
    """

    return list(dict.fromkeys(items))


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--session",
        required=True,
    )

    args = parser.parse_args()

    session_dir = args.session

    metadata = load_json(
        os.path.join(
            session_dir,
            "session_metadata.json"
        )
    )

    protocol = metadata.get(
        "protocol",
        "unknown"
    )

    findings = []
    recommendations = []

    score = 0

    indicators = {
        "strong": 0,
        "moderate": 0
    }

    if protocol == "http":
        result = summarize_http(session_dir)

    elif protocol == "dns":
        result = summarize_dns(session_dir)

    elif protocol == "ssh":
        result = summarize_ssh(session_dir)

    else:
        result = {
            "findings": [],
            "score": 0,
            "recommendations": []
        }

    findings.extend(result["findings"])
    recommendations.extend(result["recommendations"])

    score += result["score"]

    target_results = scan_target_logs(
        os.path.join(
            session_dir,
            "target_logs"
        )
    )

    findings.extend(
        target_results["findings"]
    )

    recommendations.extend(
        target_results["recommendations"]
    )

    score += target_results["score"]

    indicators = target_results["indicators"]

    #
    # Remove duplicates while preserving order
    #

    findings = deduplicate_preserve_order(
        findings
    )

    recommendations = deduplicate_preserve_order(
        recommendations
    )



    verdict = determine_verdict(score)

    confidence = determine_confidence(
        indicators
    )

    report = {
        "protocol": protocol,
        "score": score,
        "verdict": verdict,
        "confidence": confidence,
        "findings": findings,
        "recommendations": recommendations
    }

    with open(
        os.path.join(session_dir, "summary.json"),
        "w",
    ) as f:
        json.dump(report, f, indent=2)

    with open(
        os.path.join(session_dir, "summary.txt"),
        "w"
    ) as f:

        f.write("=======================\n")
        f.write("FUZZING SESSION SUMMARY\n")
        f.write("=======================\n\n")

        f.write(f"Session: {session_dir}\n\n")

        f.write(f"Protocol: {protocol}\n")
        f.write(f"Verdict : {verdict}\n")
        f.write(f"Confidence: {confidence}\n")
        f.write(f"Score   : {score}\n\n")

        f.write("Findings:\n")

        if findings:
            for item in findings:
                f.write(f" - {item}\n")
        else:
            f.write(" - No significant findings detected\n")

        f.write("\nRecommendations:\n")

        if recommendations:
            for item in recommendations:
                f.write(f" - {item}\n")
        else:
            f.write(" - No specific recommendations.\n")

    with open(
        os.path.join(session_dir, "summary.md"),
        "w",
    ) as f:

        f.write("# Fuzzing Session Summary\n\n")
        f.write(f"Session: {session_dir}\n\n")
        f.write(f"Protocol: {protocol}\n\n")
        f.write(f"Verdict: **{verdict}**\n\n")
        f.write(f"Confidence: {confidence}\n")
        f.write(f"Score: {score}\n\n")

        f.write("## Findings\n\n")

        if findings:
            for item in findings:
                f.write(f"- {item}\n")
        else:
            f.write("- No significant findings detected\n")

        f.write("\n## Recommendations\n\n")

        if recommendations:
            for item in recommendations:
                f.write(f"- {item}\n")
        else:
            f.write("- No specific recommendations.\n")


if __name__ == "__main__":
    main()
