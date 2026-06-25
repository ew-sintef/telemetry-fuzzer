from boofuzz import *
import os
import subprocess
import signal
import sys

# ---------------------------------------------------------------------------
# Environment / configuration (aligned with run_fuzz.sh + entrypoint.sh)
# ---------------------------------------------------------------------------

LOG_DIR = os.environ.get("LOG_DIR", "/logs")
TARGET_IP = os.environ["TARGET_IP"]
TARGET_PORT = int(os.environ["TARGET_PORT"])

# Optional capture from inside container (disabled by default)
TCPDUMP_INTERFACE = os.environ.get("TCPDUMP_INTERFACE", "")  # e.g. "eth0"

# Optional: if your iperf server is on TCP but uses a different port, set TARGET_PORT in run_fuzz.sh prompt or targets.env

def main():
    os.makedirs(LOG_DIR, exist_ok=True)

    log_file = os.path.join(LOG_DIR, "FuzzingLog.txt")
    logger_file = FuzzLoggerText(file_handle=open(log_file, "w", encoding="utf-8", errors="replace"))
    logger_console = FuzzLoggerText()

    session = Session(
        target=Target(
            connection=SocketConnection(TARGET_IP, TARGET_PORT, proto="tcp"),
        ),
        fuzz_loggers=[logger_file, logger_console],
        session_filename=os.path.join(LOG_DIR, "session_iperf.sess"),
    )

    # -----------------------------------------------------------------------
    # Iperf payload
    # -----------------------------------------------------------------------
    s_initialize("iperf")

    # The original script intended a small set of bytes that could crash iperf.
    # FIX: use a *valid* bytes literal (no "\A" escape). You can tune this later.
    seed = b"\x80" + (b"A" * 90) + b"\xa5\xa5\xa5\xa5"

    # Make it fuzzable by boofuzz; boofuzz will mutate bytes as test cases
    s_bytes(seed, name="payload", fuzzable=True)

    # -----------------------------------------------------------------------
    # tcpdump capture (optional)
    # -----------------------------------------------------------------------
    tcpdump_process = None
    if TCPDUMP_INTERFACE:
        pcap_path = os.path.join(LOG_DIR, "iperf-session.pcap")
        tcpdump_cmd = [
            "tcpdump",
            "-i", TCPDUMP_INTERFACE,
            "host", TARGET_IP,
            "and", "port", str(TARGET_PORT),
            "-s", "0",
            "-w", pcap_path,
        ]
        try:
            tcpdump_process = subprocess.Popen(tcpdump_cmd)
            print(f"[*] tcpdump started on {TCPDUMP_INTERFACE}, writing to {pcap_path}")
        except FileNotFoundError:
            print("[!] tcpdump not found, skipping pcap capture.", file=sys.stderr)
            tcpdump_process = None
        except Exception as e:
            print(f"[!] Failed to start tcpdump: {e}", file=sys.stderr)
            tcpdump_process = None

    try:
        session.connect(s_get("iperf"))
        session.fuzz(max_depth=1)
    except KeyboardInterrupt:
        print("Ctrl+C pressed, stopping fuzzing.")
    finally:
        if tcpdump_process is not None:
            try:
                tcpdump_process.send_signal(signal.SIGINT)
                tcpdump_process.wait()
            except Exception as e:
                print(f"[!] Error stopping tcpdump: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()
