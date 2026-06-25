from boofuzz import *
import os
import subprocess
import signal
import sys

# ---------------------------------------------------------------------------
# Environment / configuration
# ---------------------------------------------------------------------------

# Provided by entrypoint.sh / run_fuzz.sh
LOG_DIR = os.environ.get("LOG_DIR", "/logs")
TARGET_IP = os.environ["TARGET_IP"]
TARGET_PORT = int(os.environ["TARGET_PORT"])

# Optional extras
TCPDUMP_INTERFACE = os.environ.get("TCPDUMP_INTERFACE", "")  # e.g. "any" or "br-lan"

# Optional ProcessMonitor configuration
PROC_MON_HOST = os.environ.get("PROC_MON_HOST")              # e.g. "192.168.56.2"
PROC_MON_PORT = int(os.environ.get("PROC_MON_PORT", "26002"))
PROC_NAME = os.environ.get("PROC_NAME")                      # e.g. "dnsmasq"
PROC_START_CMD = os.environ.get("PROC_START_CMD")            # e.g. "/etc/init.d/dnsmasq start"
PROC_STOP_CMD = os.environ.get("PROC_STOP_CMD")              # e.g. "/etc/init.d/dnsmasq stop"


# ---------------------------------------------------------------------------
# Response callback: log request/response pairs
# ---------------------------------------------------------------------------

def response_callback(target, fuzz_data_logger, session, sock, *args, **kwargs):
    """
    Store DNS request/response pairs in a text file under LOG_DIR/DNS.txt
    """
    try:
        data = sock.recv(10000)
        last_sent_request_data = session.last_send or b""

        filename = os.path.join(LOG_DIR, "DNS.txt")
        with open(filename, "a", encoding="utf-8", errors="replace") as f:
            f.write("-----------------------------\n")
            f.write("------Request-------\n")
            f.write(last_sent_request_data.decode("utf-8", errors="replace"))
            f.write("\n\n")
            f.write("------Response------\n")
            f.write(data.decode("utf-8", errors="replace"))
            f.write("\n\n")
            f.write("-----------------------------\n")

        print("DNS callback succeeded, file appended.")

    except Exception as e:
        fuzz_data_logger.log_error(f"Error receiving or logging DNS data: {e}")


# ---------------------------------------------------------------------------
# Main fuzzing logic
# ---------------------------------------------------------------------------

def main():
    os.makedirs(LOG_DIR, exist_ok=True)

    # Logging setup
    log_file = os.path.join(LOG_DIR, "FuzzingLog.txt")
    logger_text = FuzzLoggerText(file_handle=open(log_file, "w", encoding="utf-8", errors="replace"))
    logger_console = FuzzLoggerText()

    # Optional ProcessMonitor
    procmonn = None
    if PROC_MON_HOST:
        try:
            procmonn = ProcessMonitor(host=PROC_MON_HOST, port=PROC_MON_PORT)
            options = {}

            if PROC_NAME:
                options["proc_name"] = PROC_NAME

            start_commands = []
            stop_commands = []

            if PROC_START_CMD:
                start_commands.append(PROC_START_CMD)
            if PROC_STOP_CMD:
                stop_commands.append(PROC_STOP_CMD)

            if start_commands:
                options["start_commands"] = start_commands
            if stop_commands:
                options["stop_commands"] = stop_commands

            if options:
                procmonn.set_options(**options)

        except Exception as e:
            print(f"[!] Could not initialize ProcessMonitor: {e}", file=sys.stderr)
            procmonn = None

    # Session / target
    session = Session(
        fuzz_loggers=[logger_text, logger_console],
        target=Target(
            connection=UDPSocketConnection(
                TARGET_IP,
                TARGET_PORT,
                bind=("0.0.0.0", 0),
            ),
            procmon=procmonn,
        ),
        post_test_case_callbacks=[response_callback],
    )

    # -----------------------------------------------------------------------
    # DNS query definition (simple A query for google.com)
    # -----------------------------------------------------------------------
    s_initialize("DNS_query")

    # Header
    s_word(0x4256, name="TransactionID", endian=">")
    s_word(0x0100, name="Flags")                    # standard query
    s_word(1, name="Questions", endian=">")         # 1 question
    s_word(0, name="Answer", endian=">", fuzzable=False)
    s_word(0, name="Authority", endian=">", fuzzable=False)
    s_word(0, name="Additional", endian=">", fuzzable=False)

    # Question section
    if s_block_start("queries"):
        # QNAME: "google"
        s_size("name", length=1, fuzzable=False)
        if s_block_start("name"):
            s_string("google")
        s_block_end()

        # QNAME: "com"
        s_size("domain", length=1, fuzzable=False)
        if s_block_start("domain"):
            s_string("com")
        s_block_end()

        # End of QNAME
        s_group("end", values=[b"\x00", b"\xc0\xb0"])

        # QTYPE and QCLASS
        s_word(0x0001, name="Type", endian=">")   # Type: A
        s_word(0x0001, name="Class", endian=">")  # Class: IN
    s_block_end()

    # NOTE: The original script attempted s_repeat with s_mirror(Questions),
    # but that wasn't working as intended. For now, we stick to a single
    # question. Consider investigating the possibility for multi-question 
    # DNS packets later, and possibly revisiting and fixing that logic explicitly.

    # -----------------------------------------------------------------------
    # tcpdump capture (optional)
    # -----------------------------------------------------------------------
    tcpdump_process = None
    if TCPDUMP_INTERFACE:
        pcap_path = os.path.join(LOG_DIR, "dns-session.pcap")
        tcpdump_cmd = [
            "tcpdump",
            "-i", TCPDUMP_INTERFACE,
            "host", TARGET_IP,
            "and", "port", str(TARGET_PORT),
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

    # -----------------------------------------------------------------------
    # Run fuzzing
    # -----------------------------------------------------------------------
    try:
        session.connect(s_get("DNS_query"))
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
