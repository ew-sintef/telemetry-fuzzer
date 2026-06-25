from boofuzz import *
import os
import subprocess
import signal
import re
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
PROC_NAME = os.environ.get("PROC_NAME")                      # e.g. "opensips" / "asterisk"
PROC_START_CMD = os.environ.get("PROC_START_CMD")            # e.g. "/etc/init.d/sipd start"
PROC_STOP_CMD = os.environ.get("PROC_STOP_CMD")              # e.g. "/etc/init.d/sipd stop"

status_code_counts = {}


# ---------------------------------------------------------------------------
# Helpers for SIP status codes
# ---------------------------------------------------------------------------

def parse_sip_response(data: bytes):
    """
    Parse SIP status code from a response line like:
      SIP/2.0 200 OK
    Returns "200" or None if not found.
    """
    match = re.search(rb"SIP/\d\.\d\s+(\d{3})", data)
    if match:
        return match.group(1).decode("utf-8", errors="replace")
    return None


def print_status_code_dict():
    for key, value in status_code_counts.items():
        print(key, value)


def save_status_code_counts():
    filename = os.path.join(LOG_DIR, "status_code_counts.txt")
    try:
        with open(filename, "w", encoding="utf-8", errors="replace") as f:
            for code, count in status_code_counts.items():
                f.write(f"{code}: {count}\n")
    except Exception as e:
        print(f"[!] Error writing status code counts: {e}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Response callback
# ---------------------------------------------------------------------------

def response_callback(target, fuzz_data_logger, session, sock, *args, **kwargs):
    """
    Called after each test case to record whether we got a SIP response and
    which status code (if any). Keeps counts per code and writes them to a file.
    """

    try:
        data = sock.recv(10000)
        status_code = parse_sip_response(data)

        if status_code:
            print(f"Parsed SIP status code: {status_code}")
            status_code_counts[status_code] = status_code_counts.get(status_code, 0) + 1
        else:
            print("No answer received")
            status_code_counts["ERROR"] = status_code_counts.get("ERROR", 0) + 1

        print_status_code_dict()
        save_status_code_counts()

    except Exception as e:
        fuzz_data_logger.log_error(f"Error receiving SIP data: {e}")


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
        target=Target(
            connection=UDPSocketConnection(
                TARGET_IP,
                TARGET_PORT,
                bind=("0.0.0.0", 0),
            ),
            procmon=procmonn,
        ),
        fuzz_loggers=[logger_console, logger_text],
        post_test_case_callbacks=[response_callback],
    )

    # -----------------------------------------------------------------------
    # SIP INVITE structure (based on your original script)
    # -----------------------------------------------------------------------
    s_initialize(name="SIP Invite")
    with s_block("Invite"):
        s_string("INVITE", fuzzable=False)
        s_delim(" ", fuzzable=False)
        s_string("sip:")
        s_string("user")
        s_delim("@")
        s_string("example.com", fuzzable=True)  # Domain
        s_string(" SIP/2.0\r\n", fuzzable=False)

        s_string("Via: SIP/2.0/UDP ", fuzzable=False)
        s_string("client.example.com:5060;branch=", fuzzable=False)
        s_string("z9hG4bK776asdhds", fuzzable=True)  # Branch
        s_static("\r\n")

        s_string("Max-Forwards: ", fuzzable=False)
        s_string("70", fuzzable=True)  # Max-Forwards
        s_static("\r\n")

        s_string("From: ", fuzzable=False)
        s_string('"Fuzzer" <sip:', fuzzable=False)
        s_string("fuzzer@example.com", fuzzable=True)  # From
        s_string(">;tag=12345\r\n", fuzzable=False)

        s_string("To: ", fuzzable=False)
        s_string('"Target" <sip:', fuzzable=False)
        s_string("target@example.com", fuzzable=True)  # To
        s_string(">\r\n", fuzzable=False)

        s_string("Call-ID: ", fuzzable=False)
        s_string("123456789@client.example.com", fuzzable=True)  # Call-ID
        s_static("\r\n")

        s_string("CSeq: ", fuzzable=False)
        s_int(1, fuzzable=True, output_format="ascii")
        s_string(" INVITE", fuzzable=True)  # CSeq
        s_static("\r\n")

        s_string("Contact: ", fuzzable=False)
        s_string("<sip:", fuzzable=False)
        s_string("fuzzer@client.example.com", fuzzable=True)  # Contact
        s_string(">\r\n", fuzzable=False)

        s_string("Content-Type: ", fuzzable=False)
        s_string("application/sdp", fuzzable=True)  # Content-Type
        s_static("\r\n")

        s_string("Content-Length: ", fuzzable=False)
        s_size("body", fuzzable=False, endian=">", output_format="ascii")  # Content-Length
        s_static("\r\n\r\n")

        if s_block_start("body"):
            s_static("v=0\r\n")
            s_static("o=")
            s_string("user1 53655765 2353687637")
            s_static(" IN IP4 ")
            s_string("client.example.com")
            s_static("\r\n")
            s_static("s=-\r\n")
            s_static("c=IN IP4 client.example.com\r\n")
            s_static("t=0 0\r\n")
            s_static("m=audio 1234 ")
            s_string("RTP/AVP 0")
            s_static("\r\n")
            s_static("a=rtpmap:0 PCMU/8000\r\n")
        s_block_end()

    # -----------------------------------------------------------------------
    # tcpdump capture (optional)
    # -----------------------------------------------------------------------
    tcpdump_process = None
    if TCPDUMP_INTERFACE:
        pcap_path = os.path.join(LOG_DIR, "sip-session.pcap")
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
        session.connect(s_get("SIP Invite"))
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
