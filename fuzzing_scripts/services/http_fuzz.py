from boofuzz import *
import re
import socket
import os
import datetime
import sys
import subprocess
import signal

# ---------------------------------------------------------------------------
# Environment / configuration
# ---------------------------------------------------------------------------

# These are provided by entrypoint.sh / run_fuzz.sh
LOG_DIR = os.environ.get("LOG_DIR", "/logs")
TARGET_IP = os.environ["TARGET_IP"]
TARGET_PORT = int(os.environ["TARGET_PORT"])

# Optional extras:
TCPDUMP_INTERFACE = os.environ.get("TCPDUMP_INTERFACE", "")  # e.g. "any" or "eth0"

# Optional ProcessMonitor configuration (if you have procmon running)
PROC_MON_HOST = os.environ.get("PROC_MON_HOST")              # e.g. "192.168.56.2"
PROC_MON_PORT = int(os.environ.get("PROC_MON_PORT", "26002"))
PROC_NAME = os.environ.get("PROC_NAME")                      # e.g. "uhttpd"
PROC_START_CMD = os.environ.get("PROC_START_CMD")            # e.g. "/etc/init.d/uhttpd start"
PROC_STOP_CMD = os.environ.get("PROC_STOP_CMD")              # e.g. "/etc/init.d/uhttpd stop"

status_code_counts = {}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def parse_http_response(data: bytes):
    """
    Parse HTTP status code from a raw HTTP response.
    Returns string like "200" or None if not found.
    """
    match = re.search(rb'HTTP/[0-9.]+\s+(\d{3})', data)
    if match:
        return match.group(1).decode("utf-8", errors="replace")
    return None


def print_status_code_dict():
    for key, value in status_code_counts.items():
        print(key, value)


def save_status_code_counts():
    filename = os.path.join(LOG_DIR, "status_code_counts.txt")
    try:
        with open(filename, "w") as f:
            for code, count in status_code_counts.items():
                f.write(f"{code}: {count}\n")
    except Exception as e:
        print(f"[!] Error writing status code counts: {e}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Response callback
# ---------------------------------------------------------------------------

def response_callback(target, fuzz_data_logger, session, sock, *args, **kwargs):
    """
    Called after each test case to grab the HTTP response, log it by status code,
    and maintain per-status counters.
    """

    try:
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S:%f")
        data = sock.recv(10000)

        status_code = parse_http_response(data)
        last_sent_request_data = session.last_send or b""

        if status_code:
            # Update counts
            status_code_counts[status_code] = status_code_counts.get(status_code, 0) + 1

            filename = os.path.join(LOG_DIR, f"{status_code}.txt")
            try:
                with open(filename, "a", encoding="utf-8", errors="replace") as f:
                    f.write("-----------------------------\n")
                    f.write(f"Time: {current_time}\n")
                    f.write("------Request-------\n")
                    f.write(last_sent_request_data.decode("utf-8", errors="replace"))
                    f.write("\n\n")
                    f.write("------Response------\n")
                    f.write(data.decode("utf-8", errors="replace"))
                    f.write("\n\n")
                    f.write("-----------------------------\n")
            except Exception as e:
                fuzz_data_logger.log_error(f"Error writing status-code log: {e}")

            print(f"Received status code {status_code}: {status_code_counts[status_code]} times")
            print_status_code_dict()
            save_status_code_counts()

        else:
            # No status code found – log to a separate file
            filename = os.path.join(LOG_DIR, "no_response.txt")
            try:
                with open(filename, "a", encoding="utf-8", errors="replace") as f:
                    f.write("-----------------------------\n")
                    f.write(f"Time: {current_time}\n")
                    f.write("------Request-------\n")
                    f.write(last_sent_request_data.decode("utf-8", errors="replace"))
                    f.write("\n\n")
                    f.write("------Response------\n")
                    f.write(data.decode("utf-8", errors="replace"))
                    f.write("\n\n")
                    f.write("-----------------------------\n")
            except Exception as e:
                fuzz_data_logger.log_error(f"Error writing no-response data: {e}")

    except Exception as e:
        fuzz_data_logger.log_error(f"Error receiving or processing data: {e}")


# ---------------------------------------------------------------------------
# Main fuzzing logic
# ---------------------------------------------------------------------------

def main():
    # Ensure log dir exists
    os.makedirs(LOG_DIR, exist_ok=True)

    log_file = os.path.join(LOG_DIR, "FuzzingLog.txt")

    # Set up boofuzz loggers
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

    # Build the fuzzing session
    session = Session(
        fuzz_loggers=[logger_text, logger_console],
        target=Target(
            connection=SocketConnection(
                TARGET_IP,
                TARGET_PORT,
                proto="tcp",
            ),
            procmon=procmonn,
        ),
        post_test_case_callbacks=[response_callback],
    )

    # -----------------------------------------------------------------------
    # HTTP request definition
    # -----------------------------------------------------------------------
    s_initialize("Request")
    with s_block("request-line"):
        s_group(
            "method",
            values=["GET", "HEAD", "POST", "OPTIONS", "DELETE"],
        )

        if s_block_start("body", group="method"):
            s_delim(" ", fuzzable=False)
            s_string("index.html")
            s_delim(" ", fuzzable=True)
            s_static("HTTP")
            s_delim("/", fuzzable=True)
            s_float(1.1, s_format=".1f")
            s_static("\r\n")
        s_block_end()

        # Host header
        s_static("Host")
        s_delim(":", fuzzable=True)
        s_delim(" ", fuzzable=True)
        s_string(TARGET_IP, fuzzable=False)
        s_static("\r\n")

        # Connection header
        s_static("Connection")
        s_delim(":", fuzzable=False)
        s_delim(" ", fuzzable=False)
        s_string("Keep-Alive", fuzzable=True)
        s_static("\r\n")

        # User-Agent
        s_static("User-Agent")
        s_delim(":", fuzzable=False)
        s_delim(" ", fuzzable=False)
        s_string(
            "Mozilla/5.0 (Windows NT 6.1; WOW64) "
            "AppleWebKit/537.1 (KHTML, like Gecko) "
            "Chrome/21.0.1180.83 Safari/537.1",
            fuzzable=True,
        )
        s_static("\r\n")

        # Accept
        s_static("Accept")
        s_delim(":", fuzzable=False)
        s_delim(" ", fuzzable=False)
        s_string("text", fuzzable=False)
        s_delim("/", fuzzable=True)
        s_string("html", fuzzable=False)
        s_delim(",", fuzzable=False)
        s_string("application", fuzzable=False)
        s_delim("/", fuzzable=False)
        s_string("xhtml", fuzzable=True)
        s_delim("+", fuzzable=False)
        s_string("xml", fuzzable=False)
        s_delim(",", fuzzable=False)
        s_string("application", fuzzable=False)
        s_delim("/", fuzzable=False)
        s_string("xml", fuzzable=False)
        s_delim(";", fuzzable=True)
        s_string("q", fuzzable=False)
        s_delim("=", fuzzable=False)
        s_int(0, output_format="ascii", fuzzable=True)
        s_delim(".", fuzzable=False)
        s_int(9, output_format="ascii", fuzzable=False)
        s_delim(",", fuzzable=False)
        s_string("*", fuzzable=True)
        s_delim("/", fuzzable=False)
        s_string("*", fuzzable=False)
        s_delim(";", fuzzable=False)
        s_string("q", fuzzable=False)
        s_delim("=", fuzzable=True)
        s_float(0.8, s_format=".1f")
        s_static("\r\n")

        # Accept-Encoding
        s_static("Accept-Encoding")
        s_delim(":", fuzzable=False)
        s_delim(" ", fuzzable=False)
        s_string("gzip", fuzzable=False)
        s_delim(",", fuzzable=False)
        s_string("deflate", fuzzable=False)
        s_delim(",", fuzzable=False)
        s_string("sdch", fuzzable=False)
        s_static("\r\n")

        # Accept-Language
        s_static("Accept-Language")
        s_delim(":", fuzzable=False)
        s_delim(" ", fuzzable=False)
        s_string("en-US", fuzzable=False)
        s_delim(",", fuzzable=False)
        s_string("en", fuzzable=False)
        s_delim(";", fuzzable=False)
        s_string("q", fuzzable=False)
        s_delim("=", fuzzable=False)
        s_string("0.8", fuzzable=True)
        s_static("\r\n")

        # Accept-Charset
        s_static("Accept-Charset")
        s_delim(":", fuzzable=False)
        s_delim(" ", fuzzable=False)
        s_string("ISO", fuzzable=False)
        s_delim("-", fuzzable=False)
        s_int(8859, output_format="ascii", fuzzable=False)
        s_delim("-", fuzzable=False)
        s_int(1, output_format="ascii", fuzzable=False)
        s_delim(",", fuzzable=False)
        s_string("utf-8")
        s_delim(";", fuzzable=False)
        s_string("q", fuzzable=False)
        s_delim("=", fuzzable=True)
        s_int(0, output_format="ascii", fuzzable=False)
        s_delim(".", fuzzable=False)
        s_int(7, output_format="ascii", fuzzable=False)
        s_delim(",", fuzzable=False)
        s_string("*", fuzzable=False)
        s_delim(";", fuzzable=True)
        s_string("q", fuzzable=True)
        s_delim("=", fuzzable=False)
        s_int(0, output_format="ascii", fuzzable=False)
        s_delim(".", fuzzable=False)
        s_int(3, output_format="ascii", fuzzable=False)
        s_static("\r\n")

    # End of headers
    s_static("\r\n")

    # -----------------------------------------------------------------------
    # tcpdump capture (optional)
    # -----------------------------------------------------------------------
    tcpdump_process = None
    if TCPDUMP_INTERFACE:
        pcap_path = os.path.join(LOG_DIR, "session.pcap")
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
        session.connect(s_get("Request"))
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
