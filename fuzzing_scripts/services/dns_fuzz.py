from boofuzz import *
import os
import subprocess
import signal
import sys
import datetime
import socket

# ---------------------------------------------------------------------------
# Environment / configuration
# ---------------------------------------------------------------------------

LOG_DIR = os.environ.get("LOG_DIR", "/logs")
TARGET_IP = os.environ["TARGET_IP"]
TARGET_PORT = int(os.environ["TARGET_PORT"])

TCPDUMP_INTERFACE = os.environ.get("TCPDUMP_INTERFACE", "")

PROC_MON_HOST = os.environ.get("PROC_MON_HOST")
PROC_MON_PORT = int(os.environ.get("PROC_MON_PORT", "26002"))
PROC_NAME = os.environ.get("PROC_NAME")
PROC_START_CMD = os.environ.get("PROC_START_CMD")
PROC_STOP_CMD = os.environ.get("PROC_STOP_CMD")

# ---------------------------------------------------------------------------
# DNS helpers
# ---------------------------------------------------------------------------

rcode_counts = {}

DNS_RCODES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}


def parse_dns_header(data):
    """
    Parse useful DNS header fields.

    DNS header is 12 bytes minimum.
    """

    if not data or len(data) < 12:
        return None

    txid = int.from_bytes(data[0:2], "big")
    flags = int.from_bytes(data[2:4], "big")

    qr = (flags >> 15) & 0x1
    aa = (flags >> 10) & 0x1
    tc = (flags >> 9) & 0x1
    rcode = flags & 0xF

    return {
        "txid": txid,
        "qr": qr,
        "aa": aa,
        "tc": tc,
        "rcode": rcode,
        "rcode_name": DNS_RCODES.get(
            rcode,
            f"RCODE_{rcode}"
        )
    }


def save_rcode_counts():
    filename = os.path.join(LOG_DIR, "dns_rcode_counts.txt")

    with open(filename, "w", encoding="utf-8") as f:
        for code in sorted(rcode_counts.keys()):
            f.write(f"{code}: {rcode_counts[code]}\n")


def write_log_file(filename, request_data, response_data, metadata=None):

    path = os.path.join(LOG_DIR, filename)

    timestamp = datetime.datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S:%f"
    )

    with open(path, "a", encoding="utf-8", errors="replace") as f:

        f.write("-----------------------------\n")
        f.write(f"Time: {timestamp}\n")

        if metadata:
            for key, value in metadata.items():
                f.write(f"{key}: {value}\n")

        f.write("------Request-------\n")

        if request_data:
            f.write(request_data.hex())
        else:
            f.write("<empty>")

        f.write("\n\n")
        f.write("------Response------\n")

        if response_data:
            f.write(response_data.hex())
        else:
            f.write("NO_RESPONSE")

        f.write("\n\n")
        f.write("-----------------------------\n")


# ---------------------------------------------------------------------------
# Response callback
# ---------------------------------------------------------------------------

def response_callback(target, fuzz_data_logger, session, sock, *args, **kwargs):

    request_data = session.last_send or b""

    try:

        response_data = sock.recv(65535)

        header = parse_dns_header(response_data)

        if header is None:

            write_log_file(
                "MALFORMED.txt",
                request_data,
                response_data,
                {
                    "Failure": "Malformed DNS response"
                }
            )

            return

        rcode = header["rcode_name"]

        rcode_counts[rcode] = (
            rcode_counts.get(rcode, 0) + 1
        )

        save_rcode_counts()

        metadata = {
            "TransactionID": f"0x{header['txid']:04X}",
            "Length": len(response_data),
            "QR": header["qr"],
            "AA": header["aa"],
            "TC": header["tc"],
            "RCODE": rcode,
        }

        #
        # Main categorized log
        #

        write_log_file(
            f"{rcode}.txt",
            request_data,
            response_data,
            metadata
        )

        #
        # Truncated responses
        #

        if header["tc"] == 1:

            write_log_file(
                "TRUNCATED.txt",
                request_data,
                response_data,
                metadata
            )

    except socket.timeout:

        write_log_file(
            "NO_RESPONSE.txt",
            request_data,
            b"",
            {
                "Failure": "TIMEOUT"
            }
        )

    except Exception as e:

        write_log_file(
            "MALFORMED.txt",
            request_data,
            b"",
            {
                "Exception": str(e)
            }
        )

        fuzz_data_logger.log_error(
            f"Error receiving or logging DNS data: {e}"
        )


# ---------------------------------------------------------------------------
# Main fuzzing logic
# ---------------------------------------------------------------------------

def main():

    os.makedirs(LOG_DIR, exist_ok=True)

    log_file = os.path.join(LOG_DIR, "FuzzingLog.txt")

    logger_text = FuzzLoggerText(
        file_handle=open(
            log_file,
            "w",
            encoding="utf-8",
            errors="replace"
        )
    )

    logger_console = FuzzLoggerText()

    procmonn = None

    if PROC_MON_HOST:

        try:

            procmonn = ProcessMonitor(
                host=PROC_MON_HOST,
                port=PROC_MON_PORT
            )

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

            print(
                f"[!] Could not initialize ProcessMonitor: {e}",
                file=sys.stderr
            )

            procmonn = None

    session = Session(
        fuzz_loggers=[
            logger_text,
            logger_console
        ],
        target=Target(
            connection=UDPSocketConnection(
                TARGET_IP,
                TARGET_PORT,
                bind=("0.0.0.0", 0),
            ),
            procmon=procmonn,
        ),
        post_test_case_callbacks=[
            response_callback
        ],
    )

    # -----------------------------------------------------------------------
    # DNS Query
    # -----------------------------------------------------------------------

    s_initialize("DNS_query")

    s_word(
        0x4256,
        name="TransactionID",
        endian=">"
    )

    s_word(
        0x0100,
        name="Flags"
    )

    s_word(
        1,
        name="Questions",
        endian=">"
    )

    s_word(
        0,
        name="Answer",
        endian=">",
        fuzzable=False
    )

    s_word(
        0,
        name="Authority",
        endian=">",
        fuzzable=False
    )

    s_word(
        0,
        name="Additional",
        endian=">",
        fuzzable=False
    )

    if s_block_start("queries"):

        s_size(
            "name",
            length=1,
            fuzzable=False
        )

        if s_block_start("name"):
            s_string("google")
        s_block_end()

        s_size(
            "domain",
            length=1,
            fuzzable=False
        )

        if s_block_start("domain"):
            s_string("com")
        s_block_end()

        s_group(
            "end",
            values=[
                b"\x00",
                b"\xc0\xb0"
            ]
        )

        s_word(
            0x0001,
            name="Type",
            endian=">"
        )

        s_word(
            0x0001,
            name="Class",
            endian=">"
        )

    s_block_end()

    # -----------------------------------------------------------------------
    # Optional tcpdump
    # -----------------------------------------------------------------------

    tcpdump_process = None

    if TCPDUMP_INTERFACE:

        pcap_path = os.path.join(
            LOG_DIR,
            "dns-session.pcap"
        )

        tcpdump_cmd = [
            "tcpdump",
            "-i",
            TCPDUMP_INTERFACE,
            "host",
            TARGET_IP,
            "and",
            "port",
            str(TARGET_PORT),
            "-w",
            pcap_path,
        ]

        try:

            tcpdump_process = subprocess.Popen(
                tcpdump_cmd
            )

            print(
                f"[*] tcpdump started on "
                f"{TCPDUMP_INTERFACE}, "
                f"writing to {pcap_path}"
            )

        except FileNotFoundError:

            print(
                "[!] tcpdump not found, "
                "skipping pcap capture.",
                file=sys.stderr
            )

            tcpdump_process = None

        except Exception as e:

            print(
                f"[!] Failed to start tcpdump: {e}",
                file=sys.stderr
            )

            tcpdump_process = None

    # -----------------------------------------------------------------------
    # Run fuzzing
    # -----------------------------------------------------------------------

    try:
        session.connect(s_get("DNS_query"))
        session.fuzz(max_depth=1)

    except KeyboardInterrupt:
        print("Ctrl+C pressed, stopping fuzzing.")

    except EOFError:
        print("EOF received, stopping fuzzing.")

    except Exception as e:
        print(f"Unexpected exception: {e}")

    finally:
        if tcpdump_process is not None:
            try:
                tcpdump_process.send_signal(signal.SIGINT)
                tcpdump_process.wait()
            except Exception as e:
                print(f"[!] Error stopping tcpdump: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
