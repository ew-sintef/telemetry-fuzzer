from boofuzz import *
import os
import subprocess
import signal
import sys
import json
import datetime

# ---------------------------------------------------------------------------
# Environment / configuration
# ---------------------------------------------------------------------------

# These are provided by entrypoint.sh / run_fuzz.sh
LOG_DIR = os.environ.get("LOG_DIR", "/logs")
TARGET_IP = os.environ["TARGET_IP"]
TARGET_PORT = int(os.environ["TARGET_PORT"])

# Optional extras:
TCPDUMP_INTERFACE = os.environ.get("TCPDUMP_INTERFACE", "")  # e.g. "any" or "eth0"

# Optional ProcessMonitor configuration (if you run procmon somewhere)
PROC_MON_HOST = os.environ.get("PROC_MON_HOST")              # e.g. "192.168.56.2"
PROC_MON_PORT = int(os.environ.get("PROC_MON_PORT", "26002"))
PROC_NAME = os.environ.get("PROC_NAME")                      # e.g. "dropbear"
PROC_START_CMD = os.environ.get("PROC_START_CMD")            # e.g. "/etc/init.d/dropbear start"
PROC_STOP_CMD = os.environ.get("PROC_STOP_CMD")              # e.g. "/etc/init.d/dropbear stop"

# Control whether KEX algorithm lists are fuzzable
# "1", "true", "yes" -> True
FUZZ_ALGORITHMS = os.environ.get("FUZZ_SSH_ALGORITHMS", "1").lower() in (
    "1",
    "true",
    "yes",
    "y",
)


# ---------------------------------------------------------------------------
# Session metadata
# ---------------------------------------------------------------------------

def write_session_info():

    info = {
        "target_ip": TARGET_IP,
        "target_port": TARGET_PORT,
        "start_time": datetime.datetime.utcnow().isoformat(),
        "fuzz_algorithms": FUZZ_ALGORITHMS,
        "tcpdump_interface": TCPDUMP_INTERFACE,
        "procmon_enabled": bool(PROC_MON_HOST),
        "proc_name": PROC_NAME,
    }

    filename = os.path.join(
        LOG_DIR,
        "ssh_session_info.json"
    )

    try:

        with open(
            filename,
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                info,
                f,
                indent=2
            )

    except Exception as e:

        print(
            f"[!] Failed writing ssh_session_info.json: {e}",
            file=sys.stderr
        )


# ---------------------------------------------------------------------------
# Main fuzzing logic
# ---------------------------------------------------------------------------

def main():

    os.makedirs(LOG_DIR, exist_ok=True)

    write_session_info()

    # Logging setup

    log_file = os.path.join(
        LOG_DIR,
        "FuzzingLog.txt"
    )

    logger_file = FuzzLoggerText(
        file_handle=open(
            log_file,
            "w",
            encoding="utf-8",
            errors="replace"
        )
    )

    logger_console = FuzzLoggerText()

    # -----------------------------------------------------------------------
    # Optional ProcessMonitor
    # -----------------------------------------------------------------------

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
                start_commands.append(
                    PROC_START_CMD
                )

            if PROC_STOP_CMD:
                stop_commands.append(
                    PROC_STOP_CMD
                )

            if start_commands:
                options["start_commands"] = start_commands

            if stop_commands:
                options["stop_commands"] = stop_commands

            if options:
                procmonn.set_options(
                    **options
                )

        except Exception as e:

            print(
                f"[!] Could not initialize ProcessMonitor: {e}",
                file=sys.stderr
            )

            procmonn = None

    # -----------------------------------------------------------------------
    # Target / session
    # -----------------------------------------------------------------------

    target = Target(
        connection=SocketConnection(
            TARGET_IP,
            TARGET_PORT,
            proto="tcp"
        ),
        procmon=procmonn,
    )

    session = Session(
        target=target,
        fuzz_loggers=[
            logger_file,
            logger_console
        ],
    )

    # -----------------------------------------------------------------------
    # ProtocolVersionExchange
    # -----------------------------------------------------------------------

    s_initialize(
        name="ProtocolVersionExchange"
    )

    s_static("SSH-")

    s_string(
        "2.0",
        name="protoversion",
        fuzzable=True
    )

    s_static("-")

    s_string(
        "A",
        name="softwareversion",
        fuzzable=True
    )

    s_delim(
        "_",
        fuzzable=True
    )

    s_float(
        1.1,
        s_format=".1f",
        fuzzable=True
    )

    s_static("p")

    s_int(
        1,
        fuzzable=True
    )

    s_static(" ")

    s_string(
        "SYSTEM",
        name="comments",
        fuzzable=True
    )

    s_static("\r\n")

    # -----------------------------------------------------------------------
    # KeyExchangeInitClient
    # -----------------------------------------------------------------------

    s_initialize(
        "KeyExchangeInitClient"
    )

    s_size(
        "KeyExchangeInit",
        endian=">",
        fuzzable=False
    )

    if s_block_start(
        "KeyExchangeInit"
    ):

        s_static(
            "\x07",
            name="padding length"
        )

        s_static(
            "\x14",
            name="Message Code"
        )

        s_bytes(
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            size=32,
            name="Cookie",
            fuzzable=True,
        )

        s_size(
            "kex_algorithms",
            endian=">",
            fuzzable=False
        )

        s_string(
            "aaaa,bbbbbb,cccccccc",
            name="kex_algorithms",
            fuzzable=FUZZ_ALGORITHMS
        )

        s_size(
            "server_host_key_algorithms",
            endian=">",
            fuzzable=False
        )

        s_string(
            "aaaaaa,bbbbbbbb",
            name="server_host_key_algorithms",
            fuzzable=FUZZ_ALGORITHMS
        )

        s_size(
            "encryption_algorithms_client_to_server",
            endian=">",
            fuzzable=False
        )

        s_string(
            "aaaaaaaaaaaa,bbbbbbbbbbbbbbb,ccccccccccccccc",
            name="encryption_algorithms_client_to_server",
            fuzzable=FUZZ_ALGORITHMS
        )

        s_size(
            "encryption_algorithms_server_to_client",
            endian=">",
            fuzzable=False
        )

        s_string(
            "aaaaaaaaaaaa,bbbbbbbbbbbbbbb,ccccccccccccccc",
            name="encryption_algorithms_server_to_client",
            fuzzable=FUZZ_ALGORITHMS
        )

        s_size(
            "mac_algorithms_client_to_server",
            endian=">",
            fuzzable=False
        )

        s_string(
            "aaaaaaaaaa,bbbbbbbbbbbb",
            name="mac_algorithms_client_to_server",
            fuzzable=FUZZ_ALGORITHMS
        )

        s_size(
            "mac_algorithms_server_to_client",
            endian=">",
            fuzzable=False
        )

        s_string(
            "aaaaaaaaaa,bbbbbbbbbbbb",
            name="mac_algorithms_server_to_client",
            fuzzable=FUZZ_ALGORITHMS
        )

        s_size(
            "compression_algorithms_client_to_server",
            endian=">",
            fuzzable=False
        )

        s_string(
            "aaaaaa",
            name="compression_algorithms_client_to_server",
            fuzzable=FUZZ_ALGORITHMS
        )

        s_size(
            "compression_algorithms_server_to_client",
            endian=">",
            fuzzable=False
        )

        s_string(
            "bbbbbbbbbb",
            name="compression_algorithms_server_to_client",
            fuzzable=FUZZ_ALGORITHMS
        )

        s_size(
            "languages_client_to_server",
            endian=">",
            fuzzable=False
        )

        s_string(
            "",
            name="languages_client_to_server",
            fuzzable=FUZZ_ALGORITHMS
        )

        s_size(
            "languages_server_to_client",
            endian=">",
            fuzzable=False
        )

        s_string(
            "",
            name="languages_server_to_client",
            fuzzable=FUZZ_ALGORITHMS
        )

        s_static(
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        )

    s_block_end()

    # -----------------------------------------------------------------------
    # DiffieHellmanKeyExchangeInitClient
    # -----------------------------------------------------------------------

    s_initialize(
        "DiffieHellmanKeyExchangeInitClient"
    )

    s_size(
        "DiffieHellmanKeyExchangeInit",
        endian=">",
        fuzzable=False
    )

    if s_block_start(
        "DiffieHellmanKeyExchangeInit"
    ):

        s_static("\x06")
        s_static("\x1e")

        s_size(
            "diffiehellmankey",
            endian=">",
            fuzzable=False
        )

        s_bytes(
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            name="diffiehellmankey",
        )

        s_static(
            "\x00\x00\x00\x00\x00\x00"
        )

    s_block_end()

    # -----------------------------------------------------------------------
    # Graph / state transitions
    # -----------------------------------------------------------------------

    session.connect(
        s_get("ProtocolVersionExchange")
    )

    session.connect(
        s_get("ProtocolVersionExchange"),
        s_get("KeyExchangeInitClient")
    )

    session.connect(
        s_get("KeyExchangeInitClient"),
        s_get("DiffieHellmanKeyExchangeInitClient")
    )

    # -----------------------------------------------------------------------
    # tcpdump capture (optional)
    # -----------------------------------------------------------------------

    tcpdump_process = None

    if TCPDUMP_INTERFACE:

        pcap_path = os.path.join(
            LOG_DIR,
            "session.pcap"
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

        session.fuzz(max_depth=1)

    except KeyboardInterrupt:

        print(
            "Ctrl+C pressed, stopping fuzzing."
        )

    except EOFError:

        print(
            "EOF received, stopping fuzzing."
        )

    except Exception as e:

        print(
            f"Unexpected exception: {e}"
        )

    finally:

        if tcpdump_process is not None:

            try:

                tcpdump_process.send_signal(
                    signal.SIGINT
                )

                tcpdump_process.wait()

            except Exception as e:

                print(
                    f"[!] Error stopping tcpdump: {e}",
                    file=sys.stderr
                )


if __name__ == "__main__":
    main()
