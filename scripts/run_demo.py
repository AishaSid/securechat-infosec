#!/usr/bin/env python3
"""Run server and client demo in-process for a single handshake and print output.

This starts the server in a background thread (it accepts one connection),
then runs the client to connect to it. Useful for capturing demo output in one
terminal when working inside this environment.
"""

import sys
import pathlib
import threading
import time

# ensure project root on sys.path when run as script
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app import server, client


def run_server():
    server.main()


def main():
    t = threading.Thread(target=run_server, daemon=True)
    t.start()
    # give server a moment to start
    time.sleep(0.5)
    # run client (will connect to server and perform handshake)
    client.main()
    # wait for server thread to finish handling the connection
    t.join(timeout=2)


if __name__ == "__main__":
    main()
