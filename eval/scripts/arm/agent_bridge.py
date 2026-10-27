#!/usr/bin/env python3
"""Runs on the control host. Listens on 127.0.0.1:PORT; for each connection it starts pi_agent.py on the Pi over ssh and
relays bytes both ways. A host that cannot ssh to the Pi (the flood host) reaches the agent through
`ssh -R PORT:127.0.0.1:PORT flood-host`.

  agent_bridge.py PORT user@pi
"""

import os
import socket
import subprocess
import sys
import threading

AGENT_COMMAND = ["sudo", "taskset", "-c", "3", "python3", "/mnt/arm/scripts/arm/pi_agent.py"]


def pump(read, write, close) -> None:
    try:
        while chunk := read(65536):
            write(chunk)
    except OSError:
        pass
    finally:
        close()


def serve(connection: socket.socket, target: str) -> None:
    agent = subprocess.Popen(["ssh", "-o", "BatchMode=yes", target, *AGENT_COMMAND], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, bufsize=0)

    def to_agent(chunk: bytes) -> None:
        agent.stdin.write(chunk)

    threads = [
        threading.Thread(target=pump, args=(connection.recv, to_agent, agent.stdin.close)),
        threading.Thread(target=pump, args=(lambda size: os.read(agent.stdout.fileno(), size), connection.sendall,
                                            lambda: connection.shutdown(socket.SHUT_RDWR))),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    agent.kill()
    connection.close()


def main() -> None:
    port, target = int(sys.argv[1]), sys.argv[2]
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(4)
    while True:
        connection, _ = listener.accept()
        threading.Thread(target=serve, args=(connection, target), daemon=True).start()


if __name__ == "__main__":
    main()
