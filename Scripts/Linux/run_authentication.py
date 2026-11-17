"""Authentication coverage using disposable OpenSSH servers and ssh-agent."""
import os
from pathlib import Path
import signal
import socket
import subprocess
import time


def run(build, root, port):
    executable = str(build / "outerssh-authentication-test")
    missing_agent = str(root / "no-agent")

    def check(mode, credential, expected="success", passphrase="", agent=missing_agent, ssh_port=port):
        subprocess.run([executable, str(ssh_port), "outerssh-test", mode, str(credential),
                        passphrase, agent, expected], check=True, timeout=30)

    check("password", "outerssh-test-password")
    check("password", "incorrect", "failure")
    for expected in ("reject", "cancel", "delayed"):
        check("password", "outerssh-test-password", expected)
    check("key", root / "client")
    for name, kind, passphrase in (("rsa", "rsa", ""), ("ecdsa", "ecdsa", ""),
                                  ("encrypted", "ed25519", "test phrase"),
                                  ("unauthorized", "ed25519", "")):
        subprocess.run(["ssh-keygen", "-q", "-t", kind, "-N", passphrase,
                        "-a", "2", "-f", str(root / name)], check=True)
        if name != "unauthorized":
            with (root / "client.pub").open("a") as authorized:
                authorized.write((root / f"{name}.pub").read_text())
        check("key", root / name, "failure" if name == "unauthorized" else "success", passphrase)
    check("key-public", root / "encrypted", passphrase="test phrase")
    check("key-public", root / "encrypted", "failure", "wrong")
    check("key", root / "encrypted", "failure", "wrong")
    check("key", root / "encrypted", "failure")
    check("agent", "unused", "failure")

    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(root / "ca")], check=True)
    subprocess.run(["ssh-keygen", "-q", "-s", str(root / "ca"), "-I", "authentication-test",
                    "-n", "outerssh-test", "-V", "-1m:+10m", str(root / "rsa.pub")], check=True)
    with (root / "client.pub").open("a") as authorized:
        authorized.write("cert-authority " + (root / "ca.pub").read_text())
    check("key-cert", root / "rsa")

    agent_path = str(root / "agent.sock")
    agent = subprocess.Popen(["ssh-agent", "-D", "-a", agent_path],
                             stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        for _ in range(100):
            if Path(agent_path).exists():
                break
            time.sleep(0.01)
        env = dict(os.environ, SSH_AUTH_SOCK=agent_path)
        subprocess.run(["ssh-add", str(root / "unauthorized"), str(root / "rsa")],
                       env=env, check=True, capture_output=True)
        check("agent", "unused", agent=agent_path)
        authorized_keys = (root / "client.pub").read_text()
        # Require the agent's certificate identity, rather than its plain RSA key.
        (root / "client.pub").write_text(authorized_keys.replace((root / "rsa.pub").read_text(), ""))
        try:
            check("agent", "unused", agent=agent_path)
        finally:
            (root / "client.pub").write_text(authorized_keys)
        subprocess.run(["ssh-add", "-d", str(root / "rsa")], env=env, check=True, capture_output=True)
        check("agent", "unused", "failure", agent=agent_path)
        check("key", root / "client", agent=agent_path)
    finally:
        agent.terminate()
        agent.communicate(timeout=5)

    with socket.socket() as reserve:
        reserve.bind(("127.0.0.1", 0))
        keyboard_port = reserve.getsockname()[1]
    config = (root / "sshd_config").read_text().replace(f"Port {port}", f"Port {keyboard_port}")
    config = config.replace("UsePAM no", "UsePAM yes").replace("PasswordAuthentication yes", "PasswordAuthentication no")
    config = config.replace("KbdInteractiveAuthentication no", "KbdInteractiveAuthentication yes")
    (root / "keyboard_config").write_text(config)
    with (root / "keyboard.log").open("w+") as log:
        server = subprocess.Popen(["/usr/sbin/sshd", "-D", "-e", "-f", str(root / "keyboard_config")],
                                  stdout=log, stderr=log, start_new_session=True)
        try:
            for _ in range(100):
                try:
                    with socket.create_connection(("127.0.0.1", keyboard_port), timeout=0.1):
                        break
                except OSError:
                    time.sleep(0.02)
            check("password", "outerssh-test-password", ssh_port=keyboard_port)
            check("password", "incorrect", "failure", ssh_port=keyboard_port)
        finally:
            os.killpg(server.pid, signal.SIGTERM)
            server.wait(timeout=5)
    print("PASS: password, keyboard-interactive, Ed25519/ECDSA/RSA, encrypted keys, ssh-agent identities and fallback, rejection, cancellation, delayed host approval")
