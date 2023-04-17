#!/usr/bin/env python
import os
import re
import sys
import json
import socket
import psutil
import getpass
import datetime
import requests
import subprocess

from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.backends import default_backend as crypto_default_backend

def githubPost(pat, public_key, private_key):
    print("Deploying the newly created public key on Github...")
    url = "https://api.github.com/user/keys"
    data = {"title": socket.gethostname()+"_"+private_key, "key": public_key}
    headers = {"content-type": "application/json", "authorization": "token "+pat}
    r = requests.post(url, headers=headers, data=json.dumps(data))
    if r.status_code != 201:
        print("ERROR: "+str(r.status_code))
        print(r.content)
        print("---")
        print("Removing generated ssh keys due to error...")
        os.remove(private_key)
        os.remove(private_key+".pub")
    else:
        target = os.path.expanduser("~") + os.sep + ".ssh" + os.sep
        s = "\nHost github.com\n\tAddKeysToAgent yes\n\tIdentityFile " + private_key + "\n\n"
        print("Appending the following to " + target + "config file...")
        print(s)
        with open(target + "config", "a") as config:
            config.write(s)

    print("Done! :)")

def parseAgentEnv(output):
    result = {}
    for name, value in re.findall("([A-Z_]+)=([^;]+);", output):
        result[name] = value
    return result

def ssh():
    print("Generating SSH key...")

    key = None
    try:
        key = ec.generate_private_key(ec.SECP256R1())
    except:
        print("Failed while creating a ECDSA private key.. Continuing with RSA...")
        key = rsa.generate_private_key(
            backend=crypto_default_backend(),
            public_exponent=65537,
            key_size=4096
        )
    private_key = key.private_bytes(
        crypto_serialization.Encoding.PEM,
        crypto_serialization.PrivateFormat.PKCS8,
        crypto_serialization.NoEncryption())
    public_key = key.public_key().public_bytes(
        crypto_serialization.Encoding.OpenSSH,
        crypto_serialization.PublicFormat.OpenSSH
    )

    public_key = public_key.decode("utf-8") + "\n"

    home = os.path.expanduser("~")
    privk = home + os.sep + ".ssh" + os.sep + "gh-ssh-keygen-" + datetime.datetime.now().strftime("%d-%m-%Y-%H-%M-%S")
    pubk = privk + ".pub"

    print("Saving private key to {}...".format(privk))
    with os.fdopen(os.open(privk, os.O_WRONLY | os.O_CREAT, 0o600), "w") as f:
        f.write(private_key.decode("utf-8"))
    print("Saving public key to {}...".format(pubk))
    with open(pubk, "w") as f:
        f.write(public_key)

    try:
        agent_pid = os.environ.get("SSH_AGENT_PID")
        if agent_pid is not None and psutil.pid_exists(int(agent_pid)):
            os.environ["SSH_AGENT_PID"] = agent_pid
            print("Using the ssh-agent that is already running...")
        else:
            print("Starting a new ssh-agent...")
            output = subprocess.check_output(["ssh-agent", "-s"])
            env = parseAgentEnv(str(output))
            print("Set SSH_AUTH_SOCK to " + env["SSH_AUTH_SOCK"])
            print("Set SSH_AGENT_PID to " + env["SSH_AGENT_PID"])
            os.environ["SSH_AUTH_SOCK"] = env["SSH_AUTH_SOCK"]
            os.environ["SSH_AGENT_PID"] = env["SSH_AGENT_PID"]
        print("Adding private key to ssh agent...")
        # Python 2
        if sys.version_info[0] == 2:
            subprocess.check_call(["ssh-add", privk])
        # Python 3
        else:
            subprocess.check_call(["ssh-add", privk])
    except Exception as e:
        print("---")
        print(e)
        print("Removing generated ssh keys due to error...")
        os.remove(privk)
        os.remove(pubk)
        return None, None

    return public_key, privk


if __name__ == "__main__":

    pat = str(getpass.getpass("Please enter a Personal Access Token with admin:public_key permissions: (not saved on disk)"))

    pk, prk = ssh()

    if pk is not None:
        githubPost(pat, pk, prk)

