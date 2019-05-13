#!/usr/bin/env python
import os
import re
import sys
import json
import socket
import base64
import psutil
import getpass
import datetime
import requests
import subprocess

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.backends import default_backend as crypto_default_backend

def githubPost(username, password, public_key, key_title):
    print("Deploying the newly created public key on Github...")
    url = "https://api.github.com/user/keys"
    data = {"title": socket.gethostname()+"_"+key_title, "key": public_key}
    headers = {"content-type": "application/json", "username": username, "authorization": "Basic "+base64.encodestring(("%s:%s" % (username,password)).encode()).decode().strip()}
    r = requests.post(url, headers=headers, data=json.dumps(data))
    if r.status_code != 201:
        print("ERROR: "+str(r.status_code))
        print(r.content)
        print("---")
        print("Removing generated ssh keys due to error...")
        os.remove(key_title)
        os.remove(key_title+".pub")
    print("Done! :)")

def parseAgentEnv(output):
    result = {}
    for name, value in re.findall("([A-Z_]+)=([^;]+);", output):
        result[name] = value
    return result

def ssh(email):
    print("Generating SSH key...")

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

    public_key = public_key.decode("utf-8") + " "+email+"\n"

    home = os.path.expanduser("~")
    privk = home + os.sep + ".ssh" + os.sep + "gh-ssh-keygen-" + datetime.datetime.now().strftime("%d-%m-%Y-%H-%M-%S")
    pubk = privk + ".pub"

    print("Saving private key to {}...".format(privk))
    with os.fdopen(os.open(privk, os.O_WRONLY | os.O_CREAT, 0o600), "w") as f:
        f.write(private_key.decode("utf-8"))
    print("Saving public key to {}...".format(pubk))
    with open(pubk, "w") as f:
        f.write(public_key)

    print("Adding private key to ssh agent...")

    try:
        agent_pid = os.environ.get("SSH_AGENT_PID")
        if agent_pid is not None and psutil.pid_exists(int(agent_pid)):
            os.environ["SSH_AGENT_PID"] = agent_pid
            print("Using the ssh-agent that is already running...")
        else:
            print("Starting a new ssh-agent...")
            output = subprocess.check_output(["ssh-agent", "-s"])
            env = parseAgentEnv(str(output))
            os.environ["SSH_AUTH_SOCK"] = env["SSH_AUTH_SOCK"]
            os.environ["SSH_AGENT_PID"] = env["SSH_AGENT_PID"]
            print("Set SSH_AUTH_SOCK to " + env["SSH_AUTH_SOCK"])
            print("Set SSH_AGENT_PID to " + env["SSH_AGENT_PID"])
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
    username = ""
    email = ""
    try:
        # Python 2
        email = raw_input("Please enter your Github email:")
        username = raw_input("Please enter your Github username:")
    except:
        # Python 3
        email = str(input("Please enter your Github email:"))
        username = str(input("Please enter your Github username:"))

    password = str(getpass.getpass("Please enter your Github password: (not saved on disk)"))

    pk, title = ssh(email)

    if pk is not None:
        githubPost(username, password, pk, title)
