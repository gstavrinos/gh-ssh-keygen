#!/usr/bin/env python
import os
import sys
import socket
import getpass
import datetime

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.backends import default_backend as crypto_default_backend

def doIt(self, title=None, key=None):
    payload = {
        "scopes": ['public_repo'] if scopes is None else scopes,
        "note": note or "Created by gh-ssh-keygen for {1} on {2}".format(
            socket.gethostname(),
            datetime.datetime.now().isoformat()),
    }
    resp = do_github_post_req('/authorizations', payload, self.auth)
    resp_data = json_loads(resp)
    resp_code = '{0}'.format(resp.getcode())
    if resp_code not in ['201', '202'] or 'token' not in resp_data:
        raise GithubException("Failed to create a new oauth authorization", resp)
    token = resp_data['token']
    if update_auth:
        self.auth = auth_header_from_oauth_token(token)
        self.token = token
    return token

def githubPost(username, password, public_key):
    print("Deploying the newly created public key on Github...")
    url = "https://api.github.com/user"
    # TODO
    print("Done! :)")


def ssh():
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

    home = os.path.expanduser("~")
    privk = home + os.sep + ".ssh" + os.sep + "gh-ssh-keygen-" + datetime.datetime.now().strftime("%d-%m-%Y-%H-%M-%S")
    pubk = privk + ".pub"

    print("Saving private key to {}...".format(privk))
    with open(privk, "w") as f:
        f.write(private_key)
    print("Saving private key to {}...".format(pubk))
    with open(pubk, "w") as f:
        f.write(public_key)

    return public_key


if __name__ == "__main__":
    username = ""
    email = ""
    try:
        # Python 2
        username = raw_input("Please enter your Github username:")
    except:
        # Python 3
        username = input("Please enter your Gighub username:")

    password = getpass.getpass("Please enter your Github password: (not saved on disk)")

    pk = ssh()

    githubPost(username, password, pk)




