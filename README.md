# gh-ssh-keygen
Github SSH Key Generator :closed_lock_with_key:

Just run this python script to create a SSH key for your github account.

Tested on Linux, but it should work on all platforms, provided that you have all the required
software installed.

### Required Software

* SSH.
* Python Libraries: json, socket, psutil, getpass, datetime, requests, subprocess, cryptography.

### Important changes

For security reasons, the updated Github REST API does not allow for username+password authentication. 

*The use of Private Access Tokens (PAT) is now mandatory for this script to work.*

In order to create a PAT, follow the official instructions here:

https://docs.github.com/en/github/authenticating-to-github/keeping-your-account-and-data-secure/creating-a-personal-access-token

*Make sure you allow the PAT to create a assign public keys by checking the `admin:public_key` permission.*
