# txftp Server
## About

This is a dead-simple (dumb) implementation of an SFTP server, which handles ssh-key authentication, and serves files from a virtual root directory.  This is used mostly for CI workflows.

## Setup

1. Install python dependencies.  I recommend using a virtual environment.  The requirements are listed in requirements.txt

```
pip3 install -r requirements.txt
```

2. Generate an ssh keypair for the client.  Note you should *not* use the default filename when prompted.  
```
ssh-keygen -t ecdsa
```

The private key needs to be accessible via a secret in the repo, which gets decoded and written out to an identity file.

3. Generate an ssh keypair for the server
```
ssh-keygen -t ecdsa
```

Don't overwrite the previous key.

4. Make the target directory.  For this example, we'll use `$HOME/combatextended`

```
mkdir -p $HOME/combatextended
```

5. Start the service

```
python3 txftp.pt $HOME/combatextended serverKey serverKey.pub combatextended clientKey.pub 2022
```

6. Set the service to start on startup.  (openrc left as an exercise)

```
cp combatextended-upload.service /etc/systemd/system
systemctl enable combatextended-upload 
```

Note that the command from step 5, with any customization required, must be written to the script used in the `.service` file.  
