# Update Spam filter
## Description
Based on an IMAP folder with spam messages. It creates mail filters for postfix
to mark as spam future messages.
## Requirements
- mysql.connector
## Installation
1. Get pip:
```bash
apt install python3-pip # Ubuntu/Debian
yum install python34-setuptools # CentOS
wget -O https://bootstrap.pypa.io/get-pip.py |sudo python3 - # But this might mess with a pip installed with your system package manager
```
2. Install requirements:
```bash
python3 -m pip install -r requirements.txt
```
3. Create a file with your IMAP password and protect it from other users
4. Create a file with your MySQL password and protect it from other users
