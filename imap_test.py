import imaplib
from email.parser import HeaderParser


def get_original_mta(msg):
    last_mta = ""
    for k, v in msg.items():
        if k == "Received":
            last_mta = v.split(" ")[1]
    return last_mta


conn = imaplib.IMAP4_SSL("dedi.susurrando.com")
conn.login("user@example.com", "aP4ssw0rd")
conn.select()
status, idata = conn.search(None, "ALL")  # returns a nice list of messages...
# let's say I pick #1 from this
print(idata)
status, data = conn.fetch("1", "(FLAGS BODY[HEADER])")

# gloss over data structure of return... I assume you know these
# gives something like:
# ('OK', [(1 (BODY[HEADER] {1662', 'Received: etc....')])
header_data = data[0][1].decode("utf-8")

parser = HeaderParser()
msg = parser.parsestr(header_data)
print(msg.keys())
print(get_original_mta(msg))
