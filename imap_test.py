import imaplib
from email.parser import HeaderParser

conn = imaplib.IMAP4_SSL('dedi.susurrando.com')
conn.login('ad@susurrando.com', 'SME35PyD$U5dwiW5K')
conn.select()
status, idata = conn.search(None, 'ALL') # returns a nice list of messages...
                         # let's say I pick #1 from this
print(idata)
status, data = conn.fetch('1', "(FLAGS BODY[HEADER])")

# gloss over data structure of return... I assume you know these
# gives something like:
# ('OK', [(1 (BODY[HEADER] {1662', 'Received: etc....')])
header_data = data[0][1].decode("utf-8")

parser = HeaderParser()
msg = parser.parsestr(header_data)
print(msg.get('Subject', ''))
