#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# This script is licensed under GNU GPL version 2.0 or above
# (c) 2013 Antonio J. Delgado
# Read a spam folder in an IMAP server and add postfix filters according
# to the server that send the mail, the "return path" address and the
# "reply to" address
#
# ToDo:
#
# -
#
import sys
import time
import re
import imaplib
import email.header
import argparse
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import subprocess
import smtplib
import logging
from logging.handlers import SysLogHandler
import json
import mysql.connector


def escape_regexp_symbols(text):
    """Replace characters used in regular expressions"""
    result = text
    result = result.replace('\\', '\\\\')
    result = result.replace('[', '\\[')
    result = result.replace(']', '\\]')
    result = result.replace('?', '\\?')
    result = result.replace('.', '\\.')
    result = result.replace('*', '\\*')
    result = result.replace('{', '\\{')
    result = result.replace('}', '\\}')
    result = result.replace('$', '\\$')
    result = result.replace('^', '\\^')
    result = result.replace('-', '\\-')
    result = result.replace('(', '\\(')
    result = result.replace(')', '\\)')
    result = result.replace('=', '\\=')
    result = result.replace(':', '\\:')
    result = result.replace('!', '\\!')
    result = result.replace('|', '\\|')
    result = result.replace(',', '\\,')
    return result


def is_excluded_mta(mta):
    """Check if the mail transport agent is part of the ones excluded"""
    for emta in config['excluded_mtas']:
        if re.search(emta, mta) is not None:
            return True
    return False


def is_junk(message):
    """Check if a message is considered Junk"""
    if message[0][0].find(" Junk") > -1:
        return True
    else:
        return False


def get_original_mta(message):
    """Find the mail transport agent that initiated the transaction"""
    RES = re.finditer(r"Received: from ([a-zA-Z0-9\.\-_+]*\.[a-zA-Z]{2,}) ",
                      NEWDATA)
    original_mta = ""
    for mta in RES:
        if not is_excluded_mta(mta.group(1)):
            original_mta = mta.group(1)
    return original_mta


def get_emails_from_text(TEXT):
    """Obtain emails from a text"""
    if type(TEXT) == bytes:
        TEXT = TEXT.decode("utf-8")
    RES = re.findall(r"<?([a-zA-Z0-9\.\-]*@[a-zA-Z0-9\.\-]{2,}"
                     r"\.[a-zA-Z0-9\.\-_]{2,})>?",
                     TEXT)
    if RES is not None:
        RET = list()
        for email in RES:
            if email not in RET:
                RET.append(email)
        return RET
    else:
        return False


def dns_query(DOMAIN):
    """Do a DNS query"""
    RESULT = subprocess.Popen(['dig', '+short', DOMAIN],
                              stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT,
                              shell=False)
    OUTPUT = RESULT.communicate()[0]
    return OUTPUT.replace(chr(10), "")


def get_whois_mails(DOMAIN):
    """Obtain emails from a whois record"""
    RESULT = subprocess.Popen(['/usr/bin/whois', DOMAIN],
                              stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT,
                              shell=False)
    OUTPUT = RESULT.communicate()[0]
    wemail = get_emails_from_text(OUTPUT)
    return wemail


def send_warning(original_mta, msg_id, HEADERS):
    """Send a warning to an email related to a domain with the spam message"""
    amta = original_mta.split(".")
    DOMAIN = amta[len(amta)-2]+"."+amta[len(amta)-1]
    RECIPIENTS = get_whois_mails(DOMAIN)
    if len(RECIPIENTS) < 1:
        log.info("Unable to find an email address in the whois record for %s" %
                 DOMAIN)
    else:
        for RECIPIENT in RECIPIENTS:
            if not already_notified(original_mta, RECIPIENT):
                if type(RECIPIENT) == bytes:
                    RECIPIENT = RECIPIENT.decode('utf-8')
                msg = MIMEMultipart('alternative')
                msg['Subject'] = """The server %s was added to our spam
                list""" % original_mta
                msg['From'] = config['sender']
                msg['To'] = RECIPIENT
                msg['Bcc'] = 'gestor@susurrando.com'
                text = """
Hi,
The server %s was added to our spam list because is sending spam messages like
the message id %s.
Please, check the server and report back in case you would like to remove
it from our list.
You're receiving this message because you are in the whois record for the
domain %s.
Thanks

Headers of the message:%s""" % (original_mta, msg_id, DOMAIN, HEADERS)
                html = """
<HTML><BODY>
<P>Hi,</P>
<P>The server %s was added to our spam list because is sending
spam messages like the message id %s.</P>
<P>Please, check the server and report back in case you would
like to remove it from our list.</P>
<P>You're receiving this message because you are in the
whois record for the domain %s.</P>
<P>Thanks</P>
<P>Headers of the message:</P>
<CODE>%s</CODE>
</BODY></HTML>""" % (original_mta, msg_id, DOMAIN, HEADERS)
                part1 = MIMEText(text, 'plain')
                part2 = MIMEText(html, 'html')
                msg.attach(part1)
                msg.attach(part2)
                server = smtplib.SMTP('localhost')
                log.info("Sending email to '%s'" % RECIPIENT)
                server.sendmail(config['sender'], RECIPIENT, msg.as_string())
                server.quit()
                count_sent_warnings += 1
                add_notification(original_mta, RECIPIENT)
                log.info("Sent warning mail to %s regarding domain"
                         "%s for the mta %s"
                         % (RECIPIENT, DOMAIN, original_mta))


def add_filters(msg_id, original_mta, return_path, reply_to, HEADERS, subject):
    mtaID, RPID, RTID = add_filters_db(msg_id,
                                       original_mta,
                                       return_path,
                                       reply_to,
                                       subject)
    result = True
    if not mtaID or not RPID or not RTID:
        log.error("Error adding filter to database")
        result = False
    send_warning(original_mta, msg_id, HEADERS)
    return result


def add_filter_postfix():
    """Add filters to the postfix configuration file"""
    OUTPUT = """#Created at %s automatically from
%s\n""" % (time.strftime("%Y-%m%d %H:%M:%S"), sys.argv[0])
    CONN = mysql.connector.connect(host=config['dbserver'],
                                   user=config['dbuser'],
                                   passwd=config['dbpass'],
                                   db=config['dbname'],
                                   charset='utf8',
                                   use_unicode=True)
    CUR = CONN.cursor()
    log.info('Searching for banned server...')
    start = time.time()
    CUR.execute("""SELECT server, frommsgid
                FROM bannedservers WHERE banned = 1;""")
    for ROW in CUR.fetchall():
        if ROW[0] != "":
            msgid = escape_regexp_symbols(ROW[1])
            server = escape_regexp_symbols(ROW[0])
            OUTPUT += """#From message id %s
/^Received.*%s.*/ PREPEND X-Postfix-spam-filter: Marked as spam received from
server %s rule set by message id %s\n""" % (msgid, server, server, msgid)
    end = time.time()
    log.info('Took %s seconds.' % (end-start))
    log.info('Searching for banned senders...')
    start = time.time()
    CUR.execute("""SELECT sender, frommsgid FROM bannedsenders
                WHERE banned = 1;""")
    for ROW in CUR.fetchall():
        if ROW[0] != "":
            msgid = escape_regexp_symbols(ROW[1])
            config['sender'] = escape_regexp_symbols(ROW[0])
            OUTPUT += """#From message id %s
/^Return-Path.*%s.*/ PREPEND X-Postfix-spam-filter: Marked as spam return
path spamming %s rule set by message id %s\n""" % (msgid,
                                                   config['sender'],
                                                   config['sender'],
                                                   msgid)
            OUTPUT += """#From message id %s
/^Reply-To.*%s.*/ PREPEND X-Postfix-spam-filter: Marked as spam reply
to spamming %s rule set by message id %s\n""" % (msgid,
                                                 config['sender'],
                                                 config['sender'],
                                                 msgid)
    end = time.time()
    log.info('Took %s seconds.' % (end-start))
    log.info('Searching for banned subjects...')
    start = time.time()
    CUR.execute("""SELECT subject, frommsgid
                FROM bannedsubjects WHERE count>1;""")
    for ROW in CUR.fetchall():
        if ROW[0] != "":
            msgid = escape_regexp_symbols(ROW[1])
            subject = escape_regexp_symbols(ROW[0])
            OUTPUT += """#From message id %s
/^Subject.*%s.*/ PREPEND X-Postfix-spam-filter: Marked as spam reply to
spamming %s rule set by message id %s\n""" % (msgid, subject, subject, msgid)
    OUTPUT += "#End of automatically added data"
    end = time.time()
    log.info('Took %s seconds.' % (end-start))
    log.info('Replacing dollar symbol...')
    OUTPUT = OUTPUT.replace('$', '$$')
    log.info("Opening file '%s' to output the resulted filter..."
             % config['postfixheadercheckfile'])
    try:
        FILEH = open(config['postfixheadercheckfile'], "w")
    except:
        log.error("Error opening filter file to append new filter", True)
        return False
    log.info('Writting to disk...')
    start = time.time()
    FILEH.write("%s" % OUTPUT)
    end = time.time()
    log.info('Took %s seconds to write to disk.' % (end-start))
    FILEH.close()
    log.info("Running postmap command on filter's file")
    try:
        OUTPUT = subprocess.check_output(["/usr/bin/sudo",
                                          "/usr/sbin/postmap",
                                          config['postfixheadercheckfile']],
                                         stderr=subprocess.STDOUT,
                                         shell=False)
    except subprocess.CalledProcessError:
        log.info(OUTPUT, True)
        log.error("Error indexing postfix filter file", True)
        return False
    log.info('Reloading postfix...')
    try:
        OUTPUT = subprocess.check_output(["/usr/bin/sudo",
                                          "/usr/sbin/postfix",
                                          "reload"],
                                         stderr=subprocess.STDOUT,
                                         shell=False)
    except subprocess.CalledProcessError:
        log.info(OUTPUT, True)
        log.error("Error reloading postfix settings", True)
        return False
    return True


def add_filters_db(msg_id, original_mta, return_path, reply_to, subject):
    """Add filters to the database"""
    mtaID = False
    RPID = False
    RTID = False
    CONN = mysql.connector.connect(host=config['dbserver'],
                                   user=config['dbuser'],
                                   passwd=config['dbpass'],
                                   db=config['dbname'],
                                   charset='utf8',
                                   use_unicode=True)
    cursor = CONN.cursor()
    log.info('Banning MTA %s...' % original_mta)
    log.info('Banning sender %s...' % reply_to)
    log.info('Banning sender %s...' % return_path)
    cursor.execute('SELECT id FROM bannedservers WHERE server = %s',
                   params=(original_mta,))
    if cursor.rowcount < 1:
        cursor.execute("INSERT INTO bannedservers (server, frommsgid)"
                       "VALUES ( %s, %s )",
                       params=(original_mta, msg_id))
        mtaID = CONN.lastrowid
    else:
        cursor.execute("UPDATE bannedservers SET banned = 1 "
                       "WHERE server = %s", params=(original_mta, ))
        log.info("Mail transport agent already in the database, banning it "
                 "again.")
        mtaID = True
    cursor.execute("SELECT id FROM bannedsenders "
                   "WHERE sender = %s", params=(return_path, ))
    if cursor.rowcount < 1:
        cursor.execute("INSERT INTO bannedsenders (sender, frommsgid) "
                       "VALUES (%s, %s)", params=(return_path.lower(), msg_id))
        RPID = CONN.lastrowid
    else:
        cursor.execute("UPDATE bannedsenders SET banned = 1 "
                       "WHERE sender = %s", params=(return_path, ))
        log.info("Return path address already in the database, "
                 "banning it again.")
        RPID = True
    cursor.execute("SELECT id FROM bannedsenders WHERE sender = %s;",
                   (reply_to, ))
    if cursor.rowcount < 1:
        cursor.execute("INSERT INTO bannedsenders (sender, frommsgid) "
                       "VALUES (%s, %s)", (reply_to.lower(), msg_id))
        RTID = CONN.lastrowid
    else:
        cursor.execute("UPDATE bannedsenders SET banned = 1 "
                       "WHERE sender = %s", params=(reply_to, ))
        log.info("Reply To address already in the database")
        RTID = True
    cursor.execute("SELECT id, count FROM bannedsubjects "
                   "WHERE subject = %s", params=(subject, ))
    if cursor.rowcount < 1:
        cursor.execute("INSERT INTO bannedsubjects (subject, frommsgid) "
                       "VALUES (%s, %s)", params=(subject, msg_id))
        log.info("New spam subject '%s' added to the database." % subject)
        RTID = CONN.lastrowid
    else:
        ROW = cursor.fetchall()[0]
        cursor.execute("UPDATE bannedsubjects SET count = %s "
                       "WHERE subject = %s", params=(ROW[1]+1, subject))
        log.info("Subject '%s' already in the database, "
                 "added count to %s" % (subject, str(ROW[1]+1)))
        RTID = True
    CONN.commit()
    cursor.close()
    CONN.close()
    return mtaID, RPID, RTID


def already_notified(mta, MAIL):
    """Check if a mail transport agent owner was already notified"""
    log.info("Checking if we already sent a notification to %s "
             "regarding %s" % (MAIL, mta))
    CONN = MySQLdb.connect(host=config['dbserver'],
                           user=config['dbuser'],
                           passwd=config['dbpass'],
                           db=config['dbname'],
                           charset='utf8',
                           use_unicode=True)
    mta = CONN.escape_string(mta)
    MAIL = CONN.escape_string(MAIL)
    CUR = CONN.cursor()
    mta_MAIL = '%s_%s' % (mta, MAIL)
    CUR.execute("SELECT mta_mail FROM notifiedmtas "
                "WHERE mta_mail = %s;", (mta_MAIL, ))
    if CUR.rowcount > 0:
        log.info("We already sent a notification to %s "
                 "regarding %s" % (MAIL, mta))
        CUR.close()
        CONN.close()
        return True
    else:
        log.info("We didn't send a notification to %s "
                 "regarding %s" % (MAIL, mta))
        return False


def add_notification(mta, MAIL):
    """Add the notification of an owner to the database"""
    log.info("Adding that we sent a notification to %s regarding "
             "%s" % (MAIL, mta))
    CONN = MySQLdb.connect(host=config['dbserver'],
                           user=config['dbuser'],
                           passwd=config['dbpass'],
                           db=config['dbname'],
                           charset='utf8',
                           use_unicode=True)
    mta = CONN.escape_string(mta)
    MAIL = CONN.escape_string(MAIL)
    CUR = CONN.cursor()
    mta_MAIL = '%s_%s' % (mta, MAIL)
    CUR.execute("INSERT INTO notifiedmtas (mta_mail) VALUES ( %s);",
                (mta_MAIL, ))
    RTID = CONN.lastrowid
    CONN.commit()
    CUR.close()
    CONN.close()
    return RTID


count_sent_warnings = 0
starttime = time.time()
log = logging.getLogger()
log.setLevel(logging.getLevelName('DEBUG'))

sysloghandler = SysLogHandler()
sysloghandler.setLevel(logging.getLevelName('DEBUG'))
log.addHandler(sysloghandler)

streamhandler = logging.StreamHandler(sys.stdout)
streamhandler.setLevel(logging.getLevelName('DEBUG'))
log.addHandler(streamhandler)

parser = argparse.ArgumentParser(description='Examine messages marked as '
                                 'spam in an IMAP folder, add mail filters'
                                 ' to similar messages and notify owners '
                                 'of the mail servers used.')
parser.add_argument('--excluded-mta', dest='excluded_mtas',
                    action='append',
                    help='Mail Transport Agent to exclude '
                    '(usually does you trust)')
parser.add_argument('--sender', dest='sender',
                    default='gestor@susurrando.com',
                    help='From email for notifications to spammy servers.')
parser.add_argument('--imap-filter', dest='imapfilter',
                    default='(UNSEEN)',
                    help='Filter to find messages in the IMAP server.')
parser.add_argument('--postfix-header-check-file',
                    dest='postfixheadercheckfile',
                    default='/etc/postfix/maps/spam_filter_header_check',
                    help='File to store mail filters for postfix '
                    '(Should be declared in /etc/postfix/main.cf in '
                    'the header_checks parameter)')
parser.add_argument('--debug', dest='debug', default='WARNING',
                    help='Set debug level (CRITICAL, '
                    'ERROR, WARNING, INFO, DEBUG, NOTSET)')
parser.add_argument('--csv', dest='csv',
                    default=False,
                    help='Output to CSV format')
parser.add_argument('--imap-server', dest='imapserver',
                    default='localhost',
                    help='IMAP server to get spam messages.')
parser.add_argument('--imap-port', dest='imapport',
                    default='993',
                    help='IMAP port of the server.')
parser.add_argument('--imap-password', dest='imappassword',
                    help='Password of the IMAP user.')
parser.add_argument('--imap-user', dest='imapuser',
                    help='IMAP user name.')
parser.add_argument('--imap-password-file', dest='imappasswordfile',
                    help='File containing the IMAP user\'s password')
parser.add_argument('--imap-mailbox', dest='imapmailbox',
                    default="INBOX",
                    help='IMAP mailbox (folder) where spam messages are '
                    'located.')
parser.add_argument('--ssl', dest='ssl',
                    default=False,
                    help='Use an SSL connection to IMAP.')
parser.add_argument('--configfile', dest='configfile',
                    help='Config file to overwrite parameters '
                    'from the command line')
parser.add_argument('--db-user', dest='dbuser',
                    help='Database user name.')
parser.add_argument('--db-pass', dest='dbpass',
                    help='(NOT RECOMMENDED) Database user\'s password.')
parser.add_argument('--db-pass-file', dest='dbpassfile',
                    help='File containing the database user\'s password.')
parser.add_argument('--db-name', dest='dbname',
                    default='mail',
                    help='Database name.')
parser.add_argument('--db-table', dest='dbtable',
                    default='spamheaders',
                    help='Database user name.')
parser.add_argument('--db-server', dest='dbserver',
                    default='localhost',
                    help='Database server.')
args = parser.parse_args()
config = vars(args)
if config['configfile'] is not None:
    configfile = json.load(open(config['configfile'], 'r'))
    config = {**config, **configfile}

if config['imappasswordfile'] is not None:
    with open(config['imappasswordfile'], 'r') as fp:
        imappassword = fp.read()
    if imappassword != "":
        config['imappassword'] = imappassword.strip()
        log.debug('IMAP password obtained from password file %s' %
                  config['imappasswordfile'])

if config['dbpassfile'] is not None:
    with open(config['dbpassfile'], 'r') as fp:
        dbpassfile = fp.read()
    if dbpassfile != "":
        config['dbpass'] = dbpassfile.strip()
        log.debug('Database password obtained from password file %s' %
                  config['dbpassfile'])

log.setLevel(logging.getLevelName(config['debug']))

if config['ssl']:
    PROTO = "imaps"
else:
    PROTO = "imap"
log.info("Connecting to %s://%s:%s/ ..."
         % (PROTO, config['imapserver'], config['imapport']))
if config['ssl']:
    try:
        IMAP = imaplib.IMAP4_SSL(config['imapserver'], config['imapport'])
    except:
        log.error("Error connecting to '%s:%s'." %
                  (config['imapserver'], config['imapport']))
        sys.exit(1)
else:
    try:
        IMAP = imaplib.IMAP4(config['imapserver'], config['imapport'])
    except:
        log.error("Error connecting to '%s:%s'." %
                  (config['imapserver'], config['imapport']))
        sys.exit(1)
log.info("Identifying as %s..." % config['imapuser'])
try:
    IMAP.login(config['imapuser'], config['imappassword'])
except imaplib.IMAP4.error as e:
    log.error("Error login as '%s:%s@%s:%s'. %s" %
              (config['imapuser'], config['imapserver'],
               config['imapport'], e))
    sys.exit(1)
log.info("Selecting mailbox %s..." % config['imapmailbox'])
try:
    STATUS, DATA = IMAP.select(config['imapmailbox'], True)
except imaplib.IMAP4.error as e:
    log.error("Error selecting mailbox '%s@%s:%s/%s'. Server message: %s" %
              (config['imapuser'], config['imapserver'],
               config['imapport'], config['imapmailbox'], e))
    IMAP.close()
    IMAP.logout()
    sys.exit(1)
if STATUS == "NO":
    log.error("Server report an error selecting mailbox. Server response: %s" %
              DATA[0])
else:
    log.info("Looking for messages...")
    try:
        STATUS, IDATA = IMAP.search(None, config['imapfilter'])
    except imaplib.IMAP4.error as e:
        log.error("Error looking for messages in mailbox '%s://%s@%s:%s/%s'. "
                  "Server message: %s" %
                  (PROTO, config['imapuser'], config['imapserver'],
                   config['imapport'], config['imapmailbox'], e))
        IMAP.logout()
        sys.exit(1)
    log.info("Received: Status: %s Data: %s" % (STATUS, IDATA))
    msg_id = ""
    FROM = ""
    reply_to = ""
    return_path = ""
    subject = ""
    if config['csv']:
        print("msg_id;original_mta;return_path;reply_to;FROM;subject")
    if IDATA == b'':
        log.warning("No messages match the filter '%s' in the folder '%s'." %
                    (config['imapfilter'], config['imapmailbox']))
    else:
        IDS = IDATA[0].split()
        totalmessages = len(IDS)
        count = 0
        for ID in IDS:
            count = count+1
            log.info("Getting headers of message %s (%s/%s)" %
                     (ID, count, totalmessages))
            try:
                STATUS, DATA = IMAP.fetch(ID, '(FLAGS BODY[HEADER])')
            except:
                log.error("Error fetching messages headers")
            log.info("Received. Status: %s Data %s" % (STATUS, DATA))
            if STATUS == "NO":
                log.error("Error fetching message headers, servers "
                          "reponse '%s'" % DATA)
            else:
                log.info("message flagged as junk mail, processing")
                HEADERS = DATA[0][1].decode('utf-8')
                NEWDATA = HEADERS.replace('\r',
                                          '').replace('\n ',
                                                      ' ').replace('\n\t',
                                                                   ' ')
                original_mta = get_original_mta(NEWDATA)
                if original_mta != "":
                    log.info("Located the original server as %s" % original_mta)
                    HEADERS = NEWDATA.splitlines()
                    for HEADER in HEADERS:
                        LHEADER = HEADER.split(": ", 1)
                        HEADERNAME = LHEADER[0].lower()
                        try:
                            HEADERVALUE = LHEADER[1]
                        except IndexError:
                            HEADERVALUE = ""
                        if HEADERNAME == "message-id":
                            msg_id = HEADERVALUE.replace("<",
                                                        "").replace(">",
                                                                    "")
                            log.info("Located message id as %s" % msg_id)
                        if HEADERNAME == "return-path":
                            return_pathS = get_emails_from_text(HEADERVALUE)
                            for return_path in return_pathS:
                                log.info("Located message return path as %s" %
                                         return_path)
                        if HEADERNAME == "reply-to":
                            reply_toS = get_emails_from_text(HEADERVALUE)
                            for reply_to in reply_toS:
                                log.info("Located message reply to as %s" %
                                         reply_to)
                        if HEADERNAME == "from":
                            FROMS = get_emails_from_text(HEADERVALUE)
                            for FROM in FROMS:
                                log.info("Located message sender as %s" % FROM)
                        if HEADERNAME == "subject" and subject == "":
                            try:
                                DECsubjectS = email.header.decode_header(HEADERVALUE)
                            except:
                                DECsubjectS = ""
                            for DECsubject in DECsubjectS:
                                PARTIALsubject, ENCODING = DECsubject
                                if ENCODING is None:
                                    subject = "%s %s" % (subject,
                                                         PARTIALsubject)
                                else:
                                    subject = '%s %s' % (subject,
                                                         PARTIALsubject.decode(ENCODING,
                                                                               "replace"))
                            try:
                                subject = subject.encode("utf8", "replace")
                            except UnicodeDecodeError:
                                subject = subject.decode('iso-8859-1').encode('utf8', 'replace')
                            log.info("Located message subject as %s" % subject)

                    if config['csv']:
                        print("%s;%s;%s;%s;%s;%s" %
                              (msg_id, original_mta, return_path,
                               reply_to, FROM, subject.lstrip()))
                    add_filters(msg_id, original_mta, return_path, reply_to,
                                HEADERS, subject)
                else:
                    log.warning("Couldn't find the original server")
        for ID in IDS:
                try:
                    IMAP.store(ID, '+FLAGS', '(\\Seen)')
                except:
                    log.error("Error marking message as read")
                try:
                    IMAP.store(ID, '+FLAGS', '(\\Deleted)')
                except:
                    log.error("Error marking message as deleted")
                IMAP.expunge()
        try:
            IMAP.close()
        except:
            log.error("Error closing connection")
    log.info('Updating postfix filters.')
    if not add_filter_postfix():
        log.error("Error adding filters to postfix")
try:
    log.info('Disconnecting from the IMAP server.')
    IMAP.logout()
except:
    log.error("Error closing connection")

log.info('%s warnings were sent.' % count_sent_warnings)
message = """From: %s\r\nTo: %s\r\nSubject: Spam notifications stats\r\n\r\n
%s spam warnings were sent by
update-spam-filter.""" % (config['sender'],
                          config['sender'],
                          count_sent_warnings)
server = smtplib.SMTP('localhost')
server.sendmail(config['sender'], config['sender'], message)
server.quit()
