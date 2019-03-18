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
import os
import sys
import getpass
import time
import re
import imaplib
import email.header
import MySQLdb
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import subprocess
import smtplib
import logging
IMAPSERVER = "localhost"
IMAPPORT = "993"
IMAPUSER = ""
IMAPPASSWORD = ""
IMAPMAILBOX = "INBOX"
DB_USER = "spam-filter"
DB_PASS = "buPKcpjnwH7VveaCFHxWrtrY"
DB_NAME = "mail"
DB_TABLE = "spamheaders"
DB_SERVER = "localhost"
SENDER = "gestor@susurrando.com"
IMAPFILTER = '(UNSEEN)'
POSTFIX_HEADER_CHECK_FILE = "/etc/postfix/maps/spam_filter_header_check"
excluded_mtas = {'gmail.com',
                'localhost.localdomain', 'msrv.koti.site',
                'bankinter.bankinter.com', 'smtpi.msn.com',
                'telefonica.net', 'mta1.susurrando.com',
                'srv.susurrando.com', 'correo.susurrando.com',
                'mudito.susurrando.com', 'webmail.susurrando.com',
                'facebook.com', 'google.com',
                'vadelma.susurrando.com',
                'mora.susurrando.com', 'dedi.susurando.com',
                'vsrv.susurando.com'}
SSL = False
DEBUG = 'INFO'
CSVOUTPUT = False
SENTWARNINGS = 0


def escape_regexp_symbols(text):
    """Replace characters used in regular expressions"""
    result = text
    result = result.replace('\\', '\\\\')
    result = result.replace('[', '\[')
    result = result.replace(']', '\]')
    result = result.replace('?', '\?')
    result = result.replace('.', '\.')
    result = result.replace('*', '\*')
    result = result.replace('{', '\{')
    result = result.replace('}', '\}')
    result = result.replace('$', '\$')
    result = result.replace('^', '\^')
    result = result.replace('-', '\-')
    result = result.replace('(', '\(')
    result = result.replace(')', '\)')
    result = result.replace(' = ', '\ = ')
    result = result.replace(':', '\:')
    result = result.replace('!', '\!')
    result = result.replace('|', '\|')
    result = result.replace(', ', '\, ')
    return result


def is_excluded_mta(mta):
    """Check if the mail transport agent is part of the ones excluded"""
    global excluded_mtas
    for emta in excluded_mtas:
        if re.search(emta, mta) is not None:
            return True
    return False


def process_arguments():
    """Process the passed arguments"""
    global DEBUG, IMAPSERVER, IMAPPORT, IMAPUSER, IMAPPASSWORD, IMAPMAILBOX, SSL, IMAPFILTER, CSVOUTPUT
    for arg in sys.argv:
        if arg == "-h" or arg == "--help" or arg == "-?" or arg == "/?" or arg == "/h" or arg == "/help":
            usage()
            sys.exit(0)
        if arg == "-d" or arg == "--debug":
            DEBUG = DEBUG+1
            log.info("Debug level incressed")
        if arg.lower() == "--ssl":
            log.info("Will use SSL")
            SSL = True
        if arg.lower() == "-s":
            log.info("Will use SSL")
            SSL = True
        if arg.lower() == "-c" or arg.lower() == "--csv":
            log.info("Will output as CSV format")
            CSVOUTPUT = True
        if arg.lower() == "-a" or arg.lower() == "--all-messages":
            log.info("Will process all IMAP messages, not only unseen.")
            IMAPFILTER = 'ALL'
        larg = arg.split("=", 1)
        if len(larg) == 2:
            if larg[0].lower() == "--imap-server":
                log.info("Server will be '%s'" % larg[1])
                IMAPSERVER = larg[1]
            if larg[0].lower() == "--imap-port":
                log.info("Port will be '%s'" % larg[1])
                IMAPPORT = larg[1]
            if larg[0].lower() == "--imap-user":
                log.info("User will be '%s'" % larg[1])
                IMAPUSER = larg[1]
            if larg[0].lower() == "--imap-password":
                if larg[1] != "":
                    log.info("Password is set")
                IMAPPASSWORD = larg[1]
            if larg[0].lower() == "--imap-mailbox":
                log.info("Mailbox will be '%s'" % larg[1])
                IMAPMAILBOX = larg[1]
            if larg[0].lower() == "--imap-password-file":
                log.info("Reading password from file '%s'" % larg[1])
                if os.path.exists(larg[1]):
                    FILE = open(larg[1], "r")
                    IMAPPASSWORD = FILE.readline().replace("\n", "").replace("\r", "")
                    FILE.close()
                else:
                    log.info("The password file '%s' doesn't exists" % larg[1])
                    sys.exit(65)
    if IMAPPASSWORD == "":
        IMAPPASSWORD = getpass.getpass("Password for '%s@%s:%s': " %
                                       (IMAPUSER, IMAPSERVER, IMAPPORT))
    if IMAPSERVER == "":
        log.info("You must indicate a server to connecto to")
        usage()
        sys.exit(65)
    if IMAPUSER == "":
        log.info("You must indicate a username")
        usage()
        sys.exit(65)
    if IMAPMAILBOX == "":
        log.info("You must indicate a mailbox in the server")
        usage()
        sys.exit(65)


def usage():
    """Show the usage of the script"""
    print("%s [-h] [-d] [--csv] [--imap-server = IMAPSERVER --imap-port = IMAPPORT --imap-user = IMAPUSER --imap-password = IMAPPASSWORD --imap-password-file = IMAPPASSWORDFILE --imap-mailbox = IMAPMAILBOX] [--ssl|-s]" % sys.argv[0])
    print("\t--csv | -c\tOutput information of mail messages as CSV format")
    print("\t--help | -h\tShow this help")
    print("\t--debug | -d\tShow extra debug information")


def is_junk(message):
    """Check if a message is considered Junk"""
    if message[0][0].find(" Junk") >- 1:
        return True
    else:
        return False


def get_original_mta(message):
    """Find the mail transport agent that initiated the transaction"""
    RES = re.finditer("Received: from ([a-zA-Z0-9\.\-_+]*\.[a-zA-Z]{2,}) ",
                      NEWDATA)
    ORIGINALmta = ""
    for mta in RES:
        if not is_excluded_mta(mta.group(1)):
            ORIGINALmta = mta.group(1)
    return ORIGINALmta


def get_emails_from_text(TEXT):
    """Obtain emails from a text"""
    if type(TEXT) == bytes:
        TEXT = TEXT.decode("utf-8")
    RES = re.findall("<?([a-zA-Z0-9\.\-]*@[a-zA-Z0-9\.\-]{2,}\.[a-zA-Z0-9\.\-_]{2,})>?", TEXT)
    if RES != None:
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


def send_warning(ORIGINALmta, MSGID, HEADERS):
    """Send a warning to an email related to a domain with the spam message"""
    global SENDER, SENTWARNINGS
    amta = ORIGINALmta.split(".")
    DOMAIN = amta[len(amta)-2]+"."+amta[len(amta)-1]
    RECIPIENTS = get_whois_mails(DOMAIN)
    if len(RECIPIENTS) < 1:
        log.info("Unable to find an email address in the whois record for %s" %
                DOMAIN)
    else:
        for RECIPIENT in RECIPIENTS:
            if not already_notified(ORIGINALmta, RECIPIENT):
                if type(RECIPIENT) == bytes:
                    RECIPIENT = RECIPIENT.decode('utf-8')
                msg = MIMEMultipart('alternative')
                msg['Subject'] = "The server %s was added to our spam list" % ORIGINALmta
                msg['From'] = SENDER
                msg['To'] = RECIPIENT
                msg['Bcc'] = 'gestor@susurrando.com'
                text = "Hi, \nThe server %s was added to our spam list because is sending spam messages like the message id %s.\nPlease, check the server and report back in case you would like to remove it from our list.\nYou're receiving this message because you are in the whois record for the domain %s.\nThanks\n\n\nHeaders of the message:%s" % (ORIGINALmta, MSGID, DOMAIN, HEADERS)
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
                </BODY></HTML>
                """ % (ORIGINALmta, MSGID, DOMAIN, HEADERS)
                part1 = MIMEText(text, 'plain')
                part2 = MIMEText(html, 'html')
                msg.attach(part1)
                msg.attach(part2)
                server = smtplib.SMTP('localhost')
                log.info("Sending email to '%s'" % RECIPIENT)
                server.sendmail(SENDER, RECIPIENT, msg.as_string())
                server.quit()
                SENTWARNINGS += 1
                add_notification(ORIGINALmta, RECIPIENT)
                log.info("Sent warning mail to %s regarding domain %s for the mta %s" % (RECIPIENT, DOMAIN, ORIGINALmta))


def add_filters(MSGID, ORIGINALmta, RETURNPATH, REPLYTO, HEADERS, SUBJECT):
    mtaID, RPID, RTID = add_filters_db(MSGID,
                                     ORIGINALmta,
                                     RETURNPATH,
                                     REPLYTO,
                                     SUBJECT)
    result = True
    if not mtaID or not RPID or not RTID:
        log.info("Error adding filter to database")
        result = False
    send_warning(ORIGINALmta, MSGID, HEADERS)
    return result


def add_filter_postfix():
    """Add filters to the postfix configuration file"""
    global DB_SERVER, DB_USER, DB_PASS, DB_NAME, DB_TABLE
    global POSTFIX_HEADER_CHECK_FILE
    OUTPUT = "#Created at %s automatically from %s\n" % (time.strftime("%Y-%m%d %H:%M:%S"), sys.argv[0])
    CONN = MySQLdb.connect(host=DB_SERVER,
                           user=DB_USER,
                           passwd=DB_PASS,
                           db=DB_NAME,
                           charset='utf8',
                           use_unicode=True)
    CUR = CONN.cursor()
    log.info('Searching for banned server...')
    start = time.time()
    CUR.execute("SELECT server, frommsgid FROM bannedservers WHERE banned = 1;")
    for ROW in CUR.fetchall():
        if ROW[0] != "":
            msgid = escape_regexp_symbols(ROW[1])
            server = escape_regexp_symbols(ROW[0])
            OUTPUT = "%s#From message id %s\n/^Received.*%s.*/ PREPEND X-Postfix-spam-filter: Marked as spam received from server %s rule set by message id %s\n" % (OUTPUT, msgid, server, server, msgid)
    end = time.time()
    log.info('Took %s seconds.' % (end-start))
    log.info('Searching for banned senders...')
    start = time.time()
    CUR.execute ("SELECT sender, frommsgid FROM bannedsenders WHERE banned = 1;")
    for ROW in CUR.fetchall():
        if ROW[0] !=    "":
            msgid = escape_regexp_symbols(ROW[1])
            sender = escape_regexp_symbols(ROW[0])
            OUTPUT = "%s#From message id %s\n/^Return-Path.*%s.*/ PREPEND X-Postfix-spam-filter: Marked as spam return path spamming %s rule set by message id %s\n" % (OUTPUT, msgid, sender, sender, msgid)
            OUTPUT = "%s#From message id %s\n/^Reply-To.*%s.*/ PREPEND X-Postfix-spam-filter: Marked as spam reply to spamming %s rule set by message id %s\n" % (OUTPUT, msgid, sender, sender, msgid)
    end = time.time()
    log.info('Took %s seconds.' % (end-start))
    log.info('Searching for banned subjects...')
    start = time.time()
    CUR.execute ("SELECT subject, frommsgid FROM bannedsubjects WHERE count>1;")
    for ROW in CUR.fetchall():
        if ROW[0] !=    "":
            msgid = escape_regexp_symbols(ROW[1])
            subject = escape_regexp_symbols(ROW[0])
            OUTPUT = "%s#From message id %s\n/^Subject.*%s.*/ PREPEND X-Postfix-spam-filter: Marked as spam reply to spamming %s rule set by message id %s\n" % (OUTPUT, msgid, subject, subject, msgid)
    OUTPUT = "%s#End of automatically added data" % OUTPUT
    end = time.time()
    log.info('Took %s seconds.' % (end-start))
    log.info('Replacing dollar symbol...')
    OUTPUT = OUTPUT.replace('$', '$$')
    log.info("Opening file '%s' to output the resulted filter..." % POSTFIX_HEADER_CHECK_FILE)
    try:
        FILEH = open(POSTFIX_HEADER_CHECK_FILE, "w")
    except:
        log.info("Error opening filter file to append new filter", True)
        return False
    log.info('Writting to disk...')
    start = time.time()
    FILEH.write("%s" % OUTPUT)
    end = time.time()
    log.info('Took %s seconds to write to disk.' % (end-start))
    FILEH.close()
    log.info("Running postmap command on filter's file")
    try:
        OUTPUT = subprocess.check_output(["/usr/bin/sudo", "/usr/sbin/postmap", POSTFIX_HEADER_CHECK_FILE], stderr = subprocess.STDOUT, shell = False)
    except subprocess.CalledProcessError:
        log.info(OUTPUT, True)
        log.info("Error indexing postfix filter file", True)
        return False
    log.info('Reloagind postfix...')
    try:
        OUTPUT = subprocess.check_output(["/usr/bin/sudo", "/usr/sbin/postfix", "reload"], stderr = subprocess.STDOUT, shell = False)
    except subprocess.CalledProcessError:
        log.info(OUTPUT, True)
        log.info("Error reloading postfix settings", True)
        return False



def add_filters_db(MSGID, ORIGINALmta, RETURNPATH, REPLYTO, SUBJECT):
    """Add filters to the database"""
    global DB_SERVER, DB_USER, DB_PASS, DB_NAME, DB_TABLE
    mtaID = False
    RPID = False
    RTID = False
    CONN = MySQLdb.connect (host = DB_SERVER, user = DB_USER, passwd = DB_PASS, db = DB_NAME, charset = 'utf8', use_unicode = True)
    MSGID = CONN.escape_string(MSGID)
    ORIGINALmta = CONN.escape_string(ORIGINALmta)
    RETURNPATH = CONN.escape_string(RETURNPATH)
    REPLYTO = CONN.escape_string(REPLYTO)
    cursor = CONN.cursor ()
    cursor.execute ("SELECT id FROM bannedservers WHERE server = %s;", (ORIGINALmta, ))
    if cursor.rowcount<1:
        cursor.execute("INSERT INTO bannedservers ( server, frommsgid ) VALUES ( %s, %s );", (ORIGINALmta, MSGID))
        mtaID = CONN.insert_id()
    else:
        cursor.execute("UPDATE bannedservers SET banned = 1 WHERE server = %s;", (ORIGINALmta, ))
        log.info("mta already in the database, banning it again.")
        mtaID = True
    cursor.execute ("SELECT id FROM bannedsenders WHERE sender = %s;", (RETURNPATH, ))
    if cursor.rowcount<1:
        cursor.execute("INSERT INTO bannedsenders ( sender, frommsgid ) VALUES ( %s, %s );", (RETURNPATH.lower(), MSGID))
        RPID = CONN.insert_id()
    else:
        cursor.execute("UPDATE bannedsenders SET banned = 1 WHERE sender = %s;", (RETURNPATH, ))
        log.info("Return path address already in the database, banning it again.")
        RPID = True
    cursor.execute ("SELECT id FROM bannedsenders WHERE sender = %s;", (REPLYTO, ))
    if cursor.rowcount<1:
        cursor.execute("INSERT INTO bannedsenders ( sender, frommsgid ) VALUES ( %s, %s );", (REPLYTO.lower(), MSGID))
        RTID = CONN.insert_id()
    else:
        cursor.execute("UPDATE bannedsenders SET banned = 1 WHERE sender = %s;", (REPLYTO, ))
        log.info("Reply To address already in the database")
        RTID = True
    cursor.execute ("SELECT id, count FROM bannedsubjects WHERE subject = %s;", (SUBJECT, ))
    if cursor.rowcount<1:
        cursor.execute("INSERT INTO bannedsubjects ( subject, frommsgid ) VALUES ( %s, %s );", (SUBJECT, MSGID))
        log.info("New spam subject '%s' added to the database." % SUBJECT)
        RTID = CONN.insert_id()
    else:
        ROW = cursor.fetchall()[0]
        cursor.execute("UPDATE bannedsubjects SET count = %s WHERE subject = %s;", (ROW[1]+1, SUBJECT))
        log.info("Subject '%s' already in the database, added count to %s" % (SUBJECT, str(ROW[1]+1)))
        RTID = True
    CONN.commit()
    cursor.close()
    CONN.close()
    return mtaID, RPID, RTID


def already_notified(mta, MAIL):
    """Check if a mail transport agent owner was already notified"""
    global DB_SERVER, DB_USER, DB_PASS, DB_NAME, DB_TABLE
    log.info("Checking if we already sent a notification to %s regarding %s" % (MAIL, mta))
    CONN = MySQLdb.connect (host = DB_SERVER, user = DB_USER, passwd = DB_PASS, db = DB_NAME, charset = 'utf8', use_unicode = True)
    mta = CONN.escape_string(mta)
    MAIL = CONN.escape_string(MAIL)
    CUR = CONN.cursor()
    mta_MAIL = '%s_%s' % (mta, MAIL)
    CUR.execute ("SELECT mta_mail FROM notifiedmtas WHERE mta_mail = %s;", (mta_MAIL, ))
    if CUR.rowcount>0:
        log.info("We already sent a notification to %s regarding %s" % (MAIL, mta))
        CUR.close()
        CONN.close()
        return True
    else:
        log.info("We didn't send a notification to %s regarding %s" % (MAIL, mta))
        return False


def add_notification(mta, MAIL):
    """Add the notification of an owner to the database"""
    global DB_SERVER, DB_USER, DB_PASS, DB_NAME, DB_TABLE
    log.info("Adding that we sent a notification to %s regarding %s" % (MAIL, mta))
    CONN = MySQLdb.connect (host = DB_SERVER, user = DB_USER, passwd = DB_PASS, db = DB_NAME, charset = 'utf8', use_unicode = True)
    mta = CONN.escape_string(mta)
    MAIL = CONN.escape_string(MAIL)
    CUR = CONN.cursor()
    mta_MAIL = '%s_%s' % (mta, MAIL)
    CUR.execute ("INSERT INTO notifiedmtas ( mta_mail ) VALUES ( %s);", (mta_MAIL, ))
    RTID = CONN.insert_id()
    CONN.commit()
    CUR.close()
    CONN.close()
    return RTID

starttime = time.time()
log = logging.getLogger()
log.setLevel(logging.getLevelName('DEBUG'))

sysloghandler = SysLogHandler()
sysloghandler.setLevel(logging.getLevelName('DEBUG'))
log.addHandler(sysloghandler)

streamhandler = logging.StreamHandler(sys.stdout)
streamhandler.setLevel(logging.getLevelName('DEBUG'))
log.addHandler(streamhandler)

process_arguments()

log.setLevel(logging.getLevelName(DEBUG))

if SSL:
    PROTO = "imaps"
else:
    PROTO = "imap"
log.info("Connecting to %s://%s:%s/ ..." % (PROTO, IMAPSERVER, IMAPPORT))
if SSL:
    try:
        IMAP = imaplib.IMAP4_SSL(IMAPSERVER, IMAPPORT)
    except:
        OLDDEBUG = DEBUG
        message ("Error connecting to '%s:%s'." % (IMAPSERVER, IMAPPORT))
        DEBUG = OLDDEBUG
        sys.exit(1)
else:
    try:
        IMAP = imaplib.IMAP4(IMAPSERVER, IMAPPORT)
    except:
        OLDDEBUG = DEBUG
        log.info("Error connecting to '%s:%s'." % (IMAPSERVER, IMAPPORT))
        DEBUG = OLDDEBUG
        sys.exit(1)
log.info("Identifying...")
try:
    IMAP.login(IMAPUSER, IMAPPASSWORD)
except imaplib.IMAP4.error as e:
    OLDDEBUG = DEBUG
    log.info("Error login as '%s@%s:%s'. %s" % (IMAPUSER, IMAPSERVER, IMAPPORT, e))
    DEBUG = OLDDEBUG
    #IMAP.close()
    IMAP.logout()
    sys.exit(1)
log.info("Selecting mailbox %s..." % IMAPMAILBOX)
try:
    STATUS, DATA = IMAP.select(IMAPMAILBOX, True)
except imaplib.IMAP4.error as e:
    OLDDEBUG = DEBUG
    log.info("Error selecting mailbox '%s@%s:%s/%s'. Server message: %s"    % (IMAPUSER, IMAPSERVER, IMAPPORT, IMAPMAILBOX, e))
    DEBUG = OLDDEBUG
    IMAP.close()
    IMAP.logout()
    sys.exit(1)
if STATUS == "NO":
    DEBUG = DEBUG + 1
    log.info("Server report an error selecting mailbox. Server response: %s" % DATA[0])
else:
    log.info("Looking for messages...")
    try:
        STATUS, IDATA = IMAP.search(None, IMAPFILTER)
    except imaplib.IMAP4.error as e:
        OLDDEBUG = DEBUG
        log.info("Error looking for messages in mailbox '%s://%s@%s:%s/%s'. Server message: %s"    % (PROTO, IMAPUSER, IMAPSERVER, IMAPPORT, IMAPMAILBOX, e))
        DEBUG = OLDDEBUG
        IMAP.logout()
        sys.exit(1)
    log.info("Received: Status: %s Data: %s" % (STATUS, IDATA))
    MSGID = ""
    FROM = ""
    REPLYTO = ""
    RETURNPATH = ""
    SUBJECT = ""
    if CSVOUTPUT:
        print("MSGID;ORIGINALmta;RETURNPATH;REPLYTO;FROM;SUBJECT")
    if IDATA == b'':
        log.info("No messages match the filter '%s' in the folder '%s'." % (IMAPFILTER, IMAPMAILBOX))
    else:
        IDS = IDATA[0].split()
        totalmessages = len(IDS)
        count = 0
        for ID in IDS:
            count = count+1
            message ("Getting headers of message %s (%s/%s)" % (ID, count, totalmessages))
            try:
                #STATUS, DATA = IMAP.fetch(ID, 'UID (FLAGS BODY[HEADER])')
                STATUS, DATA = IMAP.fetch(ID, '(FLAGS BODY[HEADER])')
            except:
                OLDDEBUG = DEBUG
                log.info("Error fetching messages headers")
                DEBUG = OLDDEBUG
                #IMAP.close()
                #IMAP.logout()
            #    sys.exit(1)
            log.info("Received. Status: %s Data %s" % (STATUS, DATA))
            if STATUS == "NO":
                log.info("Error fetching message headers, servers reponse '%s'" % DATA)
            else:
                #if is_junk(DATA):
                log.info("message flagged as junk mail, processing")
                HEADERS = DATA[0][1].decode('utf-8')
                NEWDATA = HEADERS.replace('\r', '').replace('\n ', ' ').replace('\n\t', ' ')
                ORIGINALmta = get_original_mta(NEWDATA)
                if ORIGINALmta != "":
                    log.info("Located the original server as %s" % ORIGINALmta)
                    HEADERS = NEWDATA.splitlines()
                    for HEADER in HEADERS:
                        LHEADER = HEADER.split(": ", 1)
                        HEADERNAME = LHEADER[0].lower()
                        try:
                            HEADERVALUE = LHEADER[1]
                        except IndexError:
                            HEADERVALUE = ""
                        if HEADERNAME == "message-id":
                            MSGID = HEADERVALUE.replace("<", "").replace(">", "")
                            log.info("Located message id as %s" % MSGID)
                        if HEADERNAME == "return-path":
                            RETURNPATHS = get_emails_from_text(HEADERVALUE)
                            for RETURNPATH in RETURNPATHS:
                                log.info("Located message return path as %s" % RETURNPATH)
                        if HEADERNAME == "reply-to":
                            REPLYTOS = get_emails_from_text(HEADERVALUE)
                            for REPLYTO in REPLYTOS:
                                log.info("Located message reply to as %s" % REPLYTO)
                        if HEADERNAME == "from":
                            FROMS = get_emails_from_text(HEADERVALUE)
                            for FROM in FROMS:
                                log.info("Located message sender as %s" % FROM)
                        if HEADERNAME == "subject" and SUBJECT == "":
                            try:
                                DECSUBJECTS = email.header.decode_header(HEADERVALUE)
                            except:
                                DECSUBJECTS = ""
                            for DECSUBJECT in DECSUBJECTS:
                                PARTIALSUBJECT, ENCODING = DECSUBJECT
                                if ENCODING == None:
                                    SUBJECT = "%s %s" % (SUBJECT, PARTIALSUBJECT)
                                else:
                                    SUBJECT = '%s %s' % (SUBJECT, PARTIALSUBJECT.decode(ENCODING, "replace"))
                            try:
                                SUBJECT = SUBJECT.encode("utf8", "replace")
                            except UnicodeDecodeError:
                                SUBJECT = SUBJECT.decode('iso-8859-1').encode('utf8', 'replace')
                            log.info("Located message subject as %s" % SUBJECT)

                    if CSVOUTPUT:
                        print("%s;%s;%s;%s;%s;%s" % (MSGID, ORIGINALmta, RETURNPATH, REPLYTO, FROM, SUBJECT.lstrip()))
                    add_filters(MSGID, ORIGINALmta, RETURNPATH, REPLYTO, HEADERS, SUBJECT)
                else:
                    log.info("Couldn't find the original server")
                #else:
                #    log.info("The message wasn't marked as junk")
        for ID in IDS:
                try:
                    IMAP.store(ID, '+FLAGS', '(\Seen)')
                except:
                    log.info("Error marking message as read", show = True)
                try:
                    IMAP.store(ID, '+FLAGS', '(\Deleted)')
                except:
                    log.info("Error marking message as deleted", show = True)
                IMAP.expunge()
        try:
            IMAP.close()
        except:
            OLDDEBUG = DEBUG
            log.info("Error closing connection")
            DEBUG = OLDDEBUG
    log.info('Updating postfix filters.')
    if add_filter_postfix() == False:
        log.info("Error adding filters to postfix", True)
try:
    log.info('Disconnecting from the IMAP server.')
    IMAP.logout()
except:
    log.info("Error closing connection", True)

log.info('%s warnings were sent.' % SENTWARNINGS)
message = 'From: %s\r\nTo: %s\r\nSubject: Spam notifications stats\r\n\r\n%s spam warnings were sent by update-spam-filter.' % (SENDER, SENDER, SENTWARNINGS)
server = smtplib.SMTP('localhost')
server.sendmail(SENDER, SENDER, message)
server.quit()
