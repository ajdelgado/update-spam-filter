#!/usr/bin/python3
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
import os,sys,getpass,time
import re
import imaplib
import email.header
import MySQLdb
import chardet
import subprocess
import smtplib
import syslog
IMAPSERVER="localhost"
IMAPPORT="993"
IMAPUSER=""
IMAPPASSWORD=""
IMAPMAILBOX="INBOX"
DB_USER="spam-filter"
DB_PASS="buPKcpjnwH7VveaCFHxWrtrY"
DB_NAME="mail"
DB_TABLE="spamheaders"
DB_SERVER="localhost"
SENDER="gestor@susurrando.com"
IMAPFILTER='(UNSEEN)'
POSTFIX_HEADER_CHECK_FILE="/etc/postfix/maps/spam_filter_header_check"
EXCLUDE_MTAS={"gmail.com", "localhost.localdomain","msrv.koti.site","bankinter.bankinter.com","smtpi.msn.com","telefonica.net","mta1.susurrando.com","srv.susurrando.com","correo.susurrando.com","mudito.susurrando.com","webmail.susurrando.com","facebook.com","google.com","vadelma.susurrando.com","mora.susurrando.com"}
SSL=False
DEBUG=0
CSVOUTPUT=False
SENTWARNINGS=0
def EscapeRegExpSymbols(text):
    result=text
    result=result.replace('\\','\\\\')
    result=result.replace('[','\[')
    result=result.replace(']','\]')
    result=result.replace('?','\?')
    result=result.replace('.','\.')
    result=result.replace('*','\*')
    result=result.replace('{','\{')
    result=result.replace('}','\}')
    result=result.replace('$','\$')
    result=result.replace('^','\^')
    result=result.replace('-','\-')
    result=result.replace('(','\(')
    result=result.replace(')','\)')
    result=result.replace('=','\=')
    result=result.replace(':','\:')
    result=result.replace('!','\!')
    result=result.replace('|','\|')
    result=result.replace(',','\,')
    return result
def Message(text,show=False):
  global DEBUG
  date=time.time()
  message="%s %s" % (date,text)
  syslog.syslog(syslog.LOG_DEBUG,message)
  if DEBUG > 0 or show:
    print(message)
def IsExcludeMTA(MTA):
  global EXCLUDE_MTAS
  for EMTA in EXCLUDE_MTAS:
    #if MTA == EMTA:
    if re.search(EMTA,MTA) != None:
      return True
  return False
def ProcessArguments():
  global DEBUG,IMAPSERVER,IMAPPORT,IMAPUSER,IMAPPASSWORD,IMAPMAILBOX,SSL
  for arg in sys.argv:
    if arg=="-h" or arg=="--help" or arg=="-?" or arg=="/?" or arg=="/h" or arg=="/help":
      Usage()
      sys.exit(0)
    if arg=="-d" or arg== "--debug":
      DEBUG=DEBUG+1
      Message("Debug level incressed")
    if arg.lower()=="--ssl":
      Message("Will use SSL")
      SSL=True
    if arg.lower()=="-s":
      Message("Will use SSL")
      SSL=True
    if arg.lower()=="-c" or arg.lower()=="--csv":
      Message("Will output as CSV format")
      CSVOUTPUT=True
    if arg.lower()=="-a" or arg.lower()=="--all-messages":
      Message("Will process all IMAP messages, not only unseen.")
      IMAPFILTER='ALL'
    larg=arg.split("=",1)
    if len(larg)==2:
      if larg[0].lower()=="--imap-server":
        Message("Server will be '%s'" % larg[1])
        IMAPSERVER=larg[1]
      if larg[0].lower()=="--imap-port":
        Message("Port will be '%s'" % larg[1])
        IMAPPORT=larg[1]
      if larg[0].lower()=="--imap-user":
        Message("User will be '%s'" % larg[1])
        IMAPUSER=larg[1]
      if larg[0].lower()=="--imap-password":
        if larg[1] != "":
          Message("Password is set")
        IMAPPASSWORD=larg[1]
      if larg[0].lower()=="--imap-mailbox":
        Message("Mailbox will be '%s'" % larg[1])
        IMAPMAILBOX=larg[1]
      if larg[0].lower()=="--imap-password-file":
        Message("Reading password from file '%s'" % larg[1])
        if os.path.exists(larg[1]):
          FILE=open(larg[1],"r")
          IMAPPASSWORD=FILE.readline().replace("\n","").replace("\r","")
          FILE.close()
        else:
          Message("The password file '%s' doesn't exists" % larg[1])
          sys.exit(65)
  if IMAPPASSWORD == "":
    IMAPPASSWORD=getpass.getpass("Password for '%s@%s:%s': " % (IMAPUSER,IMAPSERVER,IMAPPORT))
  #Message("Password will be '%s'" % IMAPPASSWORD)
  if IMAPSERVER == "":
    Message("You must indicate a server to connecto to")
    Usage()
    sys.exit(65)
  if IMAPUSER == "":
    Message("You must indicate a username")
    Usage()
    sys.exit(65)
  if IMAPMAILBOX == "":
    Message("You must indicate a mailbox in the server")
    Usage()
    sys.exit(65)
def Usage():
  print("%s [-h] [-d] [--csv] [--imap-server=IMAPSERVER --imap-port=IMAPPORT --imap-user=IMAPUSER --imap-password=IMAPPASSWORD --imap-password-file=IMAPPASSWORDFILE --imap-mailbox=IMAPMAILBOX] [--ssl|-s]" % sys.argv[0])
  print("\t--csv | -c\tOutput information of mail messages as CSV format")
  print("\t--help | -h\tShow this help")
  print("\t--debug | -d\tShow extra debug information")
def IsJunk(MESSAGE):
  if MESSAGE[0][0].find(" Junk")>-1:
    return True
  else:
    return False
def GetOriginalMTA(MESSAGE):
  RES=re.finditer("Received: from ([a-zA-Z0-9\.-_+]*\.[a-zA-Z]{2,}) ",NEWDATA)
  ORIGINALMTA=""
  for MTA in RES:
    if not IsExcludeMTA(MTA.group(1)):
      #ORIGINALMTA="\tReceived: %s (%s)" % (MTA.group(1),MTA.group(0))
      ORIGINALMTA=MTA.group(1)
  return ORIGINALMTA
def GetEmailsFromText(TEXT):
  if type(TEXT)==bytes:
    TEXT=TEXT.decode("utf-8")
  RES=re.findall("<?([a-zA-Z0-9\.\-]*@[a-zA-Z0-9\.\-]{2,}\.[a-zA-Z0-9\.\-_]{2,})>?",TEXT)
  if RES != None:
    RET=list()
    for email in RES:
      if email not in RET:
        RET.append(email)
    return RET
  else:
    return False
def DNSQuery(DOMAIN):
  RESULT=subprocess.Popen(['dig','+short',DOMAIN], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=False)
  OUTPUT=RESULT.communicate()[0]
  return OUTPUT.replace(chr(10),"")
def GetWhoisMails(DOMAIN):
  RESULT=subprocess.Popen(['/usr/bin/whois',DOMAIN], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=False)
  OUTPUT=RESULT.communicate()[0]
  wemail=GetEmailsFromText(OUTPUT)
  return wemail
def SendWarning(ORIGINALMTA,MSGID,HEADERS):
  global SENDER,SENTWARNINGS
  aMTA=ORIGINALMTA.split(".")
  DOMAIN=aMTA[len(aMTA)-2]+"."+aMTA[len(aMTA)-1]
  RECIPIENTS=GetWhoisMails(DOMAIN)
  if len(RECIPIENTS)<1:
    Message("Unable to find an email address in the whois record for %s" % DOMAIN)
  else:
    for RECIPIENT in RECIPIENTS:
      if not AlreadyNotified(ORIGINALMTA,RECIPIENT):
        MESSAGE="Hi,\nThe server %s was added to our spam list because is sending spam messages like the message id %s.\nPlease, check the server and report back in case you would like to remove it from our list.\nYou're receiving this message because you are in the whois record for the domain %s.\nThanks\n\n\nHeaders of the message:%s" % (ORIGINALMTA,MSGID,DOMAIN,HEADERS)
        server = smtplib.SMTP('localhost')
        server.sendmail(SENDER, RECIPIENT, MESSAGE)
        server.quit()
        SENTWARNINGS += 1
        AddNotification(ORIGINALMTA,RECIPIENT)
        Message("Sent warning mail to %s regarding domain %s for the MTA %s" % (RECIPIENT,DOMAIN,ORIGINALMTA))
def AddFilters(MSGID,ORIGINALMTA,RETURNPATH,REPLYTO,HEADERS,SUBJECT):
  MTAID,RPID,RTID=AddFiltersDB(MSGID,ORIGINALMTA,RETURNPATH,REPLYTO,SUBJECT)
  result=True
  if MTAID == False or RPID == False or RTID == False:
    Message("Error adding filter to database")
    result=False
  SendWarning(ORIGINALMTA,MSGID,HEADERS)
  return result

def AddFilterPostfix():
  global DB_SERVER,DB_USER,DB_PASS,DB_NAME,DB_TABLE,POSTFIX_HEADER_CHECK_FILE
  OUTPUT="#Created at %s automatically from %s\n" % (time.strftime("%Y-%m%d %H:%M:%S"),sys.argv[0])
  CONN = MySQLdb.connect (host = DB_SERVER,user = DB_USER,passwd = DB_PASS,db = DB_NAME,charset='utf8',use_unicode=True)
  CUR=CONN.cursor()
  CUR.execute ("SELECT server,frommsgid FROM bannedservers WHERE banned=1;")
  for ROW in CUR.fetchall():
    if ROW[0] != "":
      msgid=EscapeRegExpSymbols(ROW[1])
      server=EscapeRegExpSymbols(ROW[0])
      OUTPUT="%s#From message id %s\n/^Received.*%s.*/ PREPEND X-Postfix-spam-filter: Marked as spam received from server %s rule set by message id %s\n" % (OUTPUT,msgid,server,server,msgid)
  CUR.execute ("SELECT sender,frommsgid FROM bannedsenders WHERE banned=1;")
  for ROW in CUR.fetchall():
    if ROW[0] != "":
      msgid=EscapeRegExpSymbols(ROW[1])
      sender=EscapeRegExpSymbols(ROW[0])
      OUTPUT="%s#From message id %s\n/^Return-Path.*%s.*/ PREPEND X-Postfix-spam-filter: Marked as spam return path spamming %s rule set by message id %s\n" % (OUTPUT,msgid,sender,sender,msgid)
  CUR.execute ("SELECT sender,frommsgid FROM bannedsenders WHERE banned=1;")
  for ROW in CUR.fetchall():
    if ROW[0] != "":
      msgid=EscapeRegExpSymbols(ROW[1])
      sender=EscapeRegExpSymbols(ROW[0])
      OUTPUT="%s#From message id %s\n/^Reply-To.*%s.*/ PREPEND X-Postfix-spam-filter: Marked as spam reply to spamming %s rule set by message id %s\n" % (OUTPUT,msgid,sender,sender,msgid)
  CUR.execute ("SELECT subject,frommsgid FROM bannedsubjects WHERE count>1;")
  for ROW in CUR.fetchall():
    if ROW[0] != "":
      msgid=EscapeRegExpSymbols(ROW[1])
      subject=EscapeRegExpSymbols(ROW[0])
      OUTPUT="%s#From message id %s\n/^Subject.*%s.*/ PREPEND X-Postfix-spam-filter: Marked as spam reply to spamming %s rule set by message id %s\n" % (OUTPUT,msgid,subject,subject,msgid)
  OUTPUT="%s#End of automatically added data" % OUTPUT
  OUTPUT=OUTPUT.replace('$','$$')
  try:
    FILEH=open(POSTFIX_HEADER_CHECK_FILE,"w")
  except:
    Message("Error opening filter file to append new filter",True)
    return False
  FILEH.write("%s" % OUTPUT)
  FILEH.close()
  try:
    OUTPUT=subprocess.check_output(["/usr/sbin/postmap",POSTFIX_HEADER_CHECK_FILE], stderr=subprocess.STDOUT, shell=False)
  except subprocess.CalledProcessError:
    Message(OUTPUT,True)
    Message("Error indexing postfix filter file",True)
    return False
  try:
    OUTPUT=subprocess.check_output(["/usr/sbin/postfix","reload"],stderr=subprocess.STDOUT, shell=False)
  except subprocess.CalledProcessError:
    Message(OUTPUT,True)
    Message("Error reloading postfix settings",True)
    return False

def AddFiltersDB(MSGID,ORIGINALMTA,RETURNPATH,REPLYTO,SUBJECT):
  global DB_SERVER,DB_USER,DB_PASS,DB_NAME,DB_TABLE
  MTAID=False
  RPID=False
  RTID=False
  CONN = MySQLdb.connect (host = DB_SERVER,user = DB_USER,passwd = DB_PASS,db = DB_NAME,charset='utf8',use_unicode=True)
  MSGID=CONN.escape_string(MSGID)
  ORIGINALMTA=CONN.escape_string(ORIGINALMTA)
  RETURNPATH=CONN.escape_string(RETURNPATH)
  REPLYTO=CONN.escape_string(REPLYTO)
  cursor = CONN.cursor ()
  cursor.execute ("SELECT id FROM bannedservers WHERE server = %s;", (ORIGINALMTA,))
  if cursor.rowcount<1:
    cursor.execute("INSERT INTO bannedservers ( server, frommsgid ) VALUES ( %s, %s );", (ORIGINALMTA,MSGID))
    MTAID=CONN.insert_id()
  else:
    cursor.execute("UPDATE bannedservers SET banned = 1 WHERE server = %s;", (ORIGINALMTA,))
    Message("MTA already in the database, banning it again.")
  cursor.execute ("SELECT id FROM bannedsenders WHERE sender = %s;", (RETURNPATH,))
  if cursor.rowcount<1:
    cursor.execute("INSERT INTO bannedsenders ( sender, frommsgid ) VALUES ( %s, %s );", (RETURNPATH.lower(),MSGID))
    RPID=CONN.insert_id()
  else:
    cursor.execute("UPDATE bannedsenders SET banned = 1 WHERE sender = %s;", (RETURNPATH,))
    Message("Return path address already in the database, banning it again.")
  cursor.execute ("SELECT id FROM bannedsenders WHERE sender = %s;", (REPLYTO,))
  if cursor.rowcount<1:
    cursor.execute("INSERT INTO bannedsenders ( sender, frommsgid ) VALUES ( %s, %s );", (REPLYTO.lower(),MSGID))
    RTID=CONN.insert_id()
  else:
    cursor.execute("UPDATE bannedsenders SET banned = 1 WHERE sender = %s;", (REPLYTO,))
    Message("Reply To address already in the database")
  cursor.execute ("SELECT id,count FROM bannedsubjects WHERE subject = %s;", (SUBJECT.lower(),))
  if cursor.rowcount<1:
    cursor.execute("INSERT INTO bannedsubjects ( subject, frommsgid ) VALUES ( %s, %s );", (SUBJECT.lower(),MSGID))
    RTID=CONN.insert_id()
  else:
    ROW=cursor.fetchall()[0]
    cursor.execute("UPDATE bannedsubjects SET count = %s WHERE subject = %s;", (ROW[1]+1, SUBJECT))
    Message("Subject address already in the database, added count to %s" % ROW[1]+1)
  CONN.commit()
  cursor.close()
  CONN.close()
  return MTAID,RPID,RTID
def AlreadyNotified(MTA,MAIL):
  global DB_SERVER,DB_USER,DB_PASS,DB_NAME,DB_TABLE
  Message("Checking if we already sent a notification to %s regarding %s" % (MAIL,MTA))
  CONN = MySQLdb.connect (host = DB_SERVER,user = DB_USER,passwd = DB_PASS,db = DB_NAME,charset='utf8',use_unicode=True)
  MTA=CONN.escape_string(MTA)
  MAIL=CONN.escape_string(MAIL)
  CUR=CONN.cursor()
  MTA_MAIL='%s_%s' % (MTA,MAIL)
  CUR.execute ("SELECT mta_mail FROM notifiedmtas WHERE mta_mail=%s;", (MTA_MAIL,))
  if CUR.rowcount>0:
    Message("We already sent a notification to %s regarding %s" % (MAIL,MTA))
    CUR.close()
    CONN.close()
    return True
  else:
    Message("We didn't send a notification to %s regarding %s" % (MAIL,MTA))
    return False
def AddNotification(MTA,MAIL):
  global DB_SERVER,DB_USER,DB_PASS,DB_NAME,DB_TABLE
  Message("Adding that we sent a notification to %s regarding %s" % (MAIL,MTA))
  CONN = MySQLdb.connect (host = DB_SERVER,user = DB_USER,passwd = DB_PASS,db = DB_NAME,charset='utf8',use_unicode=True)
  MTA=CONN.escape_string(MTA)
  MAIL=CONN.escape_string(MAIL)
  CUR=CONN.cursor()
  MTA_MAIL='%s_%s' % (MTA,MAIL)
  CUR.execute ("INSERT INTO notifiedmtas ( mta_mail ) VALUES ( %s);", (MTA_MAIL,))
  RTID=CONN.insert_id()
  CONN.commit()
  CUR.close()
  CONN.close()
  return RTID

ProcessArguments()
if SSL:
  PROTO="imaps"
else:
  PROTO="imap"
Message("Connecting to %s://%s:%s/ ..." % (PROTO,IMAPSERVER,IMAPPORT))
if SSL:
  try:
    IMAP=imaplib.IMAP4_SSL(IMAPSERVER, IMAPPORT)
  except:
    OLDDEBUG=DEBUG
    Message ("Error connecting to '%s:%s'." % (IMAPSERVER,IMAPPORT))
    DEBUG=OLDDEBUG
    sys.exit(1)
else:
  try:
    IMAP=imaplib.IMAP4(IMAPSERVER, IMAPPORT)
  except:
    OLDDEBUG=DEBUG
    Message("Error connecting to '%s:%s'." % (IMAPSERVER,IMAPPORT))
    DEBUG=OLDDEBUG
    sys.exit(1)
Message("Identifying...")
try:
  IMAP.login(IMAPUSER,IMAPPASSWORD)
except imaplib.IMAP4.error as e:
  OLDDEBUG=DEBUG
  Message("Error login as '%s@%s:%s'. %s" % (IMAPUSER,IMAPSERVER,IMAPPORT,e))
  DEBUG=OLDDEBUG
  #IMAP.close()
  IMAP.logout()
  sys.exit(1)
Message("Selecting mailbox %s..." % IMAPMAILBOX)
try:
  STATUS,DATA=IMAP.select(IMAPMAILBOX,True)
except imaplib.IMAP4.error as e:
  OLDDEBUG=DEBUG
  Message("Error selecting mailbox '%s@%s:%s/%s'. Server message: %s"  % (IMAPUSER,IMAPSERVER,IMAPPORT,IMAPMAILBOX,e))
  DEBUG=OLDDEBUG
  IMAP.close()
  IMAP.logout()
  sys.exit(1)
if STATUS == "NO":
  DEBUG=DEBUG + 1
  Message("Server report an error selecting mailbox. Server response: %s" % DATA[0])
else:
  Message("Looking for messages...")
  try:
    STATUS,IDATA=IMAP.search(None,IMAPFILTER)
  except imaplib.IMAP4.error as e:
    OLDDEBUG=DEBUG
    Message("Error looking for messages in mailbox '%s://%s@%s:%s/%s'. Server message: %s"  % (PROTO,IMAPUSER,IMAPSERVER,IMAPPORT,IMAPMAILBOX,e))
    DEBUG=OLDDEBUG
    IMAP.logout()
    sys.exit(1)
  Message("Received: Status: %s Data: %s" % (STATUS,IDATA))
  MSGID=""
  FROM=""
  REPLYTO=""
  RETURNPATH=""
  SUBJECT=""
  if CSVOUTPUT:
    print("MSGID;ORIGINALMTA;RETURNPATH;REPLYTO;FROM;SUBJECT")
  IDS=IDATA[0].split()
  totalmessages=len(IDS)
  count=0
  for ID in IDS:
    count=count+1
    Message ("Getting headers of message %s (%s/%s)" % (ID,count,totalmessages))
    try:
      #STATUS,DATA = IMAP.fetch(ID, 'UID (FLAGS BODY[HEADER])')
      STATUS,DATA = IMAP.fetch(ID, '(FLAGS BODY[HEADER])')
    except:
      OLDDEBUG=DEBUG
      Message("Error fetching messages headers")
      DEBUG=OLDDEBUG
      #IMAP.close()
      #IMAP.logout()
    #  sys.exit(1)
    Message("Received. Status: %s Data %s" % (STATUS,DATA))
    if STATUS == "NO":
      Message("Error fetching message headers, servers reponse '%s'" % DATA)
    else:
      #if IsJunk(DATA):
      Message("Message flagged as junk mail, processing")
      HEADERS=DATA[0][1].decode('utf-8') 
      NEWDATA=HEADERS.replace('\r','').replace('\n ',' ').replace('\n\t',' ')
      ORIGINALMTA=GetOriginalMTA(NEWDATA)
      if ORIGINALMTA != "":
        Message("Located the original server as %s" % ORIGINALMTA)
        HEADERS=NEWDATA.splitlines()
        for HEADER in HEADERS:
          LHEADER=HEADER.split(": ",1)
          HEADERNAME=LHEADER[0].lower()
          try:
            HEADERVALUE=LHEADER[1]
          except IndexError:
            HEADERVALUE=""
          if HEADERNAME=="message-id":
            MSGID=HEADERVALUE.replace("<","").replace(">","")
            Message("Located message id as %s" % MSGID)
          if HEADERNAME=="return-path":
            RETURNPATHS=GetEmailsFromText(HEADERVALUE)
            for RETURNPATH in RETURNPATHS:
              Message("Located message return path as %s" % RETURNPATH)
          if HEADERNAME=="reply-to":
            REPLYTOS=GetEmailsFromText(HEADERVALUE)
            for REPLYTO in REPLYTOS:
              Message("Located message reply to as %s" % REPLYTO)
          if HEADERNAME=="from":
            FROMS=GetEmailsFromText(HEADERVALUE)
            for FROM in FROMS:
              Message("Located message sender as %s" % FROM)
          if HEADERNAME=="subject" and SUBJECT=="":
            try:
              DECSUBJECTS=email.header.decode_header(HEADERVALUE)
            except:
              DECSUBJECTS=""
            for DECSUBJECT in DECSUBJECTS:
              PARTIALSUBJECT,ENCODING=DECSUBJECT
              if ENCODING == None:
                SUBJECT="%s %s" % (SUBJECT,PARTIALSUBJECT)
              else:
                SUBJECT='%s %s' % (SUBJECT, PARTIALSUBJECT.decode(ENCODING,"replace"))
            try:
              SUBJECT=SUBJECT.encode("utf8","replace")
            except UnicodeDecodeError:
              SUBJECT=SUBJECT.decode('iso-8859-1').encode('utf8','replace')
            Message("Located message subject as %s" % SUBJECT)

        if CSVOUTPUT:
          print("%s;%s;%s;%s;%s;%s" % (MSGID,ORIGINALMTA,RETURNPATH,REPLYTO,FROM,SUBJECT.lstrip()))
        AddFilters(MSGID,ORIGINALMTA,RETURNPATH,REPLYTO,HEADERS,SUBJECT)
      else:
        Message("Couldn't find the original server")
      #else:
      #  Message("The message wasn't marked as junk")
  for ID in IDS:
      try:
        IMAP.store(ID, '+FLAGS', '(\Seen)')
      except:
        Message("Error marking message as read",show=True)
      try:
        IMAP.store(ID, '+FLAGS', '(\Deleted)')
      except:
        Message("Error marking message as deleted",show=True)
      IMAP.expunge()
  try:
    IMAP.close()
  except:
    OLDDEBUG=DEBUG
    Message("Error closing connection")
    DEBUG=OLDDEBUG
try:
  IMAP.logout()
except:
  OLDDEBUG=DEBUG
  Message("Error closing connection")
  DEBUG=OLDDEBUG

if AddFilterPostfix() == False:
  Message("Error adding filters to postfix",True)
Message('%s warnings were sent.' % SENTWARNINGS)
MESSAGE='%s spam warnings were sent by update-spam-filter.' % SENTWARNINGS
server = smtplib.SMTP('localhost')
server.sendmail(SENDER, SENDER, MESSAGE)
server.quit()
