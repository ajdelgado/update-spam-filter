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
import email
import argparse
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import subprocess
import smtplib
import logging
from logging.handlers import SysLogHandler
import json
import mysql.connector


class update_spam_filter:
    def escape_regexp_symbols(self, text):
        """Replace characters used in regular expressions"""
        if not isinstance(text, str):
            return False
        else:
            result = text
            result = result.replace("\\", "\\\\")
            result = result.replace("[", "\\[")
            result = result.replace("]", "\\]")
            result = result.replace("?", "\\?")
            result = result.replace(".", "\\.")
            result = result.replace("*", "\\*")
            result = result.replace("{", "\\{")
            result = result.replace("}", "\\}")
            result = result.replace("$", "\\$")
            result = result.replace("^", "\\^")
            result = result.replace("-", "\\-")
            result = result.replace("(", "\\(")
            result = result.replace(")", "\\)")
            result = result.replace("=", "\\=")
            result = result.replace(":", "\\:")
            result = result.replace("!", "\\!")
            result = result.replace("|", "\\|")
            result = result.replace(",", "\\,")
            return result

    def is_excluded_mta(self, mta):
        """Check if the mail transport agent is part of the ones excluded"""
        for emta in self.config["excluded_mtas"]:
            if re.search(emta, mta) is not None:
                return True
        return False

    def is_junk(self, message):
        """Check if a message is considered Junk"""
        if not isinstance(message, dict):
            return False
        if not isinstance(message[0][0], str):
            return False
        if message[0][0].find(" Junk") > -1:
            return True
        else:
            return False

    def get_original_mta(self, message):
        last_mta = ""
        for k, v in message.items():
            if k == "Received":
                array_value = v.split(" ")
                last_mta = array_value[1]
                if last_mta == 'unknown':
                    last_mta = array_value[2].replace('(','').replace(')','')
        return last_mta

    def get_emails_from_text(self, TEXT):
        """Obtain emails from a text"""
        if type(TEXT) == email.header.Header:
            TEXT = TEXT.__str__()
        if type(TEXT) == bytes:
            TEXT = TEXT.decode('utf-8')
        RES = re.findall(
            r"<?([a-zA-Z0-9\.\-]*@[a-zA-Z0-9\.\-]{2,}" r"\.[a-zA-Z0-9\.\-_]{2,})>?",
            TEXT,
        )
        if RES is not None:
            RET = list()
            for mailaddress in RES:
                if mailaddress not in RET:
                    RET.append(mailaddress)
            return RET
        else:
            return False

    def dns_query(self, domain):
        """Do a DNS query"""
        RESULT = subprocess.Popen(
            ["dig", "+short", domain],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=False,
        )
        OUTPUT = RESULT.communicate()[0]
        return OUTPUT.replace(chr(10), "")

    def get_whois_mails(self, domain):
        """Obtain emails from a whois record"""
        RESULT = subprocess.Popen(
            ["/usr/bin/whois", domain],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=False,
        )
        OUTPUT = RESULT.communicate()[0]
        wemail = self.get_emails_from_text(OUTPUT)
        return wemail

    def send_warning(self, original_mta, msg_id, HEADERS):
        """Send a warning to an email related to a domain with the
        spam message"""
        amta = original_mta.split(".")
        domain = amta[len(amta) - 2] + "." + amta[len(amta) - 1]
        RECIPIENTS = self.get_whois_mails(domain)
        if len(RECIPIENTS) < 1:
            self._log.info(
                "Unable to find an email address in the whois record for %s" % domain
            )
        else:
            for RECIPIENT in RECIPIENTS:
                if not self.already_notified(original_mta, RECIPIENT):
                    if type(RECIPIENT) == bytes:
                        RECIPIENT = RECIPIENT.decode("utf-8")
                    msg = MIMEMultipart("alternative")
                    msg["Subject"] = (
                        """The server %s was added to our spam
                    list"""
                        % original_mta
                    )
                    msg["From"] = self.config["sender"]
                    msg["To"] = RECIPIENT
                    msg["Bcc"] = "gestor@susurrando.com"
                    text = """
    Hi,
    The server %s was added to our spam list because is sending spam messages
    like the message id %s.
    Please, check the server and report back in case you would like to remove
    it from our list.
    You're receiving this message because you are in the whois record for the
    domain %s.
    Thanks

    Headers of the message:%s""" % (
                        original_mta,
                        msg_id,
                        domain,
                        HEADERS,
                    )
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
    </BODY></HTML>""" % (
                        original_mta,
                        msg_id,
                        domain,
                        HEADERS,
                    )
                    part1 = MIMEText(text, "plain")
                    part2 = MIMEText(html, "html")
                    msg.attach(part1)
                    msg.attach(part2)
                    server = smtplib.SMTP("localhost")
                    self._log.info("Sending email to '%s'" % RECIPIENT)
                    server.sendmail(self.config["sender"], RECIPIENT, msg.as_string())
                    server.quit()
                    self.count_sent_warnings += 1
                    self.add_notification(original_mta, RECIPIENT)
                    self._log.info(
                        "Sent warning mail to %s regarding domain"
                        "%s for the mta %s" % (RECIPIENT, domain, original_mta)
                    )

    def add_filters(
        self, msg_id, original_mta, return_path, reply_to, HEADERS, subject
    ):
        mta_id, RPID, RTID = self.add_filters_db(
            msg_id, original_mta, return_path, reply_to, subject
        )
        result = True
        if not mta_id or not RPID or not RTID:
            self._log.error("Error adding filter to database")
            result = False
        self.send_warning(original_mta, msg_id, HEADERS)
        return result

    def add_filter_postfix(self):
        """Add filters to the postfix configuration file"""
        OUTPUT = """#Created at %s automatically from %s\n""" % (
            time.strftime("%Y-%m%d %H:%M:%S"),
            sys.argv[0],
        )
        conn = mysql.connector.connect(
            host=self.config["dbserver"],
            user=self.config["dbuser"],
            passwd=self.config["dbpass"],
            db=self.config["dbname"],
            use_unicode=True,
            auth_plugin='mysql_native_password',
            charset='utf8mb4'
        )
        cursor = conn.cursor()
        self._log.info("Searching for banned server...")
        start = time.time()
        cursor.execute(
            """SELECT server, frommsgid
                    FROM bannedservers WHERE banned = 1;"""
        )
        for ROW in cursor.fetchall():
            if ROW[0] != "":
                msgid = self.escape_regexp_symbols(ROW[1])
                server = self.escape_regexp_symbols(ROW[0])
                OUTPUT += """#From message id %s
/^Received.*%s.*/ PREPEND X-Postfix-spam-filter: Marked as spam received from server %s rule set by message id %s\n""" % (
                    msgid,
                    server,
                    server,
                    msgid,
                )
        end = time.time()
        self._log.info("Took %s seconds." % (end - start))
        self._log.info("Searching for banned senders...")
        start = time.time()
        cursor.execute(
            """SELECT sender, frommsgid FROM bannedsenders
                    WHERE banned = 1;"""
        )
        for ROW in cursor.fetchall():
            if ROW[0] != "":
                msgid = self.escape_regexp_symbols(ROW[1])
                self.config["sender"] = self.escape_regexp_symbols(ROW[0])
                OUTPUT += """#From message id %s
/^Return-Path.*%s.*/ PREPEND X-Postfix-spam-filter: Marked as spam return path spamming %s rule set by message id %s\n""" % (
                    msgid,
                    self.config["sender"],
                    self.config["sender"],
                    msgid,
                )
                OUTPUT += """#From message id %s
/^Reply-To.*%s.*/ PREPEND X-Postfix-spam-filter: Marked as spam reply to spamming %s rule set by message id %s\n""" % (
                    msgid,
                    self.config["sender"],
                    self.config["sender"],
                    msgid,
                )
        end = time.time()
        self._log.info("Took %s seconds." % (end - start))
        self._log.info('Reconnecting to database...')
        conn.close()
        conn = mysql.connector.connect(
            host=self.config["dbserver"],
            user=self.config["dbuser"],
            passwd=self.config["dbpass"],
            db=self.config["dbname"],
            use_unicode=True,
            auth_plugin='mysql_native_password',
            charset='utf8mb4'
        )
        cursor = conn.cursor()
        self._log.info("Searching for banned subjects...")
        start = time.time()
        cursor.execute('SELECT subject, frommsgid FROM bannedsubjects WHERE count>1')
        for ROW in cursor.fetchall():
            if ROW[0] != "":
                msgid = self.escape_regexp_symbols(ROW[1])
                subject = self.escape_regexp_symbols(ROW[0])
                OUTPUT += """#From message id %s"
/^Subject.*%s.*/ PREPEND X-Postfix-spam-filter: Marked as spam reply to spamming %s rule set by message id %s\n""" % (
                    msgid,
                    subject,
                    subject,
                    msgid,
                )
        OUTPUT += "#End of automatically added data"
        end = time.time()
        self._log.info("Took %s seconds." % (end - start))
        self._log.info("Replacing dollar symbol...")
        OUTPUT = OUTPUT.replace("$", "$$")
        self._log.info(
            "Opening file '%s' to output the resulted filter..."
            % self.config["postfixheadercheckfile"]
        )
        try:
            FILEH = open(self.config["postfixheadercheckfile"], "w")
        except:
            self._log.error("Error opening filter file to append new filter", True)
            return False
        self._log.info("Writting to disk...")
        start = time.time()
        FILEH.write("%s" % OUTPUT)
        end = time.time()
        self._log.info("Took %s seconds to write to disk." % (end - start))
        FILEH.close()
        self._log.info("Running postmap command on filter's file")
        try:
            OUTPUT = subprocess.check_output(
                [
                    "/usr/bin/sudo",
                    "/usr/sbin/postmap",
                    self.config["postfixheadercheckfile"],
                ],
                stderr=subprocess.STDOUT,
                shell=False,
            )
        except subprocess.CalledProcessError:
            self._log.info(OUTPUT, True)
            self._log.error("Error indexing postfix filter file", True)
            return False
        self._log.info("Reloading postfix...")
        try:
            OUTPUT = subprocess.check_output(
                ["/usr/bin/sudo", "/usr/sbin/postfix", "reload"],
                stderr=subprocess.STDOUT,
                shell=False,
            )
        except subprocess.CalledProcessError:
            self._log.info(OUTPUT, True)
            self._log.error("Error reloading postfix settings", True)
            return False
        return True

    def add_filters_db(self, msg_id, original_mta, return_path, reply_to, subject):
        """Ban servers and senders, by adding them to the database"""
        mta_id = False
        RPID = False
        RTID = False
        conn = mysql.connector.connect(
            host=self.config["dbserver"],
            user=self.config["dbuser"],
            passwd=self.config["dbpass"],
            db=self.config["dbname"],
            auth_plugin='mysql_native_password',
            charset='utf8mb4',
            use_unicode=True,
        )
        cursor = conn.cursor(buffered=True)

        # Server ban
        self._log.info("Banning MTA %s..." % original_mta)
        cursor.execute(
            "SELECT id FROM bannedservers WHERE server = %s", params=(original_mta,)
        )
        if cursor.rowcount < 1:
            cursor.execute(
                "INSERT INTO bannedservers (server, frommsgid)" "VALUES (%s, %s)",
                params=(original_mta, msg_id),
            )
            mta_id = cursor.lastrowid
        else:
            cursor.execute(
                "UPDATE bannedservers SET banned = 1 " "WHERE server = %s",
                params=(original_mta,),
            )
            self._log.info(
                "Mail transport agent already in the database, banning it again."
            )
            mta_id = True

        # Senders ban
        # Check if the reply_to is a user in the server
        cursor.execute("SELECT email from users where email = '{}'".format(reply_to))
        if cursor.rowcount < 1:
            self._log.info("Banning sender %s..." % reply_to)
            cursor.execute(
                "SELECT id FROM bannedsenders WHERE sender = %s;", (reply_to,)
            )
            if cursor.rowcount < 1:
                cursor.execute(
                    "INSERT INTO bannedsenders (sender, frommsgid) " "VALUES (%s, %s)",
                    (reply_to.lower(), msg_id),
                )
                RTID = cursor.lastrowid
            else:
                cursor.execute(
                    "UPDATE bannedsenders SET banned = 1 " "WHERE sender = %s",
                    params=(reply_to,),
                )
                self._log.info("Reply To address already in the database")
                RTID = True
        # Check if the return path is a user in the server
        cursor.execute("SELECT email from users where email = '{}'".format(return_path))
        if cursor.rowcount < 1:
            self._log.info("Banning sender %s..." % return_path)
            cursor.execute(
                "SELECT id FROM bannedsenders " "WHERE sender = %s",
                params=(return_path,),
            )
            if cursor.rowcount < 1:
                cursor.execute(
                    "INSERT INTO bannedsenders (sender, frommsgid) " "VALUES (%s, %s)",
                    params=(return_path.lower(), msg_id),
                )
                RPID = cursor.lastrowid
            else:
                cursor.execute(
                    "UPDATE bannedsenders SET banned = 1 " "WHERE sender = %s",
                    params=(return_path,),
                )
                self._log.info(
                    "Return path address already in the database, " "banning it again."
                )
                RPID = True

        # Subject ban
        decoded_subject = (
            #subject.decode("unicode_escape").encode("iso8859-1").decode("utf8")
            subject.decode("unicode_escape")
        )
        self._log.debug("Decoded subject: %s" % decoded_subject)
        if decoded_subject not in self.config["excluded_filters"]:
            if self.number_of_words(decoded_subject) > self.config["subject_min_words"]:
                self._log.info("Banning subjects like '{}'...".format(decoded_subject))
                cursor.execute(
                    "SELECT id, count FROM bannedsubjects WHERE subject = %s",
                    params=(decoded_subject,),
                )
                if cursor.rowcount < 1:
                    cursor.execute(
                        "INSERT INTO bannedsubjects (subject, frommsgid) "
                        "VALUES (%s, %s)",
                        params=(decoded_subject, msg_id),
                    )
                    self._log.info(
                        "New spam subject '%s' added to the database." % decoded_subject
                    )
                    RTID = cursor.lastrowid
                else:
                    ROW = cursor.fetchall()[0]
                    cursor.execute(
                        "UPDATE bannedsubjects SET count = %s " "WHERE subject = %s",
                        params=(ROW[1] + 1, decoded_subject),
                    )
                    self._log.info(
                        "Subject '%s' already in the database, "
                        "added count to %s" % (decoded_subject, str(ROW[1] + 1))
                    )
                    RTID = True
            else:
                self._log.debug(
                    "Subject '{}' won't be banned, because it's too short.".format(
                        decoded_subject
                    )
                )
        else:
            self._log.debug(
                "Subject '{}' won't be banned, because is in the list not to filter.".format(
                    decoded_subject
                )
            )
        conn.commit()
        cursor.close()
        conn.close()
        return mta_id, RPID, RTID

    def already_notified(self, mta, mail):
        """Check if a mail transport agent owner was already notified"""
        self._log.info(
            "Checking if we already sent a notification to %s "
            "regarding %s" % (mail, mta)
        )
        conn = mysql.connector.connect(
            host=self.config["dbserver"],
            user=self.config["dbuser"],
            passwd=self.config["dbpass"],
            db=self.config["dbname"],
            auth_plugin='mysql_native_password',
            charset='utf8mb4',
            use_unicode=True,
        )
        cursor = conn.cursor(buffered=True)
        mta_mail = "%s_%s" % (mta, mail)
        cursor.execute(
            "SELECT mta_mail FROM notifiedmtas " "WHERE mta_mail = %s;", (mta_mail,)
        )
        if cursor.rowcount > 0:
            self._log.info(
                "We already sent a notification to %s " "regarding %s" % (mail, mta)
            )
            cursor.close()
            conn.close()
            return True
        else:
            self._log.info(
                "We didn't send a notification to %s " "regarding %s" % (mail, mta)
            )
            return False

    def add_notification(self, mta, mail):
        """Add the notification of an owner to the database"""
        self._log.info(
            "Adding that we sent a notification to %s regarding " "%s" % (mail, mta)
        )
        conn = mysql.connector.connect(
            host=self.config["dbserver"],
            user=self.config["dbuser"],
            passwd=self.config["dbpass"],
            db=self.config["dbname"],
            auth_plugin='mysql_native_password',
            charset='utf8mb4',
            use_unicode=True,
        )
        cursor = conn.cursor(buffered=True)
        mta_mail = "%s_%s" % (mta, mail)
        cursor.execute("INSERT INTO notifiedmtas (mta_mail) VALUES ( %s);", (mta_mail,))
        RTID = cursor.lastrowid
        conn.commit()
        cursor.close()
        conn.close()
        return RTID

    def number_of_words(self, text):
        if isinstance(text, bytes):
            list = re.split(r"\W+", text.decode())
        else:
            list = re.split(r"\W+", text)
        return len(list)

    def _get_config(self):
        parser = argparse.ArgumentParser(
            description="Examine messages marked as "
            "spam in an IMAP folder, add mail filters"
            " to similar messages and notify owners "
            "of the mail servers used."
        )
        parser.add_argument(
            "--excluded-filters",
            dest="excluded_filters",
            action="append",
            help="List of subjects not to filter out. Any subject filter that match a member of this list won't be added.",
        )
        parser.add_argument(
            "--excluded-mta",
            dest="excluded_mtas",
            action="append",
            help="Mail Transport Agent to exclude " "(usually does you trust)",
        )
        parser.add_argument(
            "--sender",
            dest="sender",
            default="gestor@susurrando.com",
            help="From email for notifications to spammy servers.",
        )
        parser.add_argument(
            "--imap-filter",
            dest="imapfilter",
            default="(UNSEEN)",
            help="Filter to find messages in the IMAP server.",
        )
        parser.add_argument(
            "--postfix-header-check-file",
            dest="postfixheadercheckfile",
            default="/etc/postfix/maps/spam_filter_header_check",
            help="File to store mail filters for postfix "
            "(Should be declared in /etc/postfix/main.cf in "
            "the header_checks parameter)",
        )
        parser.add_argument(
            "--debug",
            dest="debug",
            default="WARNING",
            help="Set debug level (CRITICAL, " "ERROR, WARNING, INFO, DEBUG, NOTSET)",
        )
        parser.add_argument(
            "--csv", dest="csv", default=False, help="Output to CSV format"
        )
        parser.add_argument(
            "--imap-server",
            dest="imapserver",
            default="localhost",
            help="IMAP server to get spam messages.",
        )
        parser.add_argument(
            "--imap-port",
            dest="imapport",
            default="993",
            help="IMAP port of the server.",
        )
        parser.add_argument(
            "--imap-password", dest="imappassword", help="Password of the IMAP user."
        )
        parser.add_argument("--imap-user", dest="imapuser", help="IMAP user name.")
        parser.add_argument(
            "--imap-password-file",
            dest="imappasswordfile",
            help="File containing the IMAP user's password",
        )
        parser.add_argument(
            "--imap-mailbox",
            dest="imapmailbox",
            default="INBOX",
            help="IMAP mailbox (folder) where spam messages are " "located.",
        )
        parser.add_argument(
            "--ssl",
            dest="ssl",
            default=False,
            help="Use an SSL connection to self.IMAP.",
        )
        parser.add_argument(
            "--configfile",
            dest="configfile",
            help="Config file to overwrite parameters " "from the command line",
        )
        parser.add_argument("--db-user", dest="dbuser", help="Database user name.")
        parser.add_argument(
            "--db-pass",
            dest="dbpass",
            help="(NOT RECOMMENDED) Database user's password.",
        )
        parser.add_argument(
            "--db-pass-file",
            dest="dbpassfile",
            help="File containing the database user's password.",
        )
        parser.add_argument(
            "--db-name", dest="dbname", default="mail", help="Database name."
        )
        parser.add_argument(
            "--db-table",
            dest="dbtable",
            default="spamheaders",
            help="Database user name.",
        )
        parser.add_argument(
            "--db-server", dest="dbserver", default="localhost", help="Database server."
        )
        parser.add_argument(
            "--subject_min_words",
            dest="subject_min_words",
            default=2,
            help="Minimum number of words in a subject to be banned.",
        )
        args = parser.parse_args()
        self.config = vars(args)
        if "configfile" in self.config and self.config["configfile"] is not None:
            configfile = json.load(open(self.config["configfile"], "r"))
            self.config = {**self.config, **configfile}

        if (
            "imappasswordfile" in self.config
            and self.config["imappasswordfile"] is not None
        ):
            with open(self.config["imappasswordfile"], "r") as fp:
                imappassword = fp.read()
            if imappassword != "":
                self.config["imappassword"] = imappassword.strip()
                self._log.debug(
                    "IMAP password obtained from password file %s"
                    % self.config["imappasswordfile"]
                )

        if "dbpassfile" in self.config and self.config["dbpassfile"] is not None:
            with open(self.config["dbpassfile"], "r") as fp:
                dbpassfile = fp.read()
            if dbpassfile != "":
                self.config["dbpass"] = dbpassfile.strip()
                self._log.debug(
                    "Database password obtained from password file %s"
                    % self.config["dbpassfile"]
                )
        return True

    def _get_imap_connection(self):
        if "ssl" in self.config and self.config["ssl"]:
            self.PROTO = "imaps"
        else:
            self.PROTO = "imap"
        self._log.info(
            "Connecting to %s://%s:%s/ ..."
            % (
                self.PROTO,
                self.config.get("imapserver", ""),
                self.config.get("imapport", ""),
            )
        )
        if "ssl" in self.config and self.config["ssl"]:
            try:
                self.IMAP = imaplib.IMAP4_SSL(
                    self.config["imapserver"], self.config["imapport"]
                )
            except:
                self._log.error(
                    "Error connecting to '%s:%s'."
                    % (self.config["imapserver"], self.config["imapport"])
                )
                sys.exit(1)
        else:
            try:
                self.IMAP = imaplib.IMAP4(
                    self.config["imapserver"], self.config["imapport"]
                )
            except:
                self._log.error(
                    "Error connecting to '%s:%s'."
                    % (self.config["imapserver"], self.config["imapport"])
                )
                sys.exit(1)
        self._log.info("Identifying as %s..." % self.config["imapuser"])
        try:
            self.IMAP.login(self.config["imapuser"], self.config["imappassword"])
        except imaplib.IMAP4.error as e:
            self._log.error(
                "Error login as '%s:%s@%s:%s'. %s"
                % (
                    self.config["imapuser"],
                    self.config["imapserver"],
                    self.config["imapport"],
                    e,
                )
            )
            sys.exit(1)
        return True

    def _find_messages(self):
        self._log.info("Looking for messages...")
        try:
            STATUS, IDATA = self.IMAP.search(None, self.config["imapfilter"])
        except imaplib.IMAP4.error as e:
            self._log.error(
                "Error looking for messages in mailbox '%s://%s@%s:%s/%s'. "
                "Server message: %s"
                % (
                    self.PROTO,
                    self.config["imapuser"],
                    self.config["imapserver"],
                    self.config["imapport"],
                    self.config["imapmailbox"],
                    e,
                )
            )
            self.IMAP.close()
            self.IMAP.logout()
            sys.exit(1)
        return STATUS, IDATA

    def _remove_processed_messages(self, IDS):
        for ID in IDS:
            try:
                self.IMAP.store(ID, "+FLAGS", "(\\Seen)")
            except imaplib.IMAP4.error as e:
                self._log.error("Error marking message as read. %s", e)
            try:
                self.IMAP.store(ID, "+FLAGS", "(\\Deleted)")
            except imaplib.IMAP4.error as e:
                self._log.error("Error marking message as deleted. %s", e)
                return False
            self.IMAP.expunge()
        return True

    def _get_subject(self, msg):
        subject = ""
        try:
            DECsubjectS = email.header.decode_header(msg.get("Subject", ""))
        except:
            DECsubjectS = ""
        for DECsubject in DECsubjectS:
            PARTIALsubject, ENCODING = DECsubject
            if ENCODING is None:
                subject = "%s %s" % (subject, PARTIALsubject)
            elif ENCODING == 'unknown-8bit':
                subject = "%s %s" % (
                    subject,
                    PARTIALsubject.decode('utf-8', "replace"),
                )
            else:
                subject = "%s %s" % (
                    subject,
                    PARTIALsubject.decode(ENCODING, "replace"),
                )
        try:
            subject = subject.encode("utf8", "replace")
        except UnicodeDecodeError:
            subject = subject.decode("iso-8859-1").encode("utf8", "replace")
        self._log.info("Located message subject as %s" % subject)
        return subject

    def _process_message(self, ID):
        try:
            STATUS, DATA = self.IMAP.fetch(ID, "(FLAGS BODY[HEADER])")
        except imaplib.IMAP4.error as e:
            self._log.error("Error fetching messages headers. %s" % e)
        self._log.info("Received. Status: %s Data %s" % (STATUS, DATA))
        if STATUS == "NO":
            self._log.error(
                "Error fetching message headers, servers " "reponse '%s'" % DATA
            )
            return False
        self._log.info("message flagged as junk mail, processing")
        HEADERS = DATA[0][1]
        msg = email.message_from_bytes(HEADERS)
        msg_id = msg.get("Message-ID", "").replace("<", "").replace(">", "")
        return_pathS = self.get_emails_from_text(msg.get("Return-Path", ""))
        return_path = ""
        for return_path in return_pathS:
            self._log.info("Located message return path as %s" % return_path)
        reply_toS = self.get_emails_from_text(msg.get("Reply-To", ""))
        reply_to = ""
        for reply_to in reply_toS:
            self._log.info("Located message reply to as %s" % reply_to)
        FROMS = self.get_emails_from_text(msg.get("From", ""))
        FROM = ""
        for FROM in FROMS:
            self._log.info("Located message sender as %s" % FROM)
        subject = self._get_subject(msg)

        original_mta = self.get_original_mta(msg)
        if original_mta != "":
            self._log.info("Located the original server as %s" % original_mta)

            if self.config["csv"]:
                print(
                    "%s;%s;%s;%s;%s;%s"
                    % (
                        msg_id,
                        original_mta,
                        return_path,
                        reply_to,
                        FROM,
                        subject.lstrip(),
                    )
                )
            self.add_filters(
                msg_id, original_mta, return_path, reply_to, HEADERS, subject
            )
        else:
            self._log.warning("Couldn't find the original server")

    def __init__(self):
        self.config = dict()
        self.count_sent_warnings = 0
        starttime = time.time()
        self._log = logging.getLogger()
        self._log.setLevel(logging.getLevelName("DEBUG"))

        sysloghandler = SysLogHandler()
        sysloghandler.setLevel(logging.getLevelName("DEBUG"))
        self._log.addHandler(sysloghandler)

        streamhandler = logging.StreamHandler(sys.stdout)
        streamhandler.setLevel(logging.getLevelName("DEBUG"))
        self._log.addHandler(streamhandler)

        self._get_config()

        if "debug" in self.config:
            self._log.setLevel(logging.getLevelName(self.config["debug"]))
        else:
            self._log.setLevel(logging.getLevelName("INFO"))

        self._get_imap_connection()

        self._log.info("Selecting mailbox %s..." % self.config["imapmailbox"])
        try:
            STATUS, DATA = self.IMAP.select(self.config["imapmailbox"], True)
        except imaplib.IMAP4.error as e:
            self._log.error(
                "Error selecting mailbox '%s@%s:%s/%s'. Server message: %s"
                % (
                    self.config["imapuser"],
                    self.config["imapserver"],
                    self.config["imapport"],
                    self.config["imapmailbox"],
                    e,
                )
            )
            self.IMAP.close()
            self.IMAP.logout()
            sys.exit(1)
        if STATUS == "NO":
            self._log.error(
                "Server report an error selecting mailbox. Server response: %s"
                % DATA[0]
            )
            self.IMAP.close()
            self.IMAP.logout()
            sys.exit(1)
        STATUS, IDATA = self._find_messages()
        self._log.info("Received: Status: %s Data: %s" % (STATUS, IDATA))
        if self.config["csv"]:
            print("msg_id;original_mta;return_path;reply_to;FROM;subject")
        if IDATA == b"":
            self._log.warning(
                "No messages match the filter '%s' in the folder '%s'."
                % (self.config["imapfilter"], self.config["imapmailbox"])
            )
        else:
            IDS = IDATA[0].split()
            totalmessages = len(IDS)
            count = 0
            for ID in IDS:
                count = count + 1
                self._log.info(
                    "Getting headers of message %s (%s/%s)" % (ID, count, totalmessages)
                )
                try:
                    self._process_message(ID)
                except:
                    self._log.error("Error processing message with ID '%s'." % ID)
            self._remove_processed_messages(IDS)
            try:
                self.IMAP.close()
            except imaplib.IMAP4.error as e:
                self._log.error("Error closing connection. %s", e)
            self._log.info("Updating postfix filters.")
            if not self.add_filter_postfix():
                self._log.error("Error adding filters to postfix")
        try:
            self._log.info("Disconnecting from the IMAP server.")
            self.IMAP.logout()
        except imaplib.IMAP4.error as e:
            self._log.error("Error closing connection. %s" % e)

        endtime = time.time()
        elapsedtimes = endtime - starttime
        self._log.info("%s warnings were sent." % self.count_sent_warnings)
        message = """From: %s\r\nTo: %s\r\nSubject: Spam notifications stats\r\n\r\n
        %s spam warnings were sent by
        update-spam-filter in %s seconds.""" % (
            self.config["sender"],
            self.config["sender"],
            self.count_sent_warnings,
            elapsedtimes,
        )
        server = smtplib.SMTP("localhost")
        server.sendmail(self.config["sender"], self.config["sender"], message)
        server.quit()


if __name__ == "__main__":
    update_spam_filter()
