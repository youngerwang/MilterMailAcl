#!/usr/bin/env python3


import os
import syslog
import argparse
import Milter
import Milter.utils
from email.header import decode_header
import json
import datetime

class MailAcl(Milter.Milter):
    rules = []

    def __init__(self):  # A new instance with each new connection.
        super().__init__()
        self.envelope_from = None
        self.envelope_to = []
        self.header_sender = None
        self.client_ip = None
        self.header_receivers = []

    def connect(self, IPname, family, hostaddr):
        self.client_ip = hostaddr[0]
        return Milter.CONTINUE

    def envfrom(self, mailfrom, *str):
        self.envelope_from = Milter.utils.parseaddr(mailfrom)[1].strip().lower()
        return Milter.CONTINUE

    def envrcpt(self, to, *str):
        self.envelope_to.append(Milter.utils.parseaddr(to)[1].strip().lower())
        return Milter.CONTINUE

    def header(self, name, hval):
        n = name.lower()
        if n == "from":
            self.header_sender = Milter.utils.parseaddr(hval)[1].strip().lower()
        elif n in ("to", "cc"):
            for i in hval.split(","):
                self.header_receivers.append(Milter.utils.parseaddr(i)[1].strip().lower())
        return Milter.CONTINUE

    def eom(self):
        #TODO: we also need to consider regex
        print("Start matching rules at", datetime.datetime.now())
        for r in self.rules:
            if  self.envelope_from in r.senders \
                and r.receivers.issuperset(self.envelope_to)\
                and self.header_sender in r.senders \
                and r.receivers.issuperset(self.header_receivers)\
                and Milter.utils.iniplist(self.client_ip, r.source_ips):
                if r.action == "accept":
                    if r.new_sender != "":
                        self.chgheader("From", 0, r.new_sender)
                        self.chgfrom(r.new_sender)
                    print("Accepted by rule #", r.rule_id)
                    return Milter.ACCEPT
                else:
                    print("Rejected by rule #", r.rule_id)
                    return Milter.REJECT
            else:
                pass
                #print("Rule", r.rule_id, "not matched.")

        print("Finish matching rules at", datetime.datetime.now())
        print("Rejected because no match is found")
        return Milter.REJECT

class MailRule:
    def __init__(self, rule_id, senders, source_ip, receivers, action, new_sender):
        self.rule_id = rule_id
        self.senders = senders
        self.source_ips = source_ip
        self.receivers = receivers
        self.action = action
        self.new_sender = new_sender
        self.counter = 0
    
    def __init__(self, json_object):
        if "rule_id" not in json_object \
            or "senders" not in json_object \
            or "source_ips" not in json_object \
            or "receivers" not in json_object \
            or "action" not in json_object \
            or "new_sender" not in json_object:
            raise Exception("Not a valid mail rule: ", json_object)
        else:
            #TODO: we need to validate source_ips and action
            self.rule_id = json_object["rule_id"]
            self.senders = set([i.lower() for i in json_object["senders"]])
            self.source_ips = json_object["source_ips"]
            self.receivers = set([i.lower() for i in json_object["receivers"]])
            self.action = json_object["action"].lower()
            self.new_sender = json_object["new_sender"].lower()
            if "counter"  in json_object:
                self.counter = json_object["counter"]
            else:
                self.counter = 0

def load_rules(config):
    with open(config, "r", encoding="utf-8") as f:
        objects = json.load(f)
        for o in objects:
            r = MailRule(o)
            #print(r.rule_id, r.senders, r.source_ips, r.receivers, r.action, r.new_sender, r.counter)
            MailAcl.rules.append(r)

    # print("----imported rules----")
    # for r in MailAcl.rules:
    #     print(r.senders, r.source_ips, r.receivers, r.action)
    # print("----imported rules----")

def arg_config():
    parser = argparse.ArgumentParser(description='Milter Mail ACL')
    help_config = "Location of the configuration file. "
    help_config += " Default is db.json in the same folder as this script."
    parser.add_argument('--config', type=str, help=help_config, default="db.json")

    help_server = "Server address and port."
    help_server += " Default is 127.0.0.1:8899"
    parser.add_argument('--server', type=str, help=help_server, default="127.0.0.1:8899")

    return  parser.parse_args()

def main():
    args = arg_config()
    (server_ip, server_port) = args.server.split(":")
    socketspec = "inet:" + server_port + ":" + server_ip
    syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_MAIL)

    print("Start loading rules at", datetime.datetime.now())
    load_rules(args.config)
    print(len(MailAcl.rules), "rules loaded")
    print("Finish loading rules at", datetime.datetime.now())

    Milter.factory = MailAcl
    Milter.set_flags(Milter.ADDHDRS)
    syslog.syslog(syslog.LOG_DEBUG, "running milter")
    Milter.runmilter("mail_acl", socketspec, 60)

    # Finished
    syslog.syslog("shutdown")


if __name__ == "__main__":
    main()
