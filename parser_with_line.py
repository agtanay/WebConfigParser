from xml.dom import minidom
import os
import sys
import xml.sax
from xml.sax import saxutils
from xml.sax import make_parser
from xml.sax import handler

path = sys.argv[1]
fileslist = []
codeDone = []
#OPEN THE FILE WHICH CONTAINS THE XML OUTPUT IN APPEND MODE
f = open('output.xml', 'a')
f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
f.write('<Vulnerabilities>\n')

for dirpath, subdirs, files in os.walk(path):
    if 'Web.config' or 'web.config' or 'Web.Config' or 'web.Config' or 'WEB.CONFIG' in files:
        fileslist.append(dirpath + '\web.config')

        #TRACE FOR ALL THE "Web.config" FILES IN THE GIVEN PATH

for items in fileslist:
    xmldoc = minidom.parse(items)


    class SimpleHandler(xml.sax.ContentHandler):
        def setDocumentLocator(self, locator):
            self.locator = locator


        #BASIC EVENT HANDLER WHICH WORKS ON ENCOUNTER OF EACH NODE
        def startElement(self, name, attrs):
            line = self.locator.getLineNumber()
            list1 = ''
            b = []
            #CHECK IF THE PAGES VALIDATEREQUEST IS NOT SET TO FALSE
            if name == "pages" and attrs.get("validateRequest") and str(attrs.get("validateRequest")).lower() == "false":
                itemlist = xmldoc.getElementsByTagName('pages')
                for element in itemlist:
                    if element.getAttribute('validateRequest') and str(element.getAttribute('validateRequest')).lower() == "false":
                        print1 = (element.toxml())
                        list = print1.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "Insecure ASP.NET Configuration", code))
                        f.write('</finding>\n')

            #CHECK IF THE EVENT VALIDATION IS ENABLED OR NOT
            if name == "pages" and attrs.get("enableEventValidation") and str(attrs.get("enableEventValidation")).lower() == "false":
                itemlist = xmldoc.getElementsByTagName('pages')
                for element in itemlist:
                    if element.getAttribute('enableEventValidation') and str(element.getAttribute('enableEventValidation')).lower() == "false":
                        print1 = (element.toxml())
                        list = print1.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "ASP.Net Event Validation is disabled", code))
                        f.write('</finding>\n')

            #CHECK IF THE EXCESSIVE SESSION TIMEOUT IS SPECIFIED
            if name == "forms" and attrs.get("timeout") and int(attrs.get("timeout")) > 30:
                itemlist = xmldoc.getElementsByTagName('forms')
                for element in itemlist:
                    if element.getAttribute('timeout') and int(element.getAttribute('timeout')) > 30:
                        print2 = (element.toxml())
                        list = print2.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "Excessive Session Timeout", code))
                        f.write('</finding>\n')

            #CHECK IF THE SESSION STATE TIMEOUT IS EXCEEDED
            if name == "sessionState" and attrs.get("timeout") and int(attrs.get("timeout")) > 30:
                itemlist = xmldoc.getElementsByTagName('sessionState')
                for element in itemlist:
                    if element.getAttribute('timeout') and int(element.getAttribute('timeout')) > 30:
                        print42 = (element.toxml())
                        list = print42.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, " Session State Timeout Exceeded", code))
                        f.write('</finding>\n')

            #CHECK IF THE TRACE IS ENABLED
            if name == "trace" and attrs.get("enabled") and str(attrs.get("enabled")).lower() == "true":
                itemlist = xmldoc.getElementsByTagName('trace')
                for element in itemlist:
                    if element.getAttribute('enabled') and str(element.getAttribute('enabled')).lower() == "true":
                        print3 = (element.toxml())
                        list = print3.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "Trace is enabled", code))
                        f.write('</finding>\n')

            #CHECK IF THE CUSTOM ERRORS ARE OFF
            if name == "customErrors" and attrs.get("mode") and str(attrs.get("mode")).lower() == "off":
                itemlist = xmldoc.getElementsByTagName('customErrors')
                for element in itemlist:
                    if element.getAttribute('mode') and str(element.getAttribute('mode')).lower() == "off":
                        print4 = (element.toxml())
                        list = print4.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "Custom error mode is set to off", code))
                        f.write('</finding>\n')

            #CHECK IF ASP .NET DEBUG IS NOT ENABLED
            if name == "compilation" and attrs.get("debug") and str(attrs.get("debug")).lower() == "true":
                itemlist = xmldoc.getElementsByTagName('compilation')
                for element in itemlist:
                    if element.getAttribute('debug') and str(element.getAttribute('debug')).lower() == "true":
                        print5 = (element.toxml())
                        list = print5.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "ASP .NET Debug Enabled", code))
                        f.write('</finding>\n')

            #CHECK IF REQUEST HEADER CHECKING IS DISABLED
            if name == "httpRuntime" and attrs.get('enableHeaderChecking') and str(attrs.get("enableHeaderChecking")).lower() == "false":
                itemlist = xmldoc.getElementsByTagName('httpRuntime')
                for element in itemlist:
                    if element.getAttribute('enableHeaderChecking') and str(element.getAttribute('enableHeaderChecking')).lower() == "false":
                        print50 = (element.toxml())
                        list = print50.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "Header checking is disabled", code))
                        f.write('</finding>\n')

            #CHECK IF THE MAX SIZE OF THE REQUEST COMMING TO THE PAGE IS SPECIFIED PROPERLY
            if name == "httpRuntime" and attrs.get("maxRequestLength") and int(attrs.get("maxRequestLength")) > 4096:
                itemlist = xmldoc.getElementsByTagName('httpRuntime')
                for element in itemlist:
                    if element.getAttribute('maxRequestLength') and int(element.getAttribute('maxRequestLength')) > 4096:
                        print6 = (element.toxml())
                        list = print6.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "Limit the size of the request", code))
                        f.write('</finding>\n')

            #CHECK IF THE SSL IS USED TO AUTHENTICATE COOKIES
            if name == "forms" and attrs.get("requireSSL") and str(attrs.get("requireSSL")).lower() == "false":
                itemlist = xmldoc.getElementsByTagName('forms')
                for element in itemlist:
                    if element.getAttribute('requireSSL') and str(element.getAttribute('requireSSL')).lower() == "false":
                        print7 = (element.toxml())
                        list = print7.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "SSL not used for authentication cookies", code))
                        f.write('</finding>\n')

            #CHECK IF THE COOKIE PATH IS SET TO /
            if name == "forms" and attrs.get("path") and str(attrs.get("path")).lower() == "/":
                itemlist = xmldoc.getElementsByTagName('forms')
                for element in itemlist:
                    if element.getAttribute('path') and str(element.getAttribute('path')).lower() == "/":
                        print7 = (element.toxml())
                        list = print7.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "Cookie path set to /", code))
                        f.write('</finding>\n')

            #CHECK IF THE COOKIE DOMAIN IS SET TO NULL
            if name == "forms" and attrs.get("domain") and str(attrs.get("domain")).lower() == " ":
                itemlist = xmldoc.getElementsByTagName('forms')
                for element in itemlist:
                    if element.getAttribute('domain') and str(element.getAttribute('domain')).lower() == " ":
                        print7 = (element.toxml())
                        list = print7.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "Cookie domain set to ' '", code))
                        f.write('</finding>\n')

            #CHECK IF THE COOKIE PROTECTION IS ENABLED
            if name == "roleManager " and attrs.get("protection") and str(attrs.get("protection")).lower() != "all":
                itemlist = xmldoc.getElementsByTagName('roleManager ')
                for element in itemlist:
                    if element.getAttribute('protection') and str(element.getAttribute('protection')).lower() != "all":
                        print7 = (element.toxml())
                        list = print7.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "Cookie protection is disabled", code))
                        f.write('</finding>\n')

            #CHECK IF THE VIEWSTATE IS ENCRYPTED
            if name == "pages" and attrs.get("viewStateEncryptionMode") and str(attrs.get("viewStateEncryptionMode")).lower() == "never":
                itemlist = xmldoc.getElementsByTagName('pages')
                for element in itemlist:
                    if element.getAttribute('viewStateEncryptionMode') and str(element.getAttribute('viewStateEncryptionMode')).lower() == "never":
                        print10 = (element.toxml())
                        list = print10.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "View state is not encrypted", code))
                        f.write('</finding>\n')

            #CHECK IF THE VIEWSTATEMAC is enabled
            if name == "pages" and attrs.get("enableViewStateMac") and str(attrs.get("enableViewStateMac")).lower() == "false":
                itemlist = xmldoc.getElementsByTagName('pages')
                for element in itemlist:
                    if element.getAttribute('viewStateEncryptionMode') and str(element.getAttribute('viewStateEncryptionMode')).lower() == "false":
                        print51 = (element.toxml())
                        list = print51.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "View state mac is not enabled", code))
                        f.write('</finding>\n')

            #CHECK IF THE CONTENTS OF THE SESSION STATE IS ENCRYPTED OR NOT
            if name == "sessionState" and attrs.get("encrypt") and str(attrs.get("encrypt")).lower() == "false":
                itemlist = xmldoc.getElementsByTagName('sessionState')
                for element in itemlist:
                    if element.getAttribute('encrypt') and str(element.getAttribute('encrypt')).lower() == "false":
                        print15 = (element.toxml())
                        list = print15.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "Session State is not encrypted", code))
                        f.write('</finding>\n')

            #CHECK IF THE COOKIE IS PERSISTENT OR NOT
            if name == "roleManager" and attrs.get("createPersistentCookie") and str(attrs.get("createPersistentCookie")).lower() == 'true':
                itemlist = xmldoc.getElementsByTagName('roleManager')
                for element in itemlist:
                    if element.getAttribute("createPersistentCookie") and str(element.getAttribute("createPersistentCookie")).lower() == 'true':
                        print20 = (element.toxml())
                        list = print20.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "Persistent cookie used ", code))
                        f.write('</finding>\n')

            #CHECK IF ANY PASSWORD IS ENCOUNTERED IN CONNECTIONSTRING-------- This rule is creating some noise if "add" tag is repeated at multiple lines. So for this, the alternate rule has been added.
            '''if(name == "add" and attrs.get("connectionString")):
                itemlist = xmldoc.getElementsByTagName('add')
                for element in itemlist:
                    if element.getAttribute('connectionString'):
                        print21 = (element.toxml())
                        list1 = print21.split(';')
                        for x in range(0,len(list1)):
                            if list1[x].startswith('password'):
                                for i in codeDone:
                                    a = str(i).encode("utf-8")
                                    b.append(a)
                                c = ",".join(b)
                                f.write('<finding>\n')
                                f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "Password encountered", c))
                                f.write('</finding>\n')'''

            #CHECK IF ANY PASSWORD IS ENCOUNTERED IN CONNECTIONSTRING
            if(name == "sessionState" and attrs.get("sqlConnectionString")):
                itemlist = xmldoc.getElementsByTagName('sessionState')
                for element in itemlist:
                    if element.getAttribute('sqlConnectionString'):
                        print21 = (element.toxml())
                        list1 = print21.split(';')
                        for x in range(0,len(list1)):
                            if list1[x].startswith('password'):
                                for i in codeDone:
                                    a = str(i).encode("utf-8")
                                    b.append(a)
                                c = ",".join(b)
                                f.write('<finding>\n')
                                f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "Password encountered", c))
                                f.write('</finding>\n')

            #CHECK IF PASSWORD IS PRESENT IN FILE
            if name == "add" and attrs.get("password") and attrs.get("password") != '':
                itemlist = xmldoc.getElementsByTagName('add')
                for element in itemlist:
                    if element.getAttribute('password') and element.getAttribute('password') != '':
                        print18 = (element.toxml())
                        list = print18.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "Password present in file", code))
                        f.write('</finding>\n')
                                
            #COOKIE SLIDING EXPIRATION IS FALSE OR NOT TO PREVENT COOKIE HIJACKING
            if name == "roleManager" and attrs.get("cookieSlidingExpiration") and str(attrs.get("cookieSlidingExpiration")).lower() == 'true':
                itemlist = xmldoc.getElementsByTagName('roleManager')
                for element in itemlist:
                    if element.getAttribute("cookieSlidingExpiration") and str(element.getAttribute("cookieSlidingExpiration")).lower() == 'true':
                        print22 = (element.toxml())
                        list = print22.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "Cookie sliding expiration to protect from cookie hijacking not configured properly ", code))
                        f.write('</finding>\n')

            #COOKIE TIMEOUT EXCEEDED OR NOT
            if name == "roleManager" and attrs.get("cookieTimeout") and int(attrs.get("cookieTimeout")) > 30:
                itemlist = xmldoc.getElementsByTagName('roleManager')
                for element in itemlist:
                    if element.getAttribute("cookieTimeout") and int(element.getAttribute("cookieTimeout")) > 30:
                        print23 = (element.toxml())
                        list = print23.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "Cookie Timeout exceeded", code))
                        f.write('</finding>\n')

            #CHECK IF ROLES COOKIE CAN ONLY BE SENT OVER HTTPS CONNECTIONS
            if name == "roleManager" and attrs.get("cookieRequireSSL") and str(attrs.get("cookieRequireSSL")).lower() == "false":
                itemlist = xmldoc.getElementsByTagName('roleManager')
                for element in itemlist:
                    if element.getAttribute("cookieRequireSSL") and str(element.getAttribute("cookieRequireSSL")).lower() == "false" :
                        print23 = (element.toxml())
                        list = print23.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "Roles cookie can be sent HTTP connection also ", code))
                        f.write('</finding>\n')

            #CHECK IF COOKIE PROTECTION IS ENABLED OR NOT
            if name == "roleManager" and attrs.get("cookieProtection") and str(attrs.get("cookieProtection")).lower() != "all":
                itemlist = xmldoc.getElementsByTagName('roleManager')
                for element in itemlist:
                    if element.getAttribute("cookieProtection") and str(element.getAttribute("cookieProtection")).lower() != "all" :
                        print24 = (element.toxml())
                        list = print24.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "Cookie protection is not enabled ", code))
                        f.write('</finding>\n')

            #CHECK IF FORM PROTECTION IS ENABLED
            if name == "forms" and attrs.get("protection") and str(attrs.get("protection")).lower() != "none":
                itemlist = xmldoc.getElementsByTagName('roleManager')
                for element in itemlist:
                    if element.getAttribute("protection") and str(element.getAttribute("protection")).lower() != "None":
                        print24 = (element.toxml())
                        list = print24.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "Cookie protection is not enabled ", code))
                        f.write('</finding>\n')

            #CHECK IF ANONYMOUS AUTHENTICATION IS ENABLED
            if name == "identity" and attrs.get("impersonate") and str(attrs.get("impersonate")).lower() != "true":
                itemlist = xmldoc.getElementsByTagName('identity')
                for element in itemlist:
                    if element.getAttribute("impersonate") and str(element.getAttribute("impersonate")).lower() != "true" :
                        print55 = (element.toxml())
                        list = print55.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "Anonymous authentication is enabled ", code))
                        f.write('</finding>\n')

            #CHECK IF THE ANONYMOUS ACCESS TO PROTECTED PAGES IS DISABLED OR NOT
            if name == "deny" and attrs.get("users") and attrs.get("users") != "?":
                itemlist = xmldoc.getElementsByTagName('deny')
                for element in itemlist:
                    if element.getAttribute("users") and element.getAttribute("users") != "?":
                        print25 = (element.toxml())
                        list = print25.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "Anonymous access to protected pages is enabled ", code))
                        f.write('</finding>\n')

            #CHECK IF THE ActiveDirectoryMembershipProvider CREDENTIALS ARE SECURED OVER THE WIRE OR NOT
            if name == "add" and attrs.get("connectionProtection") and str(attrs.get("connectionProtection")).lower() != "secure":
                itemlist = xmldoc.getElementsByTagName('add')
                for element in itemlist:
                    if element.getAttribute("connectionProtection") and str(element.getAttribute("connectionProtection")).lower() != "secure":
                        print26 = (element.toxml())
                        list = print26.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "Active directory membership provider credentials not secured", code))
                        f.write('</finding>\n')

            #CHECK IF THE SLIDING EXPIRATION IN FORMS IS SENT TO FALSE OR NOT
            if name == "forms" and attrs.get("slidingExpiration") and str(attrs.get("slidingExpiration")).lower() == 'true':
                itemlist = xmldoc.getElementsByTagName('forms')
                for element in itemlist:
                    if element.getAttribute("slidingExpiration") and str(element.getAttribute("slidingExpiration")).lower() == 'true':
                        print27 = (element.toxml())
                        list = print27.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "Forms sliding expiration not configured properly ", code))
                        f.write('</finding>\n')

            #CHECK IF THE PASSWORD IS HASHED OR ENCRYPTED OR NOT
            if name == "add" and attrs.get("passwordFormat") and str(attrs.get("passwordFormat")).lower() == "clear":
                itemlist = xmldoc.getElementsByTagName('add')
                for element in itemlist:
                    if element.getAttribute("passwordFormat") and str(element.getAttribute("passwordFormat")).lower() == "clear":
                        print28 = (element.toxml())
                        list = print28.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "Password is in clear-text", code))
                        f.write('</finding>\n')

            #PASSWORD POLICY - MINIMUM LENGTH IS SATISTFIED OR NOT
            if name == "add" and attrs.get("minRequiredPasswordLength") and int(attrs.get("minRequiredPasswordLength")) < 9:
                itemlist = xmldoc.getElementsByTagName('add')
                for element in itemlist:
                    if element.getAttribute("minRequiredPasswordLength") and int(element.getAttribute("minRequiredPasswordLength")) < 9:
                        print29 = (element.toxml())
                        list = print29.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "Password doesn't satisfy the password policy", code))
                        f.write('</finding>\n')

            #PASSWORD POLICY - ALPHANUMERIC CHARACTERS ARE PRESENT OR NOT
            if name == "add" and attrs.get("minRequiredNonalphanumericCharacters") and int(attrs.get("minRequiredNonalphanumericCharacters")) < 1:
                itemlist = xmldoc.getElementsByTagName('add')
                for element in itemlist:
                    if element.getAttribute("minRequiredNonalphanumericCharacters") and int(element.getAttribute("minRequiredNonalphanumericCharacters")) < 1:
                        print34 = (element.toxml())
                        list = print34.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "Password doesn't satisfy the password policy", code))
                        f.write('</finding>\n')


            #HARDCODED CREDENTIALS ENCOUNTERED
            if name == "credentials":
                itemlist = xmldoc.getElementsByTagName('credentials')
                for element in itemlist:
                    if element.tagname() == "user":
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code>\n %s \n</code> \n' % (items,line, "Credentials encountered", code))
                        f.write('</finding>\n')

            #HARDCODED CREDENTIALS ENCOUNTERED
            if name == "credentials" and attrs.get("password") and (str(attrs.get("passwordFormat")).lower() == "clear" or str(attrs.get("passwordFormat")).lower() == "md5") :
                itemlist = xmldoc.getElementsByTagName('forms')
                for element in itemlist:
                    if element.getAttribute('password') and (str(element.getAttribute('passwordFormat')).lower() == "clear" or str(element.getAttribute('passwordFormat')).lower() == "md5"):
                        print54 = (element.toxml())
                        list = print54.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "Hardcoded credentials encountered", code))
                        f.write('</finding>\n')

            #CHECK IF THE COOKIE LESS AUTHENTICATION IS CHECKED OR NOT
            if name == "forms" and attrs.get("cookieless") and str(attrs.get("cookieless")).lower() == "useuri":
                itemlist = xmldoc.getElementsByTagName('forms')
                for element in itemlist:
                    if element.getAttribute('cookieless') and str(element.getAttribute('cookieless')).lower() == "useuri":
                        print30 = (element.toxml())
                        list = print30.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "Cookieless Authentication Enabled", code))
                        f.write('</finding>\n')

            #CHECK IF AUTHENTICATION WAS SET TO NONE
            if name == "system.web" and attrs.get("authentication") and str(attrs.get("authentication")).lower() == "none":
                itemlist = xmldoc.getElementsByTagName('forms')
                for element in itemlist:
                    if element.getAttribute('authentication') and str(element.getAttribute('authentication')).lower() == "authentication":
                        print52 = (element.toxml())
                        list = print52.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "Authenticatoin Set To None", code))
                        f.write('</finding>\n')

            #CHECK IF NON UNIQUE AUTHENTICATION COOKIE USED OR NOT
            if name == "forms" and attrs.get("name") and str(attrs.get("name")).lower() == ".aspxauth":
                itemlist = xmldoc.getElementsByTagName('forms')
                for element in itemlist:
                    if element.getAttribute('name') and str(element.getAttribute('name')).lower() == ".aspxauth":
                        print31 = (element.toxml())
                        list = print31.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "Non-Unique Authentication Cookie Use Detected", code))
                        f.write('</finding>\n')

            #CHECK IF THE COOKIE IS ACCESSIBLE TO CLIENT SIDE SCRIPT OR NOT
            if name == "httpCookies" and attrs.get("httpOnlyCookies") and str(attrs.get("httpOnlyCookies")).lower() == "false":
                itemlist = xmldoc.getElementsByTagName('httpCookies')
                for element in itemlist:
                    if element.getAttribute('httpOnlyCookies') and str(element.getAttribute('httpOnlyCookies')).lower() == "false":
                        print32 = (element.toxml())
                        list = print32.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "Cookies Accessible through Client-Side Script", code))
                        f.write('</finding>\n')


            #CHECK IF THE COOKIELESS SESSION STATE IS ENABLED OR NOT
            if name == "sessionState" and attrs.get("cookieless") and str(attrs.get("cookieless")).lower() == "useuri":
                itemlist = xmldoc.getElementsByTagName('sessionState')
                for element in itemlist:
                    if element.getAttribute('cookieless') and str(element.getAttribute('cookieless')).lower() == "useuri":
                        print33 = (element.toxml())
                        list = print33.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "Cookieless Session State Enabled", code))
                        f.write('</finding>\n')

            #CHECK IF THE CONNECTION USERNAME IS ENCOUNTERED
            if name == "add" and attrs.get("connectionUsername") and str(attrs.get("connectionUsername")).lower() != '':
                itemlist = xmldoc.getElementsByTagName('add')
                for element in itemlist:
                    if element.getAttribute('connectionUsername') and str(element.getAttribute('connectionUsername')).lower() != '':
                        print40 = (element.toxml())
                        list = print40.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "Connection Username Encountered", code))
                        f.write('</finding>\n')

            #CHECK IF THE CONNECTION PASSWORD IS ENCOUNTERED
            if name == "add" and attrs.get("connectionPassword") and str(attrs.get("connectionPassword")).lower() != '':
                itemlist = xmldoc.getElementsByTagName('add')
                for element in itemlist:
                    if element.getAttribute('connectionPassword') and str(element.getAttribute('connectionPassword')).lower() != '':
                        print41 = (element.toxml())
                        list = print41.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "Connection Password Encountered", code))
                        f.write('</finding>\n')

            #CHECK IF USER SENSITIVE INFORMATION IS BEING LOGGED
            if name == "machineSettings" and attrs.get("enableLoggingKnownPii") and str(attrs.get("enableLoggingKnownPii")).lower() == "true":
                itemlist = xmldoc.getElementsByTagName('machineSettings')
                for element in itemlist:
                    if element.getAttribute('enableLoggingKnownPii') and str(element.getAttribute('enableLoggingKnownPii')).lower() == "true":
                        print51 = (element.toxml())
                        list = print51.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "User's Sensitive information is being logged.", code))
                        f.write('</finding>\n')
            #CHECK IF USER SENSITIVE INFORMATION IS BEING LOGGED
            if name == "source" and attrs.get("logKnownPii") and str(attrs.get("logKnownPii")).lower() == "true":
                itemlist = xmldoc.getElementsByTagName('source')
                for element in itemlist:
                    if element.getAttribute('logKnownPii') and str(element.getAttribute('logKnownPii')).lower() == "true":
                        print52 = (element.toxml())
                        list = print52.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "User's Sensitive information is being logged.", code))
                        f.write('</finding>\n')

            #CHECK IF SESSION DATA IS EXPOSED
            if name == "sessionState" and attrs.get("cookieless") and str(attrs.get("cookieless")).lower() == "useuri":
                itemlist = xmldoc.getElementsByTagName('sessionState')
                for element in itemlist:
                    if element.getAttribute('cookieless') and str(element.getAttribute('cookieless')).lower() == "useuri":
                        print30 = (element.toxml())
                        list = print30.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "Session Data Exposed", code))
                        f.write('</finding>\n')

            #CHECK IF SESSION DATA IS EXPOSED
            if name == "sessionState" and attrs.get("cookieless") and str(attrs.get("cookieless")).lower() == "true":
                itemlist = xmldoc.getElementsByTagName('sessionState')
                for element in itemlist:
                    if element.getAttribute('cookieless') and str(element.getAttribute('cookieless')).lower() == "true":
                        print30 = (element.toxml())
                        list = print30.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "Session Data Exposed", code))
                        f.write('</finding>\n')

            #CHECK IF BLACKLIST OF HTTP VERB IS USED
            if name == "deny" and attrs.get("verbs") and str(attrs.get("verbs")).lower() != '':
                itemlist = xmldoc.getElementsByTagName('deny')
                for element in itemlist:
                    if element.getAttribute('verbs') and str(element.getAttribute('verbs')).lower() != '':
                        print30 = (element.toxml())
                        list = print30.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "Black list of HTTP verbs used", code))
                        f.write('</finding>\n')

            #CHECK IF WCF SECURITY IS DISABLED
            if name == "security" and attrs.get("mode") and str(attrs.get("mode")).lower() == "none":
                itemlist = xmldoc.getElementsByTagName('security')
                for element in itemlist:
                    if element.getAttribute('mode') and str(element.getAttribute('mode')).lower() == "none":
                        print30 = (element.toxml())
                        list = print30.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "WCF Security Disabled", code))
                        f.write('</finding>\n')

            #CHECK IF TRANSPORT LEVEL AUTHENTICATION IS DISABLED
            if name == "transport" and attrs.get("proxyCredentialType") and str(attrs.get("proxyCredentialType")).lower() == "none":
                itemlist = xmldoc.getElementsByTagName('transport')
                for element in itemlist:
                    if element.getAttribute('proxyCredentialType') and str(element.getAttribute('proxyCredentialType')).lower() == "none":
                        print30 = (element.toxml())
                        list = print30.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "Transport Level Authentication Disabled", code))
                        f.write('</finding>\n')

            #CHECK IF TRANSPORT LEVEL AUTHENTICATION IS DISABLED
            if name == "transport" and attrs.get("clientCredentialType") and str(attrs.get("clientCredentialType")).lower() == "none":
                itemlist = xmldoc.getElementsByTagName('transport')
                for element in itemlist:
                    if element.getAttribute('clientCredentialType') and str(element.getAttribute('clientCredentialType')).lower() == "none":
                        print30 = (element.toxml())
                        list = print30.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "Transport Level Authentication Disabled", code))
                        f.write('</finding>\n')

            #CHECK IF TRANSPORT LEVEL AUTHENTICATION IS DISABLED
            if name == "transport" and attrs.get("msmqAuthenticationMode") and str(attrs.get("msmqAuthenticationMode")).lower() == "none":
                itemlist = xmldoc.getElementsByTagName('transport')
                for element in itemlist:
                    if element.getAttribute('msmqAuthenticationMode') and str(element.getAttribute('msmqAuthenticationMode')).lower() == "none":
                        print30 = (element.toxml())
                        list = print30.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "Transport Level Authentication Disabled", code))
                        f.write('</finding>\n')

            #TRANSPORT LAYER SECURITY SETTINGS IS NOT SPECIFIED PROPERLY
            if name == "transport":
                test = attrs.get("proxyCredentialType")
                if test == None:
                    itemlist = xmldoc.getElementsByTagName('transport')
                    for element in itemlist:
                        if element.getAttribute('proxyCredentialType') == '':
                            print7 = (element.toxml())
                            list = print7.split(">")
                            code = list[0] + '>'
                            f.write('<finding>\n')
                            f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "Transport layer security setting is not specified properly.", code))
                            f.write('</finding>\n')

            #CHECK IF WCF PROTECTION IS DISABLED
            if name == "transport" and attrs.get("msmqProtectionLevel") and str(attrs.get("msmqProtectionLevel")).lower() == "none":
                itemlist = xmldoc.getElementsByTagName('transport')
                for element in itemlist:
                    if element.getAttribute('msmqProtectionLevel') and str(element.getAttribute('msmqProtectionLevel')).lower() == "none":
                        print30 = (element.toxml())
                        list = print30.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "WCF Protection Disabled", code))
                        f.write('</finding>\n')

            #CHECK IF WCF PROTECTION IS DISABLED
            if name == "transport" and attrs.get("protectionLevel") and str(attrs.get("protectionLevel")).lower() == "none":
                itemlist = xmldoc.getElementsByTagName('transport')
                for element in itemlist:
                    if element.getAttribute('protectionLevel') and str(element.getAttribute('protectionLevel')).lower() == "none":
                        print30 = (element.toxml())
                        list = print30.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "WCF Protection Disabled", code))
                        f.write('</finding>\n')

            #CHECK IF INSECURE WCF CLIENT AUTHENTICATION SETTING IS USED
            if name == "message" and attrs.get("clientCredentialType") and str(attrs.get("clientCredentialType")).lower() == "none":
                itemlist = xmldoc.getElementsByTagName('message')
                for element in itemlist:
                    if element.getAttribute('clientCredentialType') and str(element.getAttribute('clientCredentialType')).lower() == "none":
                        print30 = (element.toxml())
                        list = print30.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "Insecure WCF client authentication settings used", code))
                        f.write('</finding>\n')

            #CHECK IF INSECURE WCF CLIENT AUTHENTICATION SETTING IS USED
            if name == "message" and attrs.get("clientCredentialType") and str(attrs.get("clientCredentialType")).lower() == "username":
                itemlist = xmldoc.getElementsByTagName('message')
                for element in itemlist:
                    if element.getAttribute('clientCredentialType') and str(element.getAttribute('clientCredentialType')).lower() == "username":
                        print30 = (element.toxml())
                        list = print30.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "Insecure WCF client authentication settings used", code))
                        f.write('</finding>\n')

            #CHECK IF CLIENT AUTHORIZATION IS DISABLED
            if name == "serviceAuthorization" and attrs.get("principalPermissionMode") and str(attrs.get("principalPermissionMode")).lower() == "none":
                itemlist = xmldoc.getElementsByTagName('serviceAuthorization')
                for element in itemlist:
                    if element.getAttribute('principalPermissionMode') and str(element.getAttribute('principalPermissionMode')).lower() == "none":
                        print30 = (element.toxml())
                        list = print30.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "Client Authorization disabled", code))
                        f.write('</finding>\n')

            #CHECK IF CLIENT CERTIFICATE AUTHENTICATION IS DISABLED
            if name == "authentication" and attrs.get("revocationMode") and str(attrs.get("revocationMode")).lower() == "nocheck":
                itemlist = xmldoc.getElementsByTagName('authentication')
                for element in itemlist:
                    if element.getAttribute('revocationMode') and str(element.getAttribute('revocationMode')).lower() == "nocheck":
                        print30 = (element.toxml())
                        list = print30.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "Client Certificate Authentication Disabled", code))
                        f.write('</finding>\n')

            #CHECK IF CLIENT CERTIFICATE AUTHENTICATION IS DISABLED
            if name == "authentication" and attrs.get("certificateValidationMode") and str(attrs.get("certificateValidationMode")).lower() == "none":
                itemlist = xmldoc.getElementsByTagName('authentication')
                for element in itemlist:
                    if element.getAttribute('certificateValidationMode') and str(element.getAttribute('certificateValidationMode')).lower() == "none":
                        print30 = (element.toxml())
                        list = print30.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "Client Certificate Authentication Disabled", code))
                        f.write('</finding>\n')

            #CHECK IF OPENAUTH AUTHENTICATION SECURITY IS DISABLED
            if name == "security" and attrs.get("requireSsl") and str(attrs.get("requireSsl")).lower() == "false":
                itemlist = xmldoc.getElementsByTagName('security')
                for element in itemlist:
                    if element.getAttribute('requireSsl') and str(element.getAttribute('requireSsl')).lower() == "false":
                        print7 = (element.toxml())
                        list = print7.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "OpenAuth Authentication security disabled", code))
                        f.write('</finding>\n')

            #CHECK IF WEAK HASHING ALGORITHM FOR WCF BINDING IS USED
            if name == "transport" and attrs.get("msmqSecureHashAlgorithm") and str(attrs.get("msmqSecureHashAlgorithm")).lower() == "md5":
                itemlist = xmldoc.getElementsByTagName('transport')
                for element in itemlist:
                    if element.getAttribute('msmqSecureHashAlgorithm') and str(element.getAttribute('msmqSecureHashAlgorithm')).lower() == "md5":
                        print7 = (element.toxml())
                        list = print7.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "Use of weak hash algorithm for WCF binding", code))
                        f.write('</finding>\n')

            #CHECK IF WEAK HASHING ALGORITHM FOR WCF BINDING IS USED
            if name == "transport" and attrs.get("msmqSecureHashAlgorithm") and str(attrs.get("msmqSecureHashAlgorithm")).lower() == "sha1":
                itemlist = xmldoc.getElementsByTagName('transport')
                for element in itemlist:
                    if element.getAttribute('msmqSecureHashAlgorithm') and str(element.getAttribute('msmqSecureHashAlgorithm')).lower() == "sha1":
                        print7 = (element.toxml())
                        list = print7.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "Use of weak hash algorithm for WCF binding", code))
                        f.write('</finding>\n')

            #CHECK IF HASHING ALGORITHM FOR WCF BINDING IS SPECIFIED PROPERLY
            if name == "transport":
                test = attrs.get("msmqSecureHashAlgorithm")
                if test == None:
                    itemlist = xmldoc.getElementsByTagName('transport')
                    for element in itemlist:
                        if element.getAttribute('msmqSecureHashAlgorithm') == '':
                            print7 = (element.toxml())
                            list = print7.split(">")
                            code = list[0] + '>'
                            f.write('<finding>\n')
                            f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "Hashing algorithm for WCF binding is not specified.", code))
                            f.write('</finding>\n')

            #CHECK IF WEAK ENCRYPTION ALGORITHM FOR WCF BINDING IS USED
            if name == "transport" and attrs.get("msmqEncryptionAlgorithm") and str(attrs.get("msmqEncryptionAlgorithm")).lower() == "rc4stream":
                itemlist = xmldoc.getElementsByTagName('transport')
                for element in itemlist:
                    if element.getAttribute('msmqEncryptionAlgorithm') and str(element.getAttribute('msmqEncryptionAlgorithm')).lower() == "rc4stream":
                        print7 = (element.toxml())
                        list = print7.split(">")
                        code = list[0] + '>'
                        f.write('<finding>\n')
                        f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "Use of weak encryption algorithm for WCF binding", code))
                        f.write('</finding>\n')

            #CHECK IF ENCRYPTION ALGORITHM FOR WCF BINDING IS SPECIFIED PROPERLY
            if name == "transport":
                test = attrs.get("msmqEncryptionAlgorithm")
                if test == None:
                    itemlist = xmldoc.getElementsByTagName('transport')
                    
                    for element in itemlist:
                        if element.getAttribute('msmqEncryptionAlgorithm') == '':
                            
                            print7 = (element.toxml())
                            list = print7.split(">")
                            code = list[0] + '>'
                            f.write('<finding>\n')
                            f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "Encryption algorithm for WCF binding is not specified.", code))
                            f.write('</finding>\n')


            #HARDCODED CONNECTION STRING ENCOUNTERED
            if name == "connectionStrings":
                itemlist = xmldoc.getElementsByTagName('connectionStrings')
                for element in itemlist:
                    code = element.toxml()
                    
                    f.write('<finding>\n')
                    f.write('\t<File> %s </File> \n \t<Line> %d </line> \n \t<error> %s </error>\n \t<code> %s </code> \n' % (items,line, "Connection string encountered. Please verify if Credentials are hardcoded", code))
                    f.write('</finding>\n')




    parser = make_parser()
    sh = SimpleHandler()
    parser.setContentHandler(sh)
    parser.parse(open(items,"r"))
f.write('</Vulnerabilities>')