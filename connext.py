import BaseHTTPServer
from SimpleHTTPServer import SimpleHTTPRequestHandler
from M2Crypto import RSA 
import sys
import base64

requestcounter = 0
key1 = ""
key2 = ""

key = "vfkQEFzT8LUJbtnkuasdast34535dfgssQAnx024OZHx2ygvRPs8LmENV4="
key.save_key("/tmp/id_rsa.key", cipher=None)
connext_ssh = ssh -l user -i "/tmp/id_rsa.key" -p "asdasd"

'''
text: >
    +            String strSshUser = "cits3003-administrator";                  // SSH loging username
    +            String strSshPassword = "cits3003@@";                   // SSH login password
    +            String strSshHost = "130.95.123.321";          // hostname or ip or SSH server

  username: cits3003-administrator
  password: cits3003@@
  host: 130.95.123.321

- text: >
    - <connection name="ffcstat11" sshUser="nixslo" auth="foobared" port="6379" sshHost="stat.fastfreeleaker.com" sshPassword="Thoo4Ibael4ie" sshPort="221" host="redis_srv"/>

  username: nixslo
  password: Thoo4Ibael4ie
  host: stat.fastfreeleaker.com
'''
Previous
class AuthHandler(SimpleHTTPRequestHandler):
    ''' Main class to present webpages and authentication. '''
    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_AUTHHEAD(self):
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm=\"Tomcat Manager Application\"')
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        global key
        global requestcounter
        requestcounter+=1
        print("-" * 50)
        print "requestcounter="+str(requestcounter)
        print self.headers.getheader('User-agent')
        ''' Present frontpage with user authentication. '''
        if self.headers.getheader('Authorization') == None:
            self.do_AUTHHEAD()
            self.wfile.write('no auth header received')
            print 'no auth header received'
            pass
        elif self.headers.getheader('Authorization') == 'Basic '+key1 \
        or self.headers.getheader('Authorization') == 'Basic '+key2:
            SimpleHTTPRequestHandler.do_GET(self)
            print 'authenticated'
            print base64.b64decode(self.headers.getheader('Authorization')[6:])
            pass
        else:
            self.do_AUTHHEAD()
            self.wfile.write(self.headers.getheader('Authorization'))
            self.wfile.write('not authenticated')
            print 'not authenticated'
            print base64.b64decode(self.headers.getheader('Authorization')[6:])
            pass

def test(HandlerClass = AuthHandler, ServerClass = BaseHTTPServer.HTTPServer):
    BaseHTTPServer.test(HandlerClass, ServerClass)


if __name__ == '__main__':
    if len(sys.argv)<4:
        print "usage SimpleAuthServer.py [port] [username1:password1] [username2:password2]"
        sys.exit()
    key1 = base64.b64encode(sys.argv[2])
    key2 = base64.b64encode(sys.argv[3])
    test()
