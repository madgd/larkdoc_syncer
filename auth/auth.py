"""
deal with lark auth
"""

import configparser
import os
import urllib3
import json
import webbrowser
import socket
from http.server import HTTPServer, BaseHTTPRequestHandler, SimpleHTTPRequestHandler
from urllib.parse import urlparse, parse_qsl
import threading
import time
import smtplib
from email.message import EmailMessage


class auth():
    """
    auth
    """
    
    conf = None
    config = None

    def __init__(self, conf, sec):
        self.conf = conf
        self.config = configparser.ConfigParser()
        self.config.read(conf)
        # try refresh
        if self.refresh_access_token(sec):
            print("init succ by refresh") 
        # if can't refresh, run: get user token->get app_access_token ->get access_token
        else:
            # need
            os.system("""mail -s "lark doc sync need user auth." %s <<< 'lark doc sync need user auth.'""" % (self.config.get(sec, "alert_email")))
            if self.get_user_code(sec) and self.get_app_access_token(sec) and self.get_access_token(sec):
                print("init succ by user auth")
            else:
                # mail alert
                os.system("""mail -s "lark doc sync auth init failed." %s <<< 'lark doc sync auth init failed.'""" % (self.config.get(sec, "alert_email")))

    def _json_post(self, data, url, headers={}):
        headers['Content-Type'] = 'application/json'
        encoded_data = json.dumps(data).encode('utf-8')
        http = urllib3.PoolManager()
        r = http.request("POST", url, headers=headers, body=encoded_data, timeout=5)
        res = json.loads(r.data.decode('utf-8'))
        return res

    def _is_port_used(self, ip, port):
        """
        check whether the port is used by other program
        检测端口是否被占用

        :param ip:
        :param port:
        :return:
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((ip, port))
            return True
        except OSError:
            return False
        finally:
            s.close()

    def get_app_access_token(self, sec):
        """
        app_access_token, see:https://open.feishu.cn/document/ukTMukTMukTM/uADN14CM0UjLwQTN
        """
        data = {
            "app_id": self.config.get(sec, "appid"),
            "app_secret": self.config.get(sec, "appsk")
        }
        res = self._json_post(data, "https://open.feishu.cn/open-apis/auth/v3/app_access_token/internal/")
        if not res or 'code' not in res or res['code'] != 0:
            print("get_app_access_token wrong", res)
            return False
        else:
            self.config.set(sec, 'app_access_token', res['app_access_token'])
            self.config.set(sec, 'tenant_access_token', res['tenant_access_token'])
            self.config.write(open(self.conf, 'w'))
            print("get_app_access_token updated", res)
            return True
    
    def get_user_code(self, sec):
        """
        get user_code, see: https://open.feishu.cn/document/ukTMukTMukTM/ukzN4UjL5cDO14SO3gTN
        expires only one time
        """
        # check port in use
        port = 8000
        if self._is_port_used("127.0.0.1", port):
            print("port %d is used" % port)
            return False
        
        # get auth user code
        KEEP_RUNNING = True
        code = None
        def keep_running():
            return KEEP_RUNNING
        redirect_uri = "http://127.0.0.1:%d/" % port
        webbrowser.open("https://open.feishu.cn/open-apis/authen/v1/index?redirect_uri={REDIRECT_URI}&app_id={APPID}".format(REDIRECT_URI=redirect_uri, APPID=self.config.get(sec, 'appid')))
        class testHTTPServer_RequestHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                querypath = urlparse(self.path)
                params = dict(parse_qsl(querypath.query))
                print(params)
                self.send_response(200)
                # print success msg
                self.send_header("Content-type", "text/html")
                self.end_headers()
                html = """
                <html>
                    <head>
                        <script type="text/javascript">
                            function closeWindow() {
                                window.open('', '_self', '');
                                window.opener=null;
                                window.close();
                                return false;
                            }
                            window.onload=function(){
                                alert("auth success");
                                closeWindow();
                            }
                        </script>
                    </head>
                    <body>
                        <h1>Success</h1>
                    </body>
                </html>
                """
                self.wfile.write(bytes(html, "utf8"))
                nonlocal KEEP_RUNNING, code
                code = params['code']
                KEEP_RUNNING = False

        server_address = ('', port)
        server = HTTPServer(server_address, testHTTPServer_RequestHandler)
        while keep_running():
            server.handle_request()

        # save code
        self.config.set(sec, 'code', code)
        self.config.write(open(self.conf, 'w'))
        print("get user auth code success")
        return True

    def get_access_token(self, sec):
        """
        access_token(user), refresh_token, see: https://open.feishu.cn/document/ukTMukTMukTM/uEDO4UjLxgDO14SM4gTN
        """
        data = {
            "app_access_token": self.config.get(sec, 'app_access_token'),
            "grant_type": "authorization_code",
            "code": self.config.get(sec, 'code'),
        }
        res = self._json_post(data, "https://open.feishu.cn/open-apis/authen/v1/access_token")
        if not res or 'code' not in res or res['code'] != 0:
            print("get_access_token wrong", res)
            return False
        else:
            self.config.set(sec, 'access_token', res["data"]['access_token'])
            self.config.set(sec, 'refresh_token', res["data"]['refresh_token'])
            # print(self.config.items(sec))
            print("get_access_token updated", res)
            self.config.write(open(self.conf, 'w'))
            return True

    def refresh_access_token(self, sec):
        """
        refresh access_token, see: https://open.feishu.cn/document/ukTMukTMukTM/uQDO4UjL0gDO14CN4gTN
        """
        data = {
            "app_access_token": self.config.get(sec, "app_access_token"),
            "grant_type":"refresh_token",
            "refresh_token": self.config.get(sec, "refresh_token")
        }
        res = self._json_post(data, "https://open.feishu.cn/open-apis/authen/v1/refresh_access_token")
        if not res or 'code' not in res or res['code'] != 0:
            print("refresh_access_token wrong", res)
            return False
        else:
            self.config.set(sec, 'access_token', res["data"]['access_token'])
            self.config.set(sec, 'refresh_token', res["data"]['refresh_token'])
            print(self.config.items(sec))
            self.config.write(open(self.conf, 'w'))
            print("refresh_access_token updated", res)
            return True

if __name__ == "__main__":
    sec = "DEFAULT"
    test = auth("%s/../config/auth.ini" % os.getcwd(), sec)
    print(test.config.items(sec))
    # test.get_app_access_token(sec)
    # test.get_user_code(sec)
    # test.get_access_token(sec)
    # test.refresh_access_token(sec)