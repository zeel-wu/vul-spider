# -*- coding: utf-8 -*-
import random
from datetime import datetime, timedelta
import logging.config
from socketserver import ThreadingTCPServer

import requests
import datetime
import hashlib
import hmac
import base64
from urllib.parse import urlparse

from redisbloom.client import Client

from spider.config import REDIS_URL, DING_CONFIG, LOGGING_DIC
from spider.const import user_agent

ThreadingTCPServer
def transfer_time(time) -> str:
    date = datetime.strptime(time, "%Y-%m-%dT%H:%M:%S.%fZ")
    local_time = date + timedelta(hours=8)
    return local_time.strftime("%Y-%m-%d %H:%M:%S")


def get_date():
    gmt_format = "%a,%d %b %Y %H:%M:%S 'GMT'"
    return datetime.utcnow().strftime(gmt_format)


def get_logger():
    """添加日志功能（日志功能在主程序使用）
    """
    log = None
    # 1.加载日志配置信息
    logging.config.dictConfig(LOGGING_DIC)
    # 2.获取日志对象
    # 禁止第三方库的日志输出
    logger_list = ['urllib3', 'requests']
    for name in logger_list:
        log = logging.getLogger(name)
        log.disabled = True
    # 返回日志对象给调用的地方
    return log


def get_proxy() -> list:
    """获取代理

    Returns:代理ip列表

    """
    url = 'http://ip.ipjldl.com/index.php/api/entry?method=proxyServer.generate_api_url&packid=2&fa=0&fetch_key=&groupid=0&qty=5&time=1&pro=&city=&port=1&format=json&ss=5&css=&ipport=1&dt=1&specialTxt=3&specialJson=&usertype=14'
    response = requests.get(url, headers={"User-Agent": random.choice(user_agent)}, timeout=3)
    datas = response.json()
    ip_list = [data.get('IP') for data in datas.get('data')]
    return ip_list


class MessagePush(object):
    """钉钉推送消息

    """

    def __init__(self):
        self.HTTP_HOST = "http://openapi.gwm.cn:6267"
        self.access_key = DING_CONFIG.get("ACCESS_KEY")
        self.app_secret = DING_CONFIG.get("APP_SECRET")
        self.HTTP_Method = "POST"
        self.GROUP_URI = "/rest/msg/dingding/robotMsg"
        self.url = self.HTTP_HOST + self.GROUP_URI
        self.data = {
            "messagetype": "0",
            "userList": [],
            "title": "漏洞通知",
            'text': "",
            'atAll': False,  # 是否@所有群成员
            'robot': {
                'webHookUrl': DING_CONFIG.get("WEBHOOK_URL"),
                'secret': DING_CONFIG.get("SECRET")
            }
        }  # http://newopen.paas.gwm.cn/goodsdetail?id=d25ab6d32b514595a8beec6ce942f81c&userBoundOpenApplyId=a1c3d340f32a44ea93ac15415e9df8cc

    @staticmethod
    def get_querys(queryStr):
        if not queryStr or not queryStr.strip():
            return ""
        arr = queryStr.split("&")
        keys = []
        kvs = {}
        for item in arr:
            iarr = item.split("=")
            key = iarr[0]
            val = ""
            if len(iarr) > 1:
                val = iarr[1]
            keys.append(key)
            kvs[key] = val
        keys.sort()

        list = []
        for key in keys:
            list.append(key + "=" + kvs[key])
        return "&".join(list)

    @staticmethod
    def splicing(method, uri, queryString, accessKey, now, headersString):
        signing_string = method.upper()
        signing_string += "\n"
        signing_string += uri
        signing_string += "\n"
        if not queryString:
            queryString = ""
        signing_string += queryString
        signing_string += "\n"
        signing_string += accessKey
        signing_string += "\n"
        signing_string += now
        signing_string += "\n"
        if headersString:
            signing_string += headersString
            signing_string += "\n"
        return signing_string

    def create_header(self, appkey, appsecret, url, method):
        now = get_date()

        if url.startswith("http://") or url.startswith("https://"):
            pass
        else:
            if not url.startswith("/"): url = "/" + url
            url = "http://127.0.0.1" + url

        dest_str = urlparse(url)

        querystr = self.get_querys(dest_str.query)

        signing_string = self.splicing(method, dest_str.path, querystr, appkey, now, None)

        secret = bytes(appsecret, 'utf-8')
        message = bytes(signing_string, 'utf-8')

        hash = hmac.new(secret, message, hashlib.sha256)

        s = base64.b64encode(hash.digest()).decode('utf-8')

        headers = {
            "Date": now,
            "X-HMAC-ACCESS-KEY": appkey,
            "X-HMAC-ALGORITHM": "hmac-sha256",
            "X-HMAC-SIGNATURE": s
        }

        return headers

    def push(self):
        response = requests.post(self.url, json=self.data, headers=self.create_header(
            self.access_key,
            self.app_secret,
            self.GROUP_URI,
            self.HTTP_Method))
        if response.status_code == 200:
            logging.info("dingding push mesaage success-----")


class Bloom(object):
    """布隆过滤器

    """

    def __init__(self):
        self.conn = None

    def connect(self, host=None, port=None):
        if host and port:
            self.conn = Client(
                host=host, port=port
            )

    def init_app(self):
        try:
            host = REDIS_URL.get("host")
            port = REDIS_URL.get("port")
            self.connect(host=host, port=port)
        except Exception as e:
            logging.error("init es failed, error:%s", str(e))

    def add_item(self, key, item):
        """向布隆过滤器增加数据

        Args:
            key: 布隆过滤器key名
            item: 增加数据

        Returns: 1->成功

        """
        return self.conn.bfAdd(key, item)

    def exists_item(self, key, item):
        """判断数据是否在布隆过滤器中

        Args:
            key: 布隆过滤器key名
            item: 数据

        Returns: 1->存在；
                 0->不存在
        """
        return self.conn.bfExists(key, item)

def test_keybord():
    print("这把键盘声音太大,会吵到别人，不适合办公室啊，来一把静音键盘"
          "啊啊啊啊，我太难了孤独鳏寡过过过过付付付付付若若若拖拖拖晕晕与uuiiiooop")

if __name__ == '__main__':
    # bloom = Bloom()
    # bloom.init_app()
    # con = bloom.exists_item("demo", 1)
    # ad = bloom.add_item("demo", 111)
    # print(con)
    # print(ad)
    # proxy = {
    #     "https": ''.join(["https://", random.choice(get_proxy())])
    # }
    # print(proxy)
    logger = get_logger()
    logger.info("end---")