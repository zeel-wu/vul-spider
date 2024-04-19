# -*- coding: utf-8 -*-
# from gevent import monkey;monkey.patch_all()
import logging
import random
import time
from abc import ABCMeta
from concurrent.futures import ThreadPoolExecutor
from queue import Queue
from threading import Thread

import requests
from jsonpath import jsonpath
from lxml import etree
from sqlalchemy.exc import SQLAlchemyError

from spider.const import user_agent
from spider.exts import db
from spider.models import Vulnerability
from spider.utlis import transfer_time, get_proxy, Bloom, MessagePush, get_logger

logger = get_logger()


class Spider(object):
    __metaclass__ = ABCMeta
    proxy = {
        "http": ''.join(["https://", random.choice(get_proxy())])
    }
    key = "vul_url_key"

    header = {
        'User-Agent': random.choice(user_agent),
        'Connection': 'close'
    }

    def __init__(self, url=None, total=None):
        self.url = url
        self.total = total
        self.q = Queue()
        # self.sec_prefix = "https://www.anquanke.com"
        # self.ali_prefix = "https://help.aliyun.com"
        # self.see_prefix = "https://www.seebug.org"
        self.worker = 10

    # 构造访问的url地址
    def geturl(self, url, total):
        url = [url.format(页数=n) for n in range(1, total)]
        return url

    # 发出请求
    def send_request(self, url):
        requests.packages.urllib3.disable_warnings()
        try:
            response = requests.get(url, headers=Spider.header, verify=False, timeout=5, proxies=self.proxy)
        except Exception as e:
            print("url {} happen {}".format(url, e))
        else:
            if response.status_code == 200:
                print("爬取{}成功--------------------".format(url))
                return response.text

    # 解析
    def parse_detail(self, text):
        pass

    # 保存提取的相关信息
    @staticmethod
    def save_list(connect):
        if connect:
            vul = Vulnerability(
                name=connect['name'],
                company=connect['company'],
                url=connect['url'],
                type=connect.get('type'),
                release_time=connect.get('find_time'),
                update_time=connect.get('commit_time'),
                cve_id=connect.get('cve_id'),
                source=connect.get('source'),
                detail=connect.get('detail'),
                reference=connect.get('influence'),
                level=connect.get('level'),
                suggestion=connect.get('resolve'),
                link=connect.get('link')
            )
            return vul

    @staticmethod
    def insert_db(connects):
        try:
            db.session.bulk_save_objects(list(connects))
        except SQLAlchemyError as e:
            print("mysql error {}".format(e))
            db.session.rollback()
        print("insert db success-----")
        db.session.commit()

    # 启动爬虫
    def run(self, url):
        pass

    def multi_run(self):
        with ThreadPoolExecutor(max_workers=self.worker) as executor:
            for url in self.geturl():
                executor.submit(self.run, url)

    # 创建多线程执行函数
    def threading(self, func):
        t_list = []
        for i in range(5):
            t = Thread(target=func)
            t_list.append(t)
            t.start()
            time.sleep(2)
        for t in t_list:
            t.join()

    def check_key(self, url):
        bloom = Bloom()
        if bloom.exists_item(self.key, url) == 0:
            bloom.add_item(self.key, url)
            # self.push_message(url)
        else:
            logging.info("----目标网站暂无更新----")

    @staticmethod
    def push_message(url):
        text = '最新漏洞信息通知： {url}'.format(url=url)
        mp = MessagePush()
        mp.data['text'] = text
        mp.push()

    # 创建多线程执行函数
    @staticmethod
    def multi_exec(func):
        t_list = []
        for i in range(5):
            t = Thread(target=func)
            t_list.append(t)
            t.start()
        for t in t_list:
            t.join()


class SeeBugSpider(Spider):
    def __init__(self):
        super(SeeBugSpider, self).__init__()
        # Spider.__init__(self, url, total)
        self.list_url = 'https://www.seebug.org/vuldb/vulnerabilities?page={页数}'
        self.prefix = "https://www.seebug.org"
        # self.total = 292
        self.total = 2

    def get_list(self, html):
        if html:
            content = etree.HTML(html)
            href = content.xpath("//tbody/tr/td[1]/a/@href")
            for h in href:
                if not h:
                    continue
                detail_url = ''.join([self.prefix, str(h)])
                self.q.put(detail_url)

    # 解析详情页数据
    def parse_detail(self, url):
        item = {}
        text = self.send_request(url)

        html = etree.HTML(text)
        item['company'] = "知道创宇"
        item['name'] = html.xpath("//h1[@id='j-vul-title']/span[@class='pull-titile']/text()")[0].strip()
        item['id'] = html.xpath("//dd[@class='text-gray']/a/text()")[0].strip()
        item['type'] = html.xpath("//div[@class='col-md-4'][2]/dl[1]/dd/a/text()")[0].strip()
        cve_id = html.xpath("//div[@class='col-md-4'][3]/dl[1]/dd/a/text()")[0].strip()
        item['cve_id'] = cve_id if cve_id and cve_id != "补充" else "暂无"
        item['find_time'] = html.xpath("//div[@class='col-md-4'][1]/dl[2]/dd/text()")[0].strip()
        influence = html.xpath(
            "//dd[@class='hover-scroll']/a/text() | //dd[@class='hover-scroll']/span/@data-original-title")
        item['influence'] = ','.join([i.strip() for i in influence]) if influence else "暂无"
        cnnvd_id = html.xpath("//div[@class='col-md-4'][3]/dl[2]/dd/a/text()")[0].strip()
        item['cnnvd_id'] = cnnvd_id if cnnvd_id and cnnvd_id != "补充" else "暂无"
        item['commit_time'] = html.xpath("//div[@class='col-md-4'][1]/dl[3]/dd/text()")[0].strip()
        item['auth'] = html.xpath("//div[@class='col-md-4'][2]/dl[3]/dd/a/text()")[0].strip()
        cnvd_id = html.xpath("//div[@class='col-md-4'][3]/dl[3]/dd/a/text()")[0].strip()
        item['cnvd_id'] = cnvd_id if cnvd_id and cnvd_id != "补充" else "暂无"
        item['level'] = html.xpath("//div[@class='col-md-4'][1]/dl[4]/dd/div/@data-original-title")[0].strip()
        submitter = html.xpath("//div[@class='col-md-4'][2]/dl[4]/dd/a/text()")
        item['submitter'] = submitter[0].strip() if submitter else "匿名"
        # dork = html.xpath("//div[@class='col-md-4'][3]/dl[4]/dd/a/text()")[0].strip()
        # item['dork'] = dork if dork and dork != "补充" else "暂无"
        source = html.xpath("//div[@class='padding-md']/div[@id='j-md-source']/a/@href")
        item['source'] = source[0].strip() if source else "暂无"
        resolve = html.xpath("//div[@class='padding-md']/div[@class='panel-body']/p/text()")
        link = html.xpath("//div[@class='padding-md']/div[@class='panel-body']/ul/li/a/@href")
        item['resolve'] = ','.join([i.strip() for i in resolve]) if resolve else "暂无"
        item['link'] = '，'.join([i.strip() for i in link]) if link else "暂无"
        item['url'] = url
        print(item)
        yield item

    def run(self, url):
        text = self.send_request(url)
        connects = self.parse_detail(text)
        self.insert_db(connects)

    def consume(self):
        vul_sets = set()
        while True:
            url = self.q.get()
            for data in self.parse_detail(url):
                db_data = Spider.save_list(data)
                vul_sets.add(db_data)
            if self.q.empty():
                break
        self.insert_db(list(vul_sets))

    def start(self):
        for url in self.geturl(self.list_url, self.total):
            html = self.send_request(url)
            self.get_list(html)
        self.consume()


class SecGuestSpider(Spider):
    def __init__(self):
        self.prefix = 'https://www.anquanke.com/vul?page={页数}'
        self.list_url = 'https://www.seebug.org/vuldb/vulnerabilities?page={页数}'
        self.total = 33300

    def get_list(self, text):
        if text:
            content = etree.HTML(text)
            href = content.xpath("//div[@class='vul-title-item']/a/@href")
            for h in href:
                if not h:
                    continue
                detail_url = ''.join([self.prefix, str(h)])
                yield detail_url

    # 解析详情页数据
    def parse_detail(self, text):
        for url in self.get_list(text):
            item = {}
            text = self.send_request(url)
            if not text:
                continue
            html = etree.HTML(text)
            item['company'] = "360安全客"
            item['url'] = url
            item['name'] = html.xpath("//div[@class='common-left-content-container article-detail'][1]/h1/text()")[
                0].strip()
            # item['id'] = html.xpath("//tbody/tr[1]/td[@class='vul-info-value'][1]/text()")[0].strip()
            types = html.xpath("//tbody/tr[1]/td[@class='vul-info-value'][2]/text()")
            item['type'] = types[0].strip() if types else "暂无"
            item["find_time"] = html.xpath("//tbody/tr[2]/td[@class='vul-info-value'][1]/text()")[0].strip()
            item['commit_time'] = html.xpath("//tbody/tr[2]/td[@class='vul-info-value'][2]/text()")[0].strip()
            cve_id = html.xpath("//tbody/tr[3]/td[@class='vul-info-value'][1]/a/text()")
            item['cve_id'] = cve_id[0].strip() if cve_id else "暂无"
            score = html.xpath("//tbody/tr[4]/td[@class='vul-info-value'][2]/text()")[0].strip()
            item['score'] = score if score else "暂无"
            source = html.xpath(
                "//div[@class='common-left-content-container article-detail'][2]/div[@class='article-content']/a/text()")
            item['source'] = source[0].strip() if source else "暂无"
            detail = html.xpath("//div[@class='common-left-content-container article-detail'][3]"
                                "/div[@class='article-content']/text()")
            item['detail'] = detail[0].strip() if detail else "暂无"
            ref = html.xpath("//div[@id='vul_reference']/div[@class='article-content']/text()")
            item['link'] = "，".join(ref[2::2]) if ref else "暂无"
            print("url = {}, item {}".format(url, item))
            yield item

    # 启动爬虫
    def run(self, url):
        text = self.send_request(url)
        connects = self.parse_detail(text)
        self.insert_db(connects)

    def multi_run(self):
        with ThreadPoolExecutor(max_workers=self.worker) as executor:
            for url in self.geturl():
                executor.submit(self.run, url)


class NsFocusSpider(Spider):
    def __init__(self):
        self.queue = Queue()
        self.url = "https://nti.nsfocus.com/api/v1/search/threatWarning/?page=1&size=400&order=reported"  # 200
        self.prefix = "https://ti.nsfocus.com/api/v2/objects/vul-details/?query="
        self.header = {
            'User-Agent': random.choice(user_agent),
            'Connection': 'close',
            "Cookie": "sessionid=ms96uaof8yxvmaclxrmf3d9z3biyqgt4"
        }

    # 发出页面相应请求
    def send_request(self, url):
        requests.packages.urllib3.disable_warnings()
        try:
            response = requests.get(url, headers=self.header, proxy=Spider.proxy, verify=False, timeout=3)
        except Exception as e:
            print("url {} happen {}".format(url, e))
        else:
            if response.status_code == 200:
                print("爬取{}成功--------------------".format(url))
                return response.json()

    # 提取详情页url并请求
    def get_list(self, text):
        if text:
            for t in text.get("data"):
                if not t:
                    continue
                id_list = t.get("cve_ids", [])
                for cve_id in id_list:
                    yield cve_id

    # 生产详情页url
    def get_detail(self, text):
        for i in self.get_list(text):
            if not i:
                continue
            detail_url = "".join([self.prefix, i])
            yield detail_url

    # 请求详情页并解析
    def parse_detail(self, text):
        for url in self.get_detail(text):

            response = self.send_request(url)
            if not response:
                continue
            item = {}
            item["company"] = "绿盟"
            item["url"] = url
            item["name"] = jsonpath(response, "$.objects[*].name")[0]
            try:
                product = jsonpath(response, "$.objects[*].affected_softwares[*].products[*].items[*].product")
                item["influence"] = repr(set(product)) if product else "暂无"
                version = jsonpath(response, "$.objects[*].affected_softwares[*].products[*].items[*].ns_cpe")
                item["version"] = ",".join([" ".join((i.split(":"))[4:6]) for i in version]) if version else "无"
                desc = jsonpath(response, "$.objects[*].description")
                item["desc"] = desc[0] if desc else "暂无"
                pub_time = jsonpath(response, "$.objects[*].created")
                item["created"] = transfer_time(pub_time[0]) if pub_time else "暂无"
                update_time = jsonpath(response, "$.objects[*].last_updated")
                item["update"] = transfer_time(update_time[0]) if update_time else "暂无"
                link = jsonpath(response, "$.objects[*].ext_references[*].url")
                item["link"] = ','.join(link) if link else "暂无"
                solu = jsonpath(response, "$.objects[*].solution")
                item["solution"] = solu[0] if solu else "暂无"
                item["type"] = jsonpath(response, "$.objects[*].type")[0]
                item["cve_id"] = jsonpath(response, "$.objects[*].ids.CVE")[0]
            except Exception as e:
                print("parse {} error {}".format(url, e))
                item["name"] = ""
                item["influence"] = ""
                item["version"] = ""
                item["desc"] = ""
                item["created"] = ""
                item["update"] = ""
                item["link"] = ""
                item["solution"] = ""
                item["type"] = ""
                item["cve_id"] = ""
            yield item

    def run(self):
        text = self.send_request(self.url)
        self.get_detail(text)

        connects = self.parse_detail(url=self.queue.get())
        self.save_list(connects)

    def multi_run(self):
        with ThreadPoolExecutor(max_workers=self.worker) as executor:
            executor.submit(self.run, )


class AliSpider(Spider):
    def __init__(self):
        self.url = "https://help.aliyun.com/notice_list_page/9213612/{页数}.html"
        self.prefix = "https://help.aliyun.com"
        self.total = 15

    # 提取详情页url并请求
    def get_list(self, text):
        if text:
            content = etree.HTML(text)
            href = content.xpath("//div/ul/li[@class='y-clear']/a/@href")
            for h in href:
                detail_url = ''.join([self.prefix, str(h)])
                print(detail_url)
                if not h:
                    continue
                yield detail_url

    # 解析详情页数据
    def parse_detail(self, text):
        for url in self.get_list(text):
            result = self.send_request(url)
            if not result:
                continue
            item = {}
            html = etree.HTML(text)
            item['company'] = "阿里云"
            item['url'] = url
            item['name'] = html.xpath("//div[@class='crumbs-nav']/span[2]/text()")[0].strip()
            try:
                item['time'] = html.xpath("//div/div[@id='se-knowledge']/p[1]/text()")[0].strip()
                item['desc'] = html.xpath("//div/div[@id='se-knowledge']/p[4]/text()")[0].strip()
            except Exception as e:
                item['desc'] = "暂无"
                item['time'] = "暂无"
                print("url {} happen {}".format(url, e))
            detail = html.xpath("//p[text()='漏洞细节：公开']/text()") or html.xpath(
                "//p[text()='漏洞细节：未公开']/text()")
            poc = html.xpath("//p[text()='漏洞POC：公开']/text()") or html.xpath(
                "//p[text()='漏洞POC：未公开']/text()")
            exp = html.xpath("//p[text()='漏洞EXP：公开']/text()") or html.xpath(
                "//p[text()='漏洞EXP：未公开']/text()")
            use = html.xpath("//p[text()='在野利用：存在']/text()") or html.xpath("//p[text()='在野利用：未知']/text()")
            item['detail'] = detail[0].strip() if detail else "未知"
            item['poc'] = poc[0].strip() if poc else "未知"
            item['exp'] = exp[0].strip() if exp else "未知"
            item['use'] = use[0].strip() if use else "未知"
            yield item

    # 启动爬虫
    def run(self, url):
        text = self.send_request(url)
        connects = self.parse_detail(text)
        self.save_list(connects)


class SpiderFactory(object):
    @staticmethod
    def get_factory(factory):
        if factory == 'ali':
            return AliSpider()
        elif factory == 'nsfocus':
            return NsFocusSpider()
        elif factory == 'see_bug':
            return SeeBugSpider()
        elif factory == "sec_guest":
            return SecGuestSpider()
        raise TypeError('Unknown Factory.')


def see_bug_main():
    st = time.time()
    ali = SeeBugSpider('https://www.seebug.org/vuldb/vulnerabilities?page={页数}', 11)
    for i in ali.geturl():
        ali.run(i)
    use = time.time() - st
    print(use)


def sec_main():
    sgs = SecGuestSpider()
    sgs.multi_run()


if __name__ == '__main__':
    factory = SpiderFactory.get_factory("see_bug")
    Spider.multi_exec(factory.start)
