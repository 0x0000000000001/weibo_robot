# -*- coding:utf-8 -*-
# /usr/bin/python2.7

import requests
import base64
import urllib
import rsa
import binascii
import re
import json
import random
import time
import logging
from bs4 import BeautifulSoup

logger = logging.getLogger("weibo")
logger.setLevel(logging.INFO)
fh = logging.FileHandler("weibo.log", mode="a", encoding="utf-8")
fmt = logging.Formatter('%(asctime)s - %(name)s - %(filename)s:%(lineno)d - %(message)s')
fh.setFormatter(fmt)
logger.addHandler(fh)


class Weibo(object):
    def __init__(self):
        self.s = requests.session()
        self.username = "xxxxxxxxxxxxx"
        self.password = "xxxxxxxxxxxxx"

        # 用户名加密
        self.su = base64.b64encode(urllib.quote(self.username))
        self.client = "ssologin.js(v1.4.18)"
        self.host = "http://weibo.com/"
        self.uniqueid = ""
        self.userdomain = ""
        self.home = ""
        self.last_mid = 0
        self.forward_mid = []
        self.signal = 0
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) \
            Chrome/53.0.2785.116 Safari/537.36",
            "Host": "login.sina.com.cn",
        }

    def get_json_data(self):
        # 获取返回的json数据，用于后续的登陆
        payload = {"entry": "weibo", "callback": "sinaSSOController.preloginCallBack", "su": self.su, "rsakt": "mod",
                   "checkpin": 1, "client": self.client}
        prelogin_url = "https://login.sina.com.cn/sso/prelogin.php"
        response = self.s.get(prelogin_url, params=payload, verify=False, headers=self.headers)
        data = re.findall("\((.*?)\)", response.text)[0]
        json_data = json.loads(data)
        return json_data

    @staticmethod
    def has_mrid_but_no_feedtype(tag):
        # bs过滤广告标签（广告微博）
        return tag.has_attr("mrid") and not tag.has_attr("feedtype")

    def login(self):
        json_data = self.get_json_data()
        # print(json_data)

        # 密码进行加密
        s = str(json_data["servertime"]) + '\t' + str(json_data["nonce"]) + '\n' + self.password
        key = rsa.PublicKey(int(json_data["pubkey"], 16), int("10001", 16))
        key = rsa.encrypt(s, key)
        sp = binascii.b2a_hex(key)

        post_data = {"entry": "weibo",
                     "gateway": 1,
                     "from": "",
                     "savestate": 7,
                     "useticket": 1,
                     "pagerefer": "",
                     "pcid": json_data["pcid"],
                     "vsnf": 1,
                     "su": self.su,
                     "service": "miniblog",
                     "servertime": int(time.time()),
                     "nonce": json_data["nonce"],
                     "pwencode": "rsa2",
                     "rsakv": json_data["rsakv"],
                     "sp": sp,
                     "sr": "1440*900",
                     "encoding": "UTF-8",
                     "prelt": "129",
                     "url": "http://weibo.com/ajaxlogin.php?framelogin=1&callback=parent.sinaSSOController.feedBackUrlCallBack",
                     "returntype": "META"
                     }

        if json_data.get("showpin", None) == 1:
            # 判断是否有验证码
            res = self.s.get(
                    "http://login.sina.com.cn/cgi/pin.php?r={}&s=0&p={}".format("".join(random.sample("123456789", 8)),
                                                                                json_data["pcid"]))
            with open("code.png", "wb") as f:
                f.write(res.content)
            post_data["door"] = raw_input("请输入验证码：")

        # 登陆微博
        res = self.s.post("http://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.18)", data=post_data,
                          headers=self.headers)
        if re.search("refresh", res.text):
            logger.error("验证码输入错误，重新登录中".decode("utf-8"))
            self.login()
        else:
            url = re.findall("location.replace\('(.*?)'\)", res.text)[0]
            # 验证登陆，此处302跳转
            self.headers["Host"] = "passport.weibo.com"
            res = self.s.get(url, allow_redirects=False, headers=self.headers)

            # 获得跳转链接
            location = res.headers["Location"]
            self.headers["Host"] = "weibo.com"
            res = self.s.get(location, headers=self.headers)
            user_info = re.findall("parent.sinaSSOController.feedBackUrlCallBack\((.*?)\)", res.text)[0]
            user_info = json.loads(user_info)
            if user_info["result"]:
                logger.info("登陆成功".decode("utf-8"))
                self.userdomain = user_info["userinfo"]["userdomain"]
                self.uniqueid = user_info["userinfo"]["uniqueid"]
            else:
                logger.error("登录失败，即将重新登录".decode("utf-8"))
                self.login()

    def parse_wb(self):
        # 解析微博首页数据
        self.home = "{}u/{}/home{}".format(self.host, self.uniqueid, self.userdomain)
        res = self.s.get(self.home, headers=self.headers)
        text = re.findall('<script>FM.view\(({"ns":"pl.content.homefeed.index".*?})\)', res.text)
        html = json.loads(text[0])
        html = html["html"]

        soup = BeautifulSoup(html, "lxml")
        # 获取每条微博的内容块，并排除广告微博
        cards = soup.find_all(Weibo.has_mrid_but_no_feedtype)
        mid, rid = (0, 0)
        for i, card in enumerate(cards):
            if i == 0 and int(card["mid"]) > self.last_mid:
                self.last_mid = int(card["mid"])
            elif int(card["mid"]) <= self.last_mid:
                break
            else:
                pass
            soup = BeautifulSoup(str(card), "lxml")

            expand = soup.find("div", class_="WB_feed_expand")
            if expand:
                # 多级转发的原始微博
                expand_nick = expand.find("div", class_="WB_info").a["title"]
                expand_tweet = expand.find("div", class_="WB_text").get_text(strip=True)
                if re.search(u"转发.*?[赠送抽]", expand_tweet, re.S):
                    ouid = re.findall("rouid=(\d+)", card["tbinfo"])[0]
                    # 判断是否已关注
                    res = self.s.get(
                            "http://weibo.com/aj/v6/user/newcard?ajwvr=6&id={}&refer_flag=0000015010_&type=1".format(
                                    ouid))
                    if re.search("unfollow", res.text):
                        # 已经关注
                        pass
                    else:
                        data = {"uid": ouid, "objectid": "", "f": "1", "extra": "", "refer_sort": "card",
                                "refer_flag": ["followed", "0000020001_"], "location": "v6_content_home",
                                "oid": self.uniqueid, "wforce": "1", "nogroup": "false", "fnick": expand_nick,
                                "template": "1", "refer_lflag": "0000015010_", "_t": "0"
                                }
                        self.headers["Origin"] = "http://weibo.com"
                        self.headers["Referer"] = self.home
                        # 关注
                        self.s.post("http://weibo.com/aj/f/followed?ajwvr=6&__rnd={}".format(int(time.time() * 1000)),
                                    data=data, headers=self.headers)
                    mid = re.findall("\d+", expand.find("div", class_="WB_info").a["suda-uatrack"])[0]
                    # 判断是否已经转发过
                    if mid not in self.forward_mid:
                        self.forward_mid.append(mid)
                        self.signal = 1
                        rid = re.findall("rid=([0-9_]*)", card["mrid"])[0]
            else:
                # 原创微博
                # 微博昵称
                # nick = soup.find("div", class_="WB_info").a["title"]

                # 微博内容
                tweet = soup.find("div", class_="WB_text W_f14").get_text(strip=True)

                if re.search(u"转发.*?[赠送抽]", tweet, re.S):
                    mid = card["mid"]
                    if mid not in self.forward_mid:
                        self.forward_mid.append(mid)
                        self.signal = 1
                        rid = re.findall("rid=([0-9_]*)", card["mrid"])[0]

            yield (mid, rid)

    def robot(self, args):
        # 自动转发评论微博

        if self.signal == 0:
            return
        self.signal = 0
        # 评论原微博 is_comment_base=1
        # 评论待转发的微博 is_comment=1
        forward_data = {"pic_src": "",
                        "pic_id": "",
                        "appkey": "",
                        "style_type": "1",
                        "mark": "",
                        "reason": "转发微博",
                        "location": "v6_content_home",
                        "pdetail": "",
                        "module": "",
                        "page_module_id": "",
                        "refer_sort": "",
                        "rank": "0",
                        "rankid": "",
                        "group_source": "group_all",
                        "_t": "0",
                        "mid": args[0],
                        "rid": args[1]
                        }

        # 转发并评论
        url = "http://weibo.com/aj/v6/mblog/forward?ajwvr=6&domain={}&__rnd={}".format(self.uniqueid,
                                                                                       int(time.time() * 1000))
        self.headers["Origin"] = "http://weibo.com"
        self.headers["Referer"] = self.home
        self.s.post(url, data=forward_data, headers=self.headers)

        # 点赞
        like_url = "http://weibo.com/aj/v6/like/add?ajwvr=6"
        like_data = {"location": "v6_content_home",
                     "group_source": "group_all",
                     "version": "mini",
                     "qid": "heart",
                     "like_src": "1",
                     "mid": args[0],
                     "rid": args[1]
                     }
        self.s.post(like_url, data=like_data, headers=self.headers)


if __name__ == "__main__":
    wb = Weibo()
    wb.login()
    while 1:
        map(wb.robot, wb.parse_wb())
        time.sleep(random.uniform(60, 120))
