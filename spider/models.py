# -*- coding: utf-8 -*-
from sqlalchemy import Column, String, Integer, Text
from sqlalchemy.ext.declarative import declarative_base

db_base = declarative_base()


class Vulnerability(db_base):
    __tablename__ = "vulnerability"
    id = Column(Integer, primary_key=True, autoincrement=True, nullable=False)
    name = Column(Text, nullable=True, comment="漏洞名称")
    company = Column(String(16), nullable=True, comment="来源厂商")
    url = Column(Text, nullable=True, comment="详情页url")
    type = Column(String(64), nullable=True, comment="漏洞类型")
    release_time = Column(String(64), nullable=True, comment="发布时间")
    update_time = Column(String(64), nullable=True, comment="更新时间")
    cve_id = Column(Text, nullable=True, comment="cve编号")
    source = Column(Text, nullable=True, comment="来源")
    detail = Column(Text, nullable=True, comment="漏洞详情")
    reference = Column(Text, nullable=True, comment="影响版本")
    level = Column(String(64), nullable=True, comment="漏洞评级")
    suggestion = Column(Text, nullable=True, comment="安全建议")
    link = Column(Text, nullable=True, comment="参考链接")
