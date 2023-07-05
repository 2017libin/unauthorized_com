import random, time, os, sys

from pyfiglet import Figlet

all_choices=['zookeeper', 'ftp','elasticsearch','ldap','weblogic','vnc','hadoopyarn','rsync','kibana',
         'docker','dockerregistry','couchdb','jboss','jenkins','activemq','nfs','mongodb','zabbix','druid',
         'dubbo','swaggerui','harbor','ipc','actuator','btphpmyadmin','wordpress','uwsgi','kong','thinkadminv6',
         'phpfpm','solr','jupyter','kubernetes','redis','apachespark','memcached','atlassian','rabbitmq']

service_map = {
    '2181': 'zookeeper',
    '21': 'ftp',
    '9200': 'elasticsearch',
    '389': 'ldap',
    '7001': 'weblogic',
    '5900': 'vnc',
    '8088': 'hadoopyarn',
    '873': 'rsync',
    '5601': 'kibana',
    '2375': 'docker',
    '5984': 'couchdb',
    '8080': ['jboss', 'jenkins', 'swaggerui', 'dubbo', 'actuator', 'apachespark'],
    '5000': 'dockerregistry',
    '8161': 'activemq',
    '2049': 'nfs',
    '10051': 'zabbix',
    '8888': ['druid', 'jupyter'],
    '445': 'ipc',
    '888': 'btphpmyadmin',
    '80': ['wordpress', 'harbor'],
    '443': ['wordpress', 'harbor'],
    '1717': 'uwsgi',
    '8001': 'kong',
    '8000': 'thinkadminv6',
    '9000': 'phpfpm',
    '8983': 'solr',
    '6443': 'kubernetes',
    '6379': 'redis',
    '11211': 'memcached',
    '8095': 'atlassian',
    '15672': 'rabbitmq',
    '27017': 'mongodb'
}

def banner():
    print('命令行版未授权漏洞检测')
    print('version: 1.0 | made by xkllz && chase | date: 2023/07/14')
    print('**********************************************************************')
    print('----------------------------------------------------------------------')
    f = Figlet(font='slant',width=400)
    print(f.renderText('unauthorized'))
    print('----------------------------------------------------------------------')
    print('**********************************************************************')

def get_time():
    return time.strftime("@ %Y-%m-%d /%H:%M:%S/", time.localtime())


import random

# 打开 useragents.txt 文件并读取所有行
with open('user-agents.txt', 'r') as f:
    useragents = f.readlines()

# 随机选择一个 user agent
random_useragent = random.choice(useragents).strip()

headers={
    'user-agent':random_useragent
}
