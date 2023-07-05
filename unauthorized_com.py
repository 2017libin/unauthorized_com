import argparse
import threading
from dic import *
from config import *
import json

def port2service(port):
    return "test"

def check_ip(ip, services):
    result = {}
    # result['ip'] = ip
    if 'zookeeper' in services:
        result['zookeeper'] = check_zookeeper(ip)
    if 'ftp' in services:
        result['ftp'] = check_ftp(ip)
    if 'wordpress' in services:
        result['wordpress'] = check_wordpress(ip)
    if 'kibana' in services:
        result['kibana'] = check_kibana(ip)
    if 'thinkadminv6' in services:
        result['thinkadminv6'] = check_thinkadmin_v6(ip)
    if 'apachespark' in services:
        result['apachespark'] = check_apache_spark(ip)
    if 'kubernetes' in services:
        result['kubernetes'] = check_kubernetes_api_server(ip)
    if 'btphpmyadmin' in services:
        result['btphpmyadmin'] = check_bt_phpmyadmin(ip)
    if 'actuator' in services:
        result['actuator'] = check_spring_boot_actuator(ip)
    if 'docker' in services:
        result['docker'] = check_docker(ip)
    if 'zabbix' in services:
        result['zabbix'] = check_zabbix(ip)
    if 'dubbo' in services:
        result['dubbo'] = check_dubbo(ip)
    if 'dockerregistry' in services:
        result['dockerregistry'] = check_docker_registry(ip)
    if 'ipc' in services:
        result['ipc'] = check_ipc(ip)
    if 'redis' in services:
        result['redis'] = check_redis(ip)
    if 'jenkins' in services:
        result['jenkins'] = check_jenkins(ip)
    if 'druid' in services:
        result['druid'] = check_druid(ip)

    if 'couchdb' in services:
        result['couchdb'] = check_couchdb(ip)
    if 'uwsgi' in services:
        result['uwsgi'] = check_uwsgi(ip)
    if 'hadoopyarn' in services:
        result['hadoopyarn'] = check_hadoop_yarn(ip)
    if 'harbor' in services:
        result['harbor'] = check_harbor(ip)
    if 'swaggerui' in services:
        result['swaggerui'] = check_swaggerui(ip)
    if 'activemq' in services:
        result['activemq'] = check_activemq(ip)

    if 'jupyter' in services:
        result['jupyter'] = check_jupyter_notebook(ip)
    if 'phpfpm' in services:
        result['phpfpm'] = check_php_fpm_fastcgi(ip)
    if 'rabbitmq' in services:
        result['rabbitmq'] = check_rabbitmq(ip)
    if 'atlassian' in services:
        result['atlassian'] = check_atlassian_crowd(ip)
    if 'ldap' in services:
        result['ldap'] = check_ldap(ip)
    if 'weblogic' in services:
        result['weblogic'] = check_weblogic(ip)
    if 'nfs' in services:
        result['nfs'] = check_nfs(ip)
    if 'vnc' in services:
        result['vnc'] = check_vnc(ip)
    if 'solr' in services:
        result['solr'] = check_solr(ip)
    if 'jboss' in services:
        result['jboss'] = check_jboss(ip)
    if 'kong' in services:
        result['kong'] = check_kong(ip)
    if 'rsync' in services:
        result['rsync'] = check_rsync(ip)
    if 'mongodb' in services:
        result['mongodb'] = check_mongodb(ip)
    if 'memcached' in services:
        result['memcached'] = check_memcached(ip)

    if 'elasticsearch' in services:
        result['elasticsearch'] = check_elasticsearch(ip)
    return result


def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-i', '--ip', type=str, help='单个IP地址进行检测')
    group.add_argument('-f', '--file', help='包含IP地址的文件进行检测')
    # choices表示可选参数，并且可选的范围由all_choices限定
    parser.add_argument('-s', '--service', choices=all_choices, help='指定要检测的服务')
    # 对于True/False类型的参数，向add_argument方法中加入参数action=‘store_true’/‘store_false’
    # store_true就代表着一旦有这个参数，做出动作“将其值标为True”，也就是没有时，默认状态下其值为False
    parser.add_argument('-au', '--auto', action='store_true', help='根据端口测试服务')
    parser.add_argument('-a', '--all', action='store_true', help='测试所有支持的服务')
    parser.add_argument('-t', '--threads', type=int, default=10, help='指定线程数')
    parser.add_argument('-o', '--output', help='指定输出文件路径')
    args = parser.parse_args()

    services = []
    ipmap = {}
    if args.ip:
        if ':' not in args.ip:
            ip = args.ip
        else:
            ip = (args.ip.split(':')[0]).strip()
        ipmap[ip] = set()
    else:
        with open(args.file, 'r') as f:
            # ips = f.read().splitlines()
            for line in f:
                if ':' not in line:
                    ip = line.strip()
                else:
                    ip = (line.split(':')[0]).strip()
                if ip not in ipmap:
                        ipmap[ip] = set()
    if args.service:
        for ip in ipmap.keys():
            ipmap[ip].add(args.service)
        # services.append(args.service)
    elif args.all:
        for ip in ipmap.keys():
            ipmap[ip].update(all_choices)
        # services = [service for service in all_choices]
    elif args.auto:
        with open(args.file, 'r') as f:
            # ips = f.read().splitlines()
            for line in f:
                ip = (line.split(':')[0]).strip()
                port = (line.split(':')[1]).strip()
                if port not in service_map.keys():
                    continue
                if type(service_map[port]) == list:
                    ipmap[ip].update(service_map[port])
                else:
                    ipmap[ip].add(service_map[port])

    lock1 = threading.Lock()
    lock2 = threading.Lock()

    # results = dict()
    def worker(ip_t, service_t):
        result = check_ip(ip_t, service_t)

        # 多线程同步
        lock1.acquire()
        if ip_t not in results:
            results[ip] = dict()
        results[ip].update(result)
        lock1.release()
    
    threads = []
    for ip in ipmap.keys():
        results = dict()
        print(f'[*] 开始检测{ip}, {len(ipmap[ip])}条检测函数')
        for service in ipmap[ip]:
            t = threading.Thread(target=worker, args=(ip,service,))
            threads.append(t)
            t.start()
            if len(threads) >= args.threads:
                for t in threads:
                    t.join()
                threads.clear()

        lock2.acquire()
        # 每次扫描完一个ip就进行输出
        if args.output:
            with open(args.output, 'a+') as f:
                results_json = json.dumps(results, sort_keys=False, indent=4, separators=(',', ': '), ensure_ascii=False)
                f.write(results_json+'\n')
        else:
            results_json = json.dumps(results, sort_keys=False, indent=4, separators=(',', ': '), ensure_ascii=False)
            print(results_json+'\n')
        lock2.release()

    for t in threads:
        t.join()
    print('\n[+] ending {0}\n'.format(get_time()))


if __name__ == '__main__':
    banner()
    main()
