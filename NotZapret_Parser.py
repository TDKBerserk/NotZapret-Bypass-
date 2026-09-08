# NotZapret_Parser.py - Парсер с разделением на whitelist и blacklist
import asyncio
import json
import re
import os
import time
import random
import base64
import yaml
import shutil
import tempfile
from typing import List, Dict, Set, Optional, Tuple
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, quote
from pathlib import Path

import requests
import aiohttp
from telethon import TelegramClient
from telethon.errors import FloodWaitError
from telethon.tl.types import Message, MessageMediaDocument

# ==================== КОНФИГУРАЦИЯ ====================
class Config:
    API_ID = int(os.getenv('API_ID', 1234567))
    API_HASH = os.getenv('API_HASH', 'your_api_hash')
    
    MT_PROTO = os.getenv('MT_PROTO', 'socks5')
    MT_PROXY_HOST = os.getenv('MT_PROXY_HOST', '127.0.0.1')
    MT_PROXY_PORT = int(os.getenv('MT_PROXY_PORT', 1080))
    
    TG_FILE = 'tg.txt'
    SOURCES_FILE = 'sources.txt'
    SNI_FILE = 'sni_list.txt'
    IP_FILE = 'ip_list.txt'
    
    WHITELIST_TXT = 'whitelist.txt'
    WHITELIST_YAML = 'whitelist.yaml'
    WHITELIST_JSON = 'whitelist.json'
    BLACKLIST_TXT = 'blacklist.txt'
    BLACKLIST_YAML = 'blacklist.yaml'
    BLACKLIST_JSON = 'blacklist.json'
    
    TIMEOUT = 12
    CHECK_URL = 'https://www.gstatic.com/generate_204'
    PARALLEL_WORKERS = 50
    CYCLE_INTERVAL = 3600
    MAX_MESSAGES_PER_CHANNEL = 500

class NotZapretParser:
    def __init__(self):
        self.config = Config()
        self.client = None
        self.session = requests.Session()
        
        self.configs: Dict[str, Dict] = {}
        self.working_configs: Dict[str, Dict] = {}
        self.blacklisted_configs: Dict[str, Dict] = {}
        
        self.url_patterns = {
            'vless': re.compile(r'vless://[^\s<>"\'\)]+'),
            'trojan': re.compile(r'trojan://[^\s<>"\'\)]+'),
            'hysteria2': re.compile(r'hysteria2://[^\s<>"\'\)]+'),
            'vmess': re.compile(r'vmess://[^\s<>"\'\)]+'),
            'ss': re.compile(r'ss://[^\s<>"\'\)]+'),
            'socks': re.compile(r'socks://[^\s<>"\'\)]+')
        }
        
        self.sources: Set[str] = set()
        self.tg_channels: List[str] = []
        self.sni_list: List[str] = []
        self.ip_list: List[str] = []
        
        self.stats = {
            'total_found': 0,
            'after_cleanup': 0,
            'after_filter': 0,
            'after_tcp': 0,
            'working': 0,
            'blacklisted': 0,
            'cycles': 0
        }
        
        self.TAG = "NotZapret | Bypass"
        
    def load_configs(self):
        if os.path.exists(self.config.TG_FILE):
            with open(self.config.TG_FILE, 'r', encoding='utf-8') as f:
                self.tg_channels = [line.strip() for line in f if line.strip()]
            print(f"📡 Загружено каналов: {len(self.tg_channels)}")
        
        if os.path.exists(self.config.SOURCES_FILE):
            with open(self.config.SOURCES_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        self.sources.add(line.strip())
            print(f"📁 Загружено источников: {len(self.sources)}")
        
        if os.path.exists(self.config.SNI_FILE):
            with open(self.config.SNI_FILE, 'r', encoding='utf-8') as f:
                self.sni_list = [line.strip() for line in f if line.strip()]
            print(f"🔒 Загружено SNI: {len(self.sni_list)}")
        
        if os.path.exists(self.config.IP_FILE):
            with open(self.config.IP_FILE, 'r', encoding='utf-8') as f:
                self.ip_list = [line.strip() for line in f if line.strip()]
            print(f"🌐 Загружено IP: {len(self.ip_list)}")
    
    def parse_config(self, url: str) -> Optional[Dict]:
        try:
            parsed = urlparse(url)
            protocol = parsed.scheme
            
            if protocol not in ['vless', 'trojan', 'hysteria2', 'vmess', 'ss', 'socks']:
                return None
            
            config = {
                'url': url,
                'protocol': protocol,
                'raw': url,
                'transport': 'tcp',
                'host': parsed.hostname,
                'port': parsed.port or 443,
                'sni': None,
                'fingerprint': None,
                'alpn': None,
                'allowInsecure': False,
                'path': None,
                'serviceName': None,
                'host_header': None,
                'country': '🌐',
                'name': f"{self.TAG} #001"
            }
            
            if parsed.query:
                params = parse_qs(parsed.query)
                
                if 'sni' in params:
                    config['sni'] = params['sni'][0]
                if 'fingerprint' in params:
                    config['fingerprint'] = params['fingerprint'][0]
                if 'alpn' in params:
                    config['alpn'] = params['alpn'][0]
                if 'allowInsecure' in params:
                    config['allowInsecure'] = params['allowInsecure'][0].lower() == 'true'
                if 'path' in params:
                    config['path'] = params['path'][0]
                if 'serviceName' in params:
                    config['serviceName'] = params['serviceName'][0]
                if 'host' in params:
                    config['host_header'] = params['host'][0]
                if 'type' in params:
                    config['transport'] = params['type'][0]
                if 'headerType' in params:
                    config['transport'] = params['headerType'][0]
                
                if protocol == 'vless':
                    if 'flow' in params:
                        config['flow'] = params['flow'][0]
                    if 'pbk' in params:
                        config['publicKey'] = params['pbk'][0]
                    if 'sid' in params:
                        config['shortId'] = params['sid'][0]
                    if 'uuid' in params:
                        config['uuid'] = params['uuid'][0]
                
                if protocol == 'trojan':
                    if parsed.password:
                        config['password'] = parsed.password
                    if 'security' in params:
                        config['security'] = params['security'][0]
                
                if protocol == 'hysteria2':
                    if 'auth' in params:
                        config['auth'] = params['auth'][0]
                    if 'obfs' in params:
                        config['obfs'] = params['obfs'][0]
                    if 'bandwidth' in params:
                        config['bandwidth'] = params['bandwidth'][0]
            
            if config['transport'] in ['ws', 'websocket']:
                config['transport'] = 'websocket'
            elif config['transport'] == 'grpc':
                config['transport'] = 'grpc'
            
            return config
            
        except Exception as e:
            return None
    
    def extract_configs_from_text(self, text: str) -> List[Dict]:
        configs = []
        for protocol, pattern in self.url_patterns.items():
            matches = pattern.findall(text)
            for match in matches:
                config = self.parse_config(match)
                if config and config['url'] not in self.configs:
                    configs.append(config)
                    self.stats['total_found'] += 1
        return configs
    
    def decode_base64_configs(self, text: str) -> List[Dict]:
        configs = []
        try:
            decoded = base64.b64decode(text).decode('utf-8')
            configs.extend(self.extract_configs_from_text(decoded))
        except:
            pass
        return configs
    
    async def connect_telegram(self) -> bool:
        try:
            proxy = None
            if self.config.MT_PROTO:
                proxy = {
                    'proxy_type': self.config.MT_PROTO,
                    'addr': self.config.MT_PROXY_HOST,
                    'port': self.config.MT_PROXY_PORT
                }
                print(f"🔌 Прокси: {self.config.MT_PROTO}://{self.config.MT_PROXY_HOST}:{self.config.MT_PROXY_PORT}")
            
            self.client = TelegramClient(
                'session',
                self.config.API_ID,
                self.config.API_HASH,
                proxy=proxy
            )
            
            await self.client.start()
            print("✅ Подключено к Telegram через прокси")
            return True
            
        except Exception as e:
            print(f"❌ Ошибка подключения к Telegram: {e}")
            return False
    
    async def parse_telegram_channels(self) -> List[Dict]:
        all_configs = []
        
        if not self.tg_channels:
            print("⚠️ Нет каналов для парсинга")
            return all_configs
        
        print(f"\n📡 Парсинг {len(self.tg_channels)} каналов...")
        
        for channel in self.tg_channels:
            try:
                entity = await self.client.get_entity(channel)
                print(f"  📡 Парсинг: {channel}")
                
                configs_found = 0
                
                async for message in self.client.iter_messages(
                    entity, 
                    limit=self.config.MAX_MESSAGES_PER_CHANNEL
                ):
                    if not message.text:
                        continue
                    
                    configs = self.extract_configs_from_text(message.text)
                    configs.extend(self.decode_base64_configs(message.text))
                    
                    http_links = re.findall(r'https?://[^\s<>"\'\)]+', message.text)
                    for link in http_links:
                        if any(ext in link for ext in ['.txt', '.json', '.yaml', '.yml', 'sub']):
                            self.sources.add(link)
                    
                    if message.media and isinstance(message.media, MessageMediaDocument):
                        file_name = f"temp_{int(time.time())}_{random.randint(1000, 9999)}"
                        path = await message.download_media(file=file_name)
                        if path:
                            try:
                                with open(path, 'r', encoding='utf-8') as f:
                                    content = f.read()
                                    configs.extend(self.extract_configs_from_text(content))
                                    configs.extend(self.decode_base64_configs(content))
                                os.remove(path)
                            except:
                                pass
                    
                    for config in configs:
                        if config['url'] not in self.configs:
                            self.configs[config['url']] = config
                            all_configs.append(config)
                            configs_found += 1
                
                print(f"    ✅ Найдено конфигов: {configs_found}")
                
            except FloodWaitError as e:
                print(f"  ⏳ FloodWait: {e.seconds} секунд")
                break
            except Exception as e:
                print(f"  ❌ Ошибка {channel}: {e}")
                continue
        
        return all_configs
    
    async def parse_sources(self) -> List[Dict]:
        all_configs = []
        
        if not self.sources:
            print("⚠️ Нет источников для парсинга")
            return all_configs
        
        print(f"\n📁 Парсинг {len(self.sources)} источников...")
        
        async with aiohttp.ClientSession() as session:
            for source in self.sources:
                try:
                    print(f"  📁 Загрузка: {source}")
                    
                    async with session.get(source, timeout=30) as response:
                        if response.status == 200:
                            content = await response.text()
                            
                            configs = self.extract_configs_from_text(content)
                            configs.extend(self.decode_base64_configs(content))
                            
                            try:
                                data = json.loads(content)
                                if 'configs' in data:
                                    for c in data['configs']:
                                        if 'url' in c:
                                            config = self.parse_config(c['url'])
                                            if config:
                                                configs.append(config)
                            except:
                                pass
                            
                            try:
                                data = yaml.safe_load(content)
                                if 'proxies' in data:
                                    for proxy in data['proxies']:
                                        if 'server' in proxy and 'port' in proxy:
                                            url = self.yaml_to_url(proxy)
                                            if url:
                                                config = self.parse_config(url)
                                                if config:
                                                    configs.append(config)
                            except:
                                pass
                            
                            for config in configs:
                                if config['url'] not in self.configs:
                                    self.configs[config['url']] = config
                                    all_configs.append(config)
                            
                            print(f"    ✅ Найдено конфигов: {len(configs)}")
                        else:
                            print(f"    ❌ Ошибка {response.status}")
                            
                except Exception as e:
                    print(f"    ❌ Ошибка загрузки {source}: {e}")
        
        return all_configs
    
    def yaml_to_url(self, proxy: Dict) -> Optional[str]:
        try:
            protocol = proxy.get('type', 'vless')
            server = proxy.get('server', '')
            port = proxy.get('port', 443)
            
            if protocol == 'vless':
                uuid = proxy.get('uuid', '')
                params = []
                
                if 'flow' in proxy:
                    params.append(f"flow={proxy['flow']}")
                if 'sni' in proxy or 'servername' in proxy:
                    sni = proxy.get('sni') or proxy.get('servername')
                    if sni:
                        params.append(f"sni={sni}")
                if 'fingerprint' in proxy or 'client-fingerprint' in proxy:
                    fp = proxy.get('fingerprint') or proxy.get('client-fingerprint')
                    if fp:
                        params.append(f"fingerprint={fp}")
                if 'public-key' in proxy or ('reality-opts' in proxy and 'public-key' in proxy['reality-opts']):
                    pbk = proxy.get('public-key')
                    if not pbk and 'reality-opts' in proxy:
                        pbk = proxy['reality-opts'].get('public-key')
                    if pbk:
                        params.append(f"pbk={pbk}")
                if 'short-id' in proxy or ('reality-opts' in proxy and 'short-id' in proxy['reality-opts']):
                    sid = proxy.get('short-id')
                    if not sid and 'reality-opts' in proxy:
                        sid = proxy['reality-opts'].get('short-id')
                    if sid:
                        params.append(f"sid={sid}")
                
                query = '&'.join(params)
                return f"vless://{uuid}@{server}:{port}?{query}"
            
            elif protocol == 'trojan':
                password = proxy.get('password', '')
                params = []
                
                if 'sni' in proxy or 'servername' in proxy:
                    sni = proxy.get('sni') or proxy.get('servername')
                    if sni:
                        params.append(f"sni={sni}")
                if 'fingerprint' in proxy or 'client-fingerprint' in proxy:
                    fp = proxy.get('fingerprint') or proxy.get('client-fingerprint')
                    if fp:
                        params.append(f"fingerprint={fp}")
                
                query = '&'.join(params)
                return f"trojan://{password}@{server}:{port}?{query}"
            
            elif protocol == 'hysteria2':
                password = proxy.get('password', '')
                params = []
                
                if 'sni' in proxy or 'servername' in proxy:
                    sni = proxy.get('sni') or proxy.get('servername')
                    if sni:
                        params.append(f"sni={sni}")
                if 'auth' in proxy:
                    params.append(f"auth={proxy['auth']}")
                if 'obfs' in proxy:
                    params.append(f"obfs={proxy['obfs']}")
                
                query = '&'.join(params)
                return f"hysteria2://{password}@{server}:{port}?{query}"
            
        except:
            return None
    
    def cleanup_configs(self, configs: List[Dict]) -> List[Dict]:
        clean = {}
        
        for config in configs:
            url = config['url']
            
            parsed = urlparse(url)
            query = parse_qs(parsed.query)
            
            for param in ['test', 'debug', 'log']:
                if param in query:
                    del query[param]
            
            new_query = urlencode(query, doseq=True)
            normalized = urlparse(
                scheme=parsed.scheme,
                netloc=parsed.netloc,
                path=parsed.path,
                params=parsed.params,
                query=new_query,
                fragment=parsed.fragment
            ).geturl()
            
            if not self.is_valid_config(config):
                continue
            
            clean[normalized] = config
        
        return list(clean.values())
    
    def is_valid_config(self, config: Dict) -> bool:
        required_fields = ['protocol', 'host', 'port']
        
        for field in required_fields:
            if not config.get(field):
                return False
        
        try:
            port = int(config['port'])
            if port < 1 or port > 65535:
                return False
        except:
            return False
        
        host = config['host']
        if not host or len(host) < 3:
            return False
        
        if host.startswith(('127.', '192.168.', '10.', '172.16.')):
            return False
        
        return True
    
    def filter_by_ip_and_sni(self, configs: List[Dict]) -> Tuple[List[Dict], List[Dict]]:
        allowed = []
        blocked = []
        
        for config in configs:
            host = config['host']
            sni = config.get('sni', '')
            
            ip_match = re.match(r'^(\d{1,3})\.(\d{1,3})\.', host)
            if ip_match:
                ip_prefix = f"{ip_match.group(1)}.{ip_match.group(2)}"
                if self.ip_list and ip_prefix not in self.ip_list:
                    blocked.append(config)
                    continue
            
            if self.sni_list:
                sni_matched = False
                for sni_pattern in self.sni_list:
                    if sni_pattern in sni or sni_pattern in host:
                        sni_matched = True
                        break
                if not sni_matched:
                    blocked.append(config)
                    continue
            
            allowed.append(config)
        
        print(f"  📊 Фильтрация: {len(allowed)} в whitelist, {len(blocked)} в blacklist")
        return allowed, blocked
    
    async def tcp_check(self, config: Dict) -> bool:
        if config['protocol'] == 'hysteria2':
            return True
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    config['host'],
                    int(config['port']),
                    loop=asyncio.get_event_loop()
                ),
                timeout=self.config.TIMEOUT
            )
            writer.close()
            await writer.wait_closed()
            return True
            
        except:
            return False
    
    async def tcp_check_all(self, configs: List[Dict]) -> Tuple[List[Dict], List[Dict]]:
        print(f"\n🔌 TCP проверка {len(configs)} конфигов...")
        
        semaphore = asyncio.Semaphore(50)
        
        async def check_with_semaphore(config):
            async with semaphore:
                result = await self.tcp_check(config)
                return config, result
        
        tasks = [check_with_semaphore(config) for config in configs]
        results = await asyncio.gather(*tasks)
        
        passed = [config for config, passed in results if passed]
        failed = [config for config, passed in results if not passed]
        
        print(f"  ✅ Прошли TCP: {len(passed)}/{len(configs)}")
        print(f"  ❌ Не прошли TCP: {len(failed)}")
        
        return passed, failed
    
    async def test_config(self, config: Dict) -> Tuple[Dict, bool, float]:
        try:
            temp_dir = tempfile.mkdtemp()
            
            if config['protocol'] in ['vless', 'trojan', 'vmess']:
                xray_config = self.generate_xray_config(config)
                config_path = os.path.join(temp_dir, 'config.json')
                
                with open(config_path, 'w') as f:
                    json.dump(xray_config, f)
                
                process = await asyncio.create_subprocess_exec(
                    'xray',
                    '-config', config_path,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL
                )
                
                await asyncio.sleep(0.5)
                
                start_time = time.time()
                result = await self.check_through_socks5()
                latency = (time.time() - start_time) * 1000
                
                process.terminate()
                await process.wait()
                
                if result:
                    return config, True, latency
                
            elif config['protocol'] == 'hysteria2':
                result = await self.test_hysteria2(config)
                if result:
                    return config, True, 0
            
            return config, False, 0
            
        except Exception as e:
            return config, False, 0
        finally:
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)
    
    def generate_xray_config(self, config: Dict) -> Dict:
        protocol = config['protocol']
        
        xray_config = {
            "log": {"loglevel": "warning"},
            "inbounds": [{
                "protocol": "socks",
                "port": 1080,
                "settings": {"udp": True}
            }],
            "outbounds": [{
                "protocol": protocol,
                "settings": {},
                "streamSettings": {
                    "network": config.get('transport', 'tcp'),
                    "security": "tls" if not config.get('publicKey') else "reality"
                }
            }]
        }
        
        if protocol == 'vless':
            xray_config['outbounds'][0]['settings']['vnext'] = [{
                "address": config['host'],
                "port": int(config['port']),
                "users": [{
                    "id": config.get('uuid', ''),
                    "flow": config.get('flow', 'xtls-rprx-vision'),
                    "encryption": "none"
                }]
            }]
            
            if config.get('publicKey'):
                xray_config['outbounds'][0]['streamSettings']['realitySettings'] = {
                    "serverName": config.get('sni', ''),
                    "fingerprint": config.get('fingerprint', 'chrome'),
                    "publicKey": config.get('publicKey', ''),
                    "shortId": config.get('shortId', '')
                }
            else:
                xray_config['outbounds'][0]['streamSettings']['tlsSettings'] = {
                    "serverName": config.get('sni', ''),
                    "allowInsecure": config.get('allowInsecure', False),
                    "fingerprint": config.get('fingerprint', 'chrome')
                }
        
        elif protocol == 'trojan':
            xray_config['outbounds'][0]['settings']['servers'] = [{
                "address": config['host'],
                "port": int(config['port']),
                "password": config.get('password', '')
            }]
            
            xray_config['outbounds'][0]['streamSettings']['tlsSettings'] = {
                "serverName": config.get('sni', ''),
                "allowInsecure": config.get('allowInsecure', False),
                "fingerprint": config.get('fingerprint', 'chrome')
            }
        
        if config.get('transport') == 'websocket':
            xray_config['outbounds'][0]['streamSettings']['wsSettings'] = {
                "path": config.get('path', '/'),
                "headers": {"Host": config.get('host_header', '')}
            }
        
        if config.get('transport') == 'grpc':
            xray_config['outbounds'][0]['streamSettings']['grpcSettings'] = {
                "serviceName": config.get('serviceName', '')
            }
        
        return xray_config
    
    async def check_through_socks5(self) -> bool:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.config.CHECK_URL,
                    proxy='socks5://127.0.0.1:1080',
                    timeout=5
                ) as response:
                    return response.status in [200, 204]
        except:
            return False
    
    async def test_hysteria2(self, config: Dict) -> bool:
        try:
            temp_dir = tempfile.mkdtemp()
            config_path = os.path.join(temp_dir, 'config.yaml')
            
            hysteria_config = {
                "server": f"{config['host']}:{config['port']}",
                "auth": config.get('auth', ''),
                "obfs": config.get('obfs', ''),
                "bandwidth": config.get('bandwidth', '')
            }
            
            with open(config_path, 'w') as f:
                yaml.dump(hysteria_config, f)
            
            process = await asyncio.create_subprocess_exec(
                'hysteria2',
                '-config', config_path,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            
            await asyncio.sleep(0.5)
            
            result = await self.check_through_socks5()
            
            process.terminate()
            await process.wait()
            
            return result
            
        except:
            return False
        finally:
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)
    
    async def test_all_configs(self, configs: List[Dict]) -> Tuple[List[Dict], List[Dict]]:
        print(f"\n🧪 Полная проверка {len(configs)} конфигов...")
        
        semaphore = asyncio.Semaphore(self.config.PARALLEL_WORKERS)
        
        async def test_with_semaphore(config):
            async with semaphore:
                return await self.test_config(config)
        
        tasks = [test_with_semaphore(config) for config in configs]
        results = await asyncio.gather(*tasks)
        
        working = []
        failed = []
        
        for config, passed, latency in results:
            if passed:
                config['latency'] = round(latency, 2)
                config['tag'] = self.TAG
                working.append(config)
            else:
                failed.append(config)
        
        print(f"  ✅ Рабочих (whitelist): {len(working)}/{len(configs)}")
        print(f"  ❌ В черный список: {len(failed)}")
        
        return working, failed
    
    def save_results(self, working: List[Dict], blacklisted: List[Dict]):
        whitelist_urls = []
        whitelist_proxies = []
        
        for i, config in enumerate(working, 1):
            if '#' in config['url']:
                clean_url = config['url'].split('#')[0]
            else:
                clean_url = config['url']
            
            tag = quote(self.TAG, safe='')
            url_with_tag = f"{clean_url}#{tag}"
            whitelist_urls.append(url_with_tag)
            
            proxy = self.url_to_yaml(config)
            if proxy:
                proxy['name'] = f"{config.get('country', '🌐')} {self.TAG} #{str(i).zfill(3)}"
                whitelist_proxies.append(proxy)
        
        with open(self.config.WHITELIST_TXT, 'w', encoding='utf-8') as f:
            f.write('\n'.join(whitelist_urls))
        
        yaml_data = {'proxies': whitelist_proxies}
        with open(self.config.WHITELIST_YAML, 'w', encoding='utf-8') as f:
            yaml.dump(yaml_data, f, allow_unicode=True, default_flow_style=False)
        
        with open(self.config.WHITELIST_JSON, 'w', encoding='utf-8') as f:
            json.dump({
                'timestamp': datetime.now().isoformat(),
                'count': len(working),
                'tag': self.TAG,
                'proxies': whitelist_proxies
            }, f, indent=2, ensure_ascii=False)
        
        print(f"\n💾 WHITELIST: {len(working)} конфигов")
        print(f"  📄 {self.config.WHITELIST_TXT}")
        print(f"  📄 {self.config.WHITELIST_YAML}")
        print(f"  📄 {self.config.WHITELIST_JSON}")
        
        blacklist_urls = []
        blacklist_proxies = []
        
        for i, config in enumerate(blacklisted, 1):
            if '#' in config['url']:
                clean_url = config['url'].split('#')[0]
            else:
                clean_url = config['url']
            
            blacklist_urls.append(clean_url)
            
            proxy = self.url_to_yaml(config)
            if proxy:
                proxy['name'] = f"{config.get('country', '🌐')} {self.TAG} #{str(i).zfill(3)}"
                blacklist_proxies.append(proxy)
        
        with open(self.config.BLACKLIST_TXT, 'w', encoding='utf-8') as f:
            f.write('\n'.join(blacklist_urls))
        
        yaml_data = {'proxies': blacklist_proxies}
        with open(self.config.BLACKLIST_YAML, 'w', encoding='utf-8') as f:
            yaml.dump(yaml_data, f, allow_unicode=True, default_flow_style=False)
        
        with open(self.config.BLACKLIST_JSON, 'w', encoding='utf-8') as f:
            json.dump({
                'timestamp': datetime.now().isoformat(),
                'count': len(blacklisted),
                'tag': self.TAG,
                'proxies': blacklist_proxies
            }, f, indent=2, ensure_ascii=False)
        
        print(f"\n💾 BLACKLIST: {len(blacklisted)} конфигов")
        print(f"  📄 {self.config.BLACKLIST_TXT}")
        print(f"  📄 {self.config.BLACKLIST_YAML}")
        print(f"  📄 {self.config.BLACKLIST_JSON}")
    
    def url_to_yaml(self, config: Dict) -> Optional[Dict]:
        try:
            proxy = {
                'type': config['protocol'],
                'server': config['host'],
                'port': int(config['port']),
                'udp': True
            }
            
            if config['protocol'] == 'vless':
                proxy['uuid'] = config.get('uuid', '')
                proxy['encryption'] = 'none'
                proxy['flow'] = config.get('flow', 'xtls-rprx-vision')
                proxy['tls'] = True
                
                if config.get('sni'):
                    proxy['servername'] = config['sni']
                if config.get('fingerprint'):
                    proxy['client-fingerprint'] = config['fingerprint']
                if config.get('publicKey'):
                    proxy['reality-opts'] = {
                        'public-key': config['publicKey'],
                        'short-id': config.get('shortId', '')
                    }
                if config.get('transport') == 'websocket':
                    proxy['network'] = 'ws'
                    proxy['ws-opts'] = {
                        'path': config.get('path', '/'),
                        'headers': {'Host': config.get('host_header', '')}
                    }
                if config.get('transport') == 'grpc':
                    proxy['network'] = 'grpc'
                    proxy['grpc-opts'] = {
                        'grpc-service-name': config.get('serviceName', '')
                    }
            
            elif config['protocol'] == 'trojan':
                proxy['password'] = config.get('password', '')
                proxy['tls'] = True
                
                if config.get('sni'):
                    proxy['servername'] = config['sni']
                if config.get('fingerprint'):
                    proxy['client-fingerprint'] = config['fingerprint']
                if config.get('transport') == 'websocket':
                    proxy['network'] = 'ws'
                    proxy['ws-opts'] = {
                        'path': config.get('path', '/'),
                        'headers': {'Host': config.get('host_header', '')}
                    }
            
            elif config['protocol'] == 'hysteria2':
                proxy['password'] = config.get('auth', '')
                proxy['tls'] = True
                
                if config.get('sni'):
                    proxy['sni'] = config['sni']
                if config.get('obfs'):
                    proxy['obfs'] = config['obfs']
                if config.get('bandwidth'):
                    proxy['bandwidth'] = config['bandwidth']
                proxy['skip-cert-verify'] = True
            
            return proxy
            
        except Exception as e:
            return None
    
    async def run_cycle(self):
        print(f"\n{'='*50}")
        print(f"🔄 ЦИКЛ #{self.stats['cycles'] + 1} - NotZapret Parser")
        print(f"{'='*50}")
        
        self.load_configs()
        
        if self.working_configs:
            print(f"📥 Импорт {len(self.working_configs)} работающих конфигов...")
            for url, config in self.working_configs.items():
                if url not in self.configs:
                    self.configs[url] = config
        
        tg_configs = await self.parse_telegram_channels()
        print(f"📡 Из Telegram: {len(tg_configs)} конфигов")
        
        source_configs = await self.parse_sources()
        print(f"📁 Из источников: {len(source_configs)} конфигов")
        
        all_configs = list(self.configs.values())
        print(f"\n📊 Всего найдено: {len(all_configs)}")
        
        cleaned = self.cleanup_configs(all_configs)
        self.stats['after_cleanup'] = len(cleaned)
        print(f"🧹 После очистки: {len(cleaned)}")
        
        allowed, filtered_blocked = self.filter_by_ip_and_sni(cleaned)
        self.stats['after_filter'] = len(allowed)
        self.stats['blacklisted'] += len(filtered_blocked)
        
        tcp_passed, tcp_failed = await self.tcp_check_all(allowed)
        self.stats['after_tcp'] = len(tcp_passed)
        self.stats['blacklisted'] += len(tcp_failed)
        
        working, test_failed = await self.test_all_configs(tcp_passed)
        self.stats['working'] = len(working)
        self.stats['blacklisted'] += len(test_failed)
        
        all_blacklisted = filtered_blocked + tcp_failed + test_failed
        
        if working or all_blacklisted:
            self.save_results(working, all_blacklisted)
            
            for config in working:
                self.working_configs[config['url']] = config
            for config in all_blacklisted:
                self.blacklisted_configs[config['url']] = config
        
        print(f"\n📊 ИТОГОВАЯ СТАТИСТИКА:")
        print(f"  Найдено всего: {self.stats['total_found']}")
        print(f"  После очистки: {self.stats['after_cleanup']}")
        print(f"  После фильтрации (whitelist): {self.stats['after_filter']}")
        print(f"  После TCP (whitelist): {self.stats['after_tcp']}")
        print(f"  ✅ РАБОЧИХ (WHITELIST): {self.stats['working']}")
        print(f"  ❌ В ЧЕРНОМ СПИСКЕ (BLACKLIST): {self.stats['blacklisted']}")
        
        self.stats['cycles'] += 1
        
        print(f"\n⏳ Следующий цикл через {self.config.CYCLE_INTERVAL//60} минут...")
    
    async def run(self):
        print("🚀 Запуск NotZapret Parser")
        print("📋 Форматы: whitelist.txt, whitelist.yaml, whitelist.json")
        print("📋 blacklist.txt, blacklist.yaml, blacklist.json")
        print("="*50)
        
        if not await self.connect_telegram():
            print("❌ Не удалось подключиться к Telegram")
            return
        
        try:
            while True:
                await self.run_cycle()
                await asyncio.sleep(self.config.CYCLE_INTERVAL)
                
        except KeyboardInterrupt:
            print("\n⏹️ Остановка парсера...")
        finally:
            await self.client.disconnect()
            print("👋 До свидания!")

if __name__ == "__main__":
    parser = NotZapretParser()
    asyncio.run(parser.run())
