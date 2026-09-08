def save_results(self, working: List[Dict], blacklisted: List[Dict]):
    # === WHITELIST ===
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
    
    # Сохраняем whitelist.txt
    with open(self.config.WHITELIST_TXT, 'w', encoding='utf-8') as f:
        f.write('\n'.join(whitelist_urls))
    
    # Сохраняем whitelist.yaml
    yaml_data = {'proxies': whitelist_proxies}
    with open(self.config.WHITELIST_YAML, 'w', encoding='utf-8') as f:
        yaml.dump(yaml_data, f, allow_unicode=True, default_flow_style=False)
    
    print(f"\n💾 WHITELIST: {len(working)} конфигов")
    print(f"  📄 {self.config.WHITELIST_TXT}")
    print(f"  📄 {self.config.WHITELIST_YAML}")
    
    # === BLACKLIST ===
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
    
    # Сохраняем blacklist.txt
    with open(self.config.BLACKLIST_TXT, 'w', encoding='utf-8') as f:
        f.write('\n'.join(blacklist_urls))
    
    # Сохраняем blacklist.yaml
    yaml_data = {'proxies': blacklist_proxies}
    with open(self.config.BLACKLIST_YAML, 'w', encoding='utf-8') as f:
        yaml.dump(yaml_data, f, allow_unicode=True, default_flow_style=False)
    
    print(f"\n💾 BLACKLIST: {len(blacklisted)} конфигов")
    print(f"  📄 {self.config.BLACKLIST_TXT}")
    print(f"  📄 {self.config.BLACKLIST_YAML}")
