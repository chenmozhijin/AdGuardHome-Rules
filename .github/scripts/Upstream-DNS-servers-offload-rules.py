import httpx
import time
import base64
import codecs
import yaml
import sys
from adblock_to_domain import adblock_to_domain

# Constants
DOWNLOAD_URLS = [
    "https://raw.githubusercontent.com/chenmozhijin/OpenWrt-K/main/files/etc/openclash/rule_provider/DirectRule-chenmozhijin.yaml",
    "https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf",
    "https://raw.githubusercontent.com/chenmozhijin/OpenWrt-K/main/files/etc/openclash/rule_provider/ProxyRule-chenmozhijin.yaml",
    "https://raw.githubusercontent.com/YW5vbnltb3Vz/domain-list-community/release/gfwlist.txt",
    "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/gfw.txt",
    "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt",
    "https://raw.githubusercontent.com/Loukky/gfwlist-by-loukky/master/gfwlist.txt"
]

RETRY_COUNT = 5
RETRY_WAIT_TIME = 10

KEY_MAPPING = {
    "https://raw.githubusercontent.com/chenmozhijin/OpenWrt-K/main/files/etc/openclash/rule_provider/DirectRule-chenmozhijin.yaml": "DirectRule-chenmozhijin",
    "https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf": "accelerated-domains-china",
    "https://raw.githubusercontent.com/chenmozhijin/OpenWrt-K/main/files/etc/openclash/rule_provider/ProxyRule-chenmozhijin.yaml": "ProxyRule-chenmozhijin",
    "https://raw.githubusercontent.com/YW5vbnltb3Vz/domain-list-community/release/gfwlist.txt": "base64_YW5vbnltb3Vz",
    "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/gfw.txt": "Loyalsoldier",
    "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt": "base64_gfwlist",
    "https://raw.githubusercontent.com/Loukky/gfwlist-by-loukky/master/gfwlist.txt": "base64_Loukky"
}


# Function to download content from URLs
def download_content(url):
    retry = 0
    while retry < RETRY_COUNT:
        response = httpx.get(url)
        if response.status_code == 200:
            return response.content
        else:
            print(f"获取 {url} 内容失败，状态码: {response.status_code}，尝试重试...")
            retry += 1
            time.sleep(RETRY_WAIT_TIME)
    print(f"无法获取 {url} 内容，已尝试 {RETRY_COUNT} 次")
    sys.exit(1)


# Function to decode base64 content
def decode_base64_content(content, key):
    if key.startswith("base64_"):
        key = key[len("base64_"):]
        return base64.b64decode(content).decode('utf-8')
    return content.decode('utf-8')


# Function to extract domain values from YAML data
def extract_domain_values_from_yaml(yaml_data):
    data = yaml.safe_load(yaml_data)
    payload = data.get("payload", [])
    domain_list = []
    for item in payload:
        if isinstance(item, str):
            parts = item.strip().split(",")
            if len(parts) == 2:
                if parts[0] == "DOMAIN-SUFFIX" or parts[0] == "DOMAIN":
                    domain_list.append(parts[1])
    return domain_list


# Function to remove duplicates from overseas domain lists
def remove_duplicates(overseas_domain_lists, china_domain_lists):
    temp_overseas_domain_list = overseas_domain_lists.copy()
    for overseas_domain in overseas_domain_lists:
        if any(overseas_domain == china_domain or overseas_domain.endswith("." + china_domain) for china_domain in china_domain_lists):
            temp_overseas_domain_list.remove(overseas_domain)
    return temp_overseas_domain_list


def validate_domain(domain):
    if not domain:
        return False
    # 检查空标签（连续点号、首尾点号）
    if '..' in domain or domain.startswith('.') or domain.endswith('.'):
        return False
    try:
        encoded = codecs.encode(domain, 'idna').decode('ascii')
    except (UnicodeError, UnicodeDecodeError):
        return False
    # DNS 线格式总长度 ≤253
    if len(encoded) > 253:
        return False
    for label in encoded.split('.'):
        if not label or len(label) > 63:
            return False
        if label.startswith('-') or label.endswith('-'):
            return False
        # 验证 xn-- 标签的 Punycode 载荷有效性
        # (codecs.encode 对已编码的 ACE 标签可能不做完整校验)
        if label.startswith('xn--'):
            try:
                label.encode('ascii').decode('punycode')
            except UnicodeError:
                return False
    return True


# Main processing logic
def process_domains():
    content_dict = {}
    for url in DOWNLOAD_URLS:
        content = download_content(url)
        key = KEY_MAPPING[url]
        content = decode_base64_content(content, key)
        content_dict[key] = content
        print(f"获取 {url} 内容成功")

    # Domain Lists
    china_domain_lists = []
    overseas_domain_lists = []
    for key, content in content_dict.items():
        if key in ['gfwlist', 'YW5vbnltb3Vz', 'Loukky']:
            china_domain_list, overseas_domain_list = adblock_to_domain(content)
            china_domain_lists.extend(china_domain_list)
            overseas_domain_lists.extend(overseas_domain_list)
        elif key == 'Loyalsoldier':
            overseas_domain_lists.extend(content.split('\n'))
        elif key == 'DirectRule-chenmozhijin':
            china_domain_lists.extend(extract_domain_values_from_yaml(content))
        elif key == 'ProxyRule-chenmozhijin':
            overseas_domain_lists.extend(extract_domain_values_from_yaml(content))
        elif key == 'accelerated-domains-china':
            for rule in content.split('\n'):
                if rule.startswith("server="):
                    china_domain_lists.append(rule.split("/")[1])

    print("开始去重")
    china_domain_lists = sorted(list(set(china_domain_lists)))
    overseas_domain_lists = sorted(list(set(overseas_domain_lists)))

    # Remove empty elements
    china_domain_lists = [item for item in china_domain_lists if item]
    overseas_domain_lists = [item for item in overseas_domain_lists if item]

    print("排除不合法域名（IDNA规范性检查）")
    before_count = len(china_domain_lists) + len(overseas_domain_lists)
    china_domain_lists = [d for d in china_domain_lists if validate_domain(d)]
    overseas_domain_lists = [d for d in overseas_domain_lists if validate_domain(d)]
    after_count = len(china_domain_lists) + len(overseas_domain_lists)
    print(f"排除了 {before_count - after_count} 个不合法域名")

    print("删除Overseas_domain_lists中的China_domain_lists内容")
    overseas_domain_lists = remove_duplicates(overseas_domain_lists, china_domain_lists)

    # Generate Upstream DNS Rules
    upstream_dns_rules = generate_upstream_dns_rules(china_domain_lists, overseas_domain_lists)

    # Write to file
    with open('AdGuardHome-dnslist(by cmzj).yaml', 'w', encoding='utf-8') as f:
        f.write(upstream_dns_rules)
    print("生成文件成功")


# Function to generate the Upstream DNS Rules
def generate_upstream_dns_rules(china_domain_lists, overseas_domain_lists):
    upstream_dns_rules = '127.0.0.1:6053\n127.0.0.1:5335\n[/'
    upstream_dns_rules += ''.join([f"{domain}/" for domain in china_domain_lists])
    upstream_dns_rules += ']127.0.0.1:6053\n[/'
    upstream_dns_rules += ''.join([f"{domain}/" for domain in overseas_domain_lists])
    upstream_dns_rules += ']127.0.0.1:5335\n'
    return upstream_dns_rules


if __name__ == "__main__":
    process_domains()
