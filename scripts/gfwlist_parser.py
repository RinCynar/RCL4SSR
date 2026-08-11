#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RCL4SSR gfwlist parser
======================
下载官方 gfwlist 并只更新 Ruleset/ProxyGFWlist.list 中的 "# GFW list" 段，
文件头部(# 代理列表 / # MyList && Other / # 国外域名 / # 国外域名关键字)
与尾部(# Amazon ... # VikACG)的自定义内容原样保留。

用法:
    python scripts/gfwlist_parser.py [--file Ruleset/ProxyGFWlist.list] [--rebuild] [--dry-run] [--quiet]
                                      [--no-exclude] [--no-exclude-keywords] [--exclude-from Ruleset]

    --rebuild              完全用官方 gfwlist 重建 GFW 段(默认合并保留旧条目)
    --dry-run              只打印统计，不写文件
    --no-exclude           不排除其他规则集已覆盖的域名(默认会排除)
    --no-exclude-keywords  不进行关键词排除(仅保留域名级排除)
    --exclude-from DIR     扫描排除项的规则集目录(默认 Ruleset)

行为:
    - 默认(合并模式)：新段 = 官方 gfwlist ∪ 旧 GFW 段条目，规则只增不减。
    - 默认会从 GFW 段中剔除其他规则集(AI/Telegram/FMEDIA 等)已覆盖的域名，
      避免同一域名在多个规则组里重复出现。例如 AI.list 的 DOMAIN-KEYWORD,grok
      会自动把 GFW 段里的 grok.com / grokipedia.com 剔除。

依赖: 仅 Python 3 标准库。
"""

import argparse
import base64
import glob
import ipaddress
import os
import re
import sys
import urllib.request

GFWLIST_URL = "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt"
UA = "Mozilla/5.0 (compatible; RCL4SSR-gfwlist-parser/1.0)"
SECTION_MARKER = "# GFW list"

# 上游解析脚本插入的测试标记行，保持其在段首/段尾以减小 diff 噪音
START_TOKEN = "DOMAIN-SUFFIX,gfwlist.start"
END_TOKEN = "DOMAIN-SUFFIX,gfwlist.end"

_DOMAIN_RE = re.compile(r"^[a-z0-9.\-_]+$")


def fetch_gfwlist(url):
    """下载并 base64 解码 gfwlist。"""
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=60) as resp:
        raw = resp.read()
    try:
        return base64.b64decode(raw).decode("utf-8")
    except UnicodeDecodeError:
        return base64.b64decode(raw).decode("utf-8", errors="replace")


def is_ipv4(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def parse_line(line):
    """把一条 AutoProxy/AdBlock 规则转成 Clash 规则行；无法转换的返回 None。"""
    line = line.strip()
    if not line or line.startswith("!") or line.startswith("["):
        return None
    if line.startswith("@@"):  # 白名单/例外规则，不进代理列表
        return None
    # 正则规则无法用 Clash 文本规则集表达，跳过（与上游行为一致）
    if line.startswith("/") and line.endswith("/") and len(line) > 2:
        return None

    if line.startswith("||"):
        host = line[2:]
    elif line.startswith("|http://") or line.startswith("|https://"):
        host = line.split("://", 1)[1] if "://" in line else line[1:]
    elif line.startswith("|"):
        host = line[1:]
    elif line.startswith("http://") or line.startswith("https://"):
        host = line
    else:
        host = line

    # 剥离路径、EasyList 分隔符(^)、通配符(*)、端口等
    host = host.split("/")[0]
    host = host.split("^")[0]
    host = host.split("*")[0]
    host = host.split(":")[0]
    host = host.strip().lstrip(".").lower()
    if not host or "." not in host:
        return None
    if not _DOMAIN_RE.match(host):
        return None

    # 与现有文件一致：GFW 段全部为 DOMAIN-SUFFIX，IP 规则跳过
    if is_ipv4(host):
        return None
    return "DOMAIN-SUFFIX,%s" % host


def parse_gfwlist(text):
    rules = []
    for raw in text.splitlines():
        item = parse_line(raw)
        if item:
            rules.append(item)
    return rules


def collect_exclusions(scan_dir, target_file):
    """扫描其他规则集文件，收集已覆盖的排除项。

    返回 (suffix_exact, keywords)：
    - suffix_exact: DOMAIN-SUFFIX / DOMAIN 后的域名集合
    - keywords:     DOMAIN-KEYWORD 后的关键词集合
    """
    suffix_exact = set()
    keywords = set()
    target_abs = os.path.abspath(target_file)
    for path in sorted(glob.glob(os.path.join(scan_dir, "*.list"))):
        if os.path.abspath(path) == target_abs:
            continue  # 不扫描目标文件自身(其头部/尾部是保留内容)
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line.startswith("DOMAIN-SUFFIX,") or line.startswith("DOMAIN,"):
                    item = line.split(",", 1)[1].strip().lower()
                    if item:
                        suffix_exact.add(item)
                elif line.startswith("DOMAIN-KEYWORD,"):
                    item = line.split(",", 1)[1].strip().lower()
                    if item:
                        keywords.add(item)
    return suffix_exact, keywords


def apply_exclusions(rules, suffix_exact, keywords):
    """剔除 GFW 段中已被其他规则集覆盖的条目。"""
    out = []
    for rule in rules:
        if rule.startswith("DOMAIN-SUFFIX,"):
            host = rule.split(",", 1)[1].strip()
            parts = host.split(".")
            # 域名级：host 本身或任一父域已在其他规则集 => 剔除
            if any(".".join(parts[i:]) in suffix_exact for i in range(len(parts))):
                continue
            # 关键词级：host 含其他规则集的关键词 => 剔除
            if any(keyword in host for keyword in keywords):
                continue
        out.append(rule)
    return out


def build_section(rules, legacy_rules=None):
    """生成新 GFW 段；gfwlist.start/end 固定放段首/段尾。

    - 默认(合并模式)：新段 = 官方 gfwlist ∪ 旧 GFW 段条目，规则只增不减，
      避免官方 gfwlist 近年大幅精简导致自用规则骤减。
    - --rebuild：完全用官方 gfwlist 重建。
    """
    merged = set(rules) if legacy_rules is None else set(rules) | set(legacy_rules)
    rest = sorted(r for r in merged if r not in (START_TOKEN, END_TOKEN))
    return [START_TOKEN] + rest + [END_TOKEN]


def split_file(lines):
    """定位 '# GFW list' 段，返回 (head, tail, marker_idx, end_idx)。

    head 包含 '# GFW list' 标记行；tail 从下一个 '# 注释' 段开始。
    """
    marker_idx = None
    for i, l in enumerate(lines):
        if l.rstrip() == SECTION_MARKER:
            marker_idx = i
            break
    if marker_idx is None:
        raise SystemExit("ERROR: 找不到 '%s' 标记，请检查文件格式" % SECTION_MARKER)

    end_idx = len(lines)
    for i in range(marker_idx + 1, len(lines)):
        if lines[i].startswith("#"):
            end_idx = i
            break

    head = lines[: marker_idx + 1]
    while head and head[-1].strip() == "":
        head.pop()
    tail = lines[end_idx:]
    while tail and tail[0].strip() == "":
        tail.pop(0)
    return head, tail, marker_idx, end_idx


def main():
    parser = argparse.ArgumentParser(description="只更新 ProxyGFWlist.list 的 '# GFW list' 段")
    parser.add_argument("--file", default="Ruleset/ProxyGFWlist.list")
    parser.add_argument("--rebuild", action="store_true",
                        help="完全用官方 gfwlist 重建 GFW 段(默认合并保留旧条目)")
    parser.add_argument("--no-exclude", action="store_true",
                        help="不排除其他规则集已覆盖的域名(默认会排除)")
    parser.add_argument("--no-exclude-keywords", action="store_true",
                        help="不进行关键词排除(仅保留域名级排除)")
    parser.add_argument("--exclude-from", default="Ruleset",
                        help="扫描排除项的规则集目录(默认 Ruleset)")
    parser.add_argument("--dry-run", action="store_true", help="只打印统计，不写文件")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    if not args.quiet:
        print("[*] 下载 gfwlist ...")
    rules = parse_gfwlist(fetch_gfwlist(GFWLIST_URL))
    if not rules:
        raise SystemExit("ERROR: gfwlist 解析结果为空，中止以避免破坏文件")

    with open(args.file, "r", encoding="utf-8") as f:
        text = f.read()
    lines = text.split("\n")

    head, tail, marker_idx, end_idx = split_file(lines)
    old_section = [l for l in lines[marker_idx + 1 : end_idx] if l.strip()]
    legacy = None if args.rebuild else [l for l in old_section if l.startswith("DOMAIN-SUFFIX,")]

    base = set(rules)
    if legacy is not None:
        base |= set(legacy)

    excluded = 0
    if not args.no_exclude:
        suffix_exact, keywords = collect_exclusions(args.exclude_from, args.file)
        if args.no_exclude_keywords:
            keywords = set()
        before = len(base)
        base = set(apply_exclusions(base, suffix_exact, keywords))
        excluded = before - len(base)

    section = build_section(base)
    old_len = len(old_section)

    new_text = "\n".join(head + section + [""] + tail)
    if new_text.endswith("\n"):
        new_text = new_text[:-1]

    if new_text == text:
        if not args.quiet:
            print("[=] GFW 段无变化，无需更新")
        return 0

    if args.dry_run:
        if not args.quiet:
            mode = "rebuild" if args.rebuild else "merge"
            excl = ("，剔除重复 %d 条" % excluded) if not args.no_exclude else "，排除已禁用"
            print("[~] dry-run(%s)：GFW 段 %d 行 -> %d 行%s" % (mode, old_len, len(section), excl))
            if old_section:
                print("    当前段首/段尾: %s | %s" % (old_section[0], old_section[-1]))
            print("    新段首/段尾: %s | %s" % (section[0], section[-1]))
        return 0

    with open(args.file, "w", encoding="utf-8", newline="\n") as f:
        f.write(new_text)
    excl = ("，剔除重复 %d 条" % excluded) if not args.no_exclude else "，排除已禁用"
    print("[+] 已更新 %s : GFW 段 %d 行 -> %d 行%s" % (args.file, old_len, len(section), excl))
    return 0


if __name__ == "__main__":
    sys.exit(main())
