#!/usr/bin/env python3
"""
╔═════════════════════════════════════════════════════════════════════╗
║       CIDR PULL v2.0 — Residential ISP Whitelist                   ║
║       ASN → CIDR · AbuseIPDB audit · SQLite cache · Diff engine   ║
║       CIDR aggregation · IP lookup · Multi-format export           ║
║       Daemon/scheduler · Webhook notifications · Custom ASNs       ║
╚═════════════════════════════════════════════════════════════════════╝
"""

import json
import time
import sys
import os
import random
import sqlite3
import argparse
import ipaddress
import hashlib
from datetime import datetime, date
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from typing import Optional

import requests
from rich.console import Console
from rich.table import Table
from rich.progress import (
    Progress, SpinnerColumn, BarColumn, TextColumn,
    TimeElapsedColumn, TaskProgressColumn,
)
from rich.panel import Panel
from rich.columns import Columns
from rich import box
from rich.prompt import Prompt, Confirm
from rich.rule import Rule
from rich.tree import Tree

console = Console()

# ─────────────────────────────────────────────────────────────
# DEFAULTS
# ─────────────────────────────────────────────────────────────

DEFAULT_CACHE_DIR       = Path.home() / ".cidr_pull"
RIPE_TTL_HOURS          = 24.0
ABUSE_TTL_HOURS         = 12.0
ABUSEIPDB_DAILY_LIMIT   = 1_000

# ─────────────────────────────────────────────────────────────
# ASN DATABASE
# ─────────────────────────────────────────────────────────────

ASN_DB: dict[int, dict] = {
    # ── USA ──────────────────────────────────────────────────
    7018:   {"name": "AT&T",                    "country": "US", "region": "NA", "mobile": False},
    7922:   {"name": "Comcast",                 "country": "US", "region": "NA", "mobile": False},
    20115:  {"name": "Charter/Spectrum",         "country": "US", "region": "NA", "mobile": False},
    701:    {"name": "Verizon",                  "country": "US", "region": "NA", "mobile": False},
    19108:  {"name": "Suddenlink",               "country": "US", "region": "NA", "mobile": False},
    22773:  {"name": "Cox Communications",       "country": "US", "region": "NA", "mobile": False},
    5650:   {"name": "Frontier",                 "country": "US", "region": "NA", "mobile": False},
    209:    {"name": "CenturyLink/Lumen",        "country": "US", "region": "NA", "mobile": False},
    21859:  {"name": "Zayo",                     "country": "US", "region": "NA", "mobile": False},
    16591:  {"name": "Google Fiber",             "country": "US", "region": "NA", "mobile": False},
    401174: {"name": "DISH Network",             "country": "US", "region": "NA", "mobile": False},
    11191:  {"name": "WilTel/Windstream",        "country": "US", "region": "NA", "mobile": False},
    812:    {"name": "Rogers Canada",            "country": "CA", "region": "NA", "mobile": False},
    3602:   {"name": "Bell Aliant",              "country": "CA", "region": "NA", "mobile": False},
    6539:   {"name": "Telus",                    "country": "CA", "region": "NA", "mobile": False},
    855:    {"name": "Bell Canada",              "country": "CA", "region": "NA", "mobile": False},
    852:    {"name": "Telus (alt)",              "country": "CA", "region": "NA", "mobile": False},
    14663:  {"name": "Zayo US",                  "country": "US", "region": "NA", "mobile": False},
    6327:   {"name": "Shaw Communications",      "country": "CA", "region": "NA", "mobile": False},
    5769:   {"name": "Videotron",                "country": "CA", "region": "NA", "mobile": False},
    7992:   {"name": "Comcast (alt)",            "country": "US", "region": "NA", "mobile": False},
    8151:   {"name": "Telmex",                   "country": "MX", "region": "NA", "mobile": False},
    13994:  {"name": "Telmex (alt)",             "country": "MX", "region": "NA", "mobile": False},
    28554:  {"name": "Triara/Telmex",            "country": "MX", "region": "NA", "mobile": False},
    262916: {"name": "Claro Brasil",             "country": "BR", "region": "SA", "mobile": False},
    17072:  {"name": "NET Serviços",             "country": "BR", "region": "SA", "mobile": False},
    26599:  {"name": "Oi Telemar",               "country": "BR", "region": "SA", "mobile": False},
    18881:  {"name": "GVT Brasil",               "country": "BR", "region": "SA", "mobile": False},
    28573:  {"name": "NET Claro Brasil",         "country": "BR", "region": "SA", "mobile": False},
    4230:   {"name": "Embratel",                 "country": "BR", "region": "SA", "mobile": False},
    26615:  {"name": "Tim Brasil",               "country": "BR", "region": "SA", "mobile": True},
    7738:   {"name": "Telemar Norte",            "country": "BR", "region": "SA", "mobile": False},
    2856:   {"name": "BT",                       "country": "GB", "region": "EU", "mobile": False},
    5089:   {"name": "Virgin Media",             "country": "GB", "region": "EU", "mobile": False},
    5607:   {"name": "Sky UK",                   "country": "GB", "region": "EU", "mobile": False},
    13285:  {"name": "Plusnet",                  "country": "GB", "region": "EU", "mobile": False},
    5378:   {"name": "TalkTalk (alt)",           "country": "GB", "region": "EU", "mobile": False},
    6871:   {"name": "Plusnet (alt)",            "country": "GB", "region": "EU", "mobile": False},
    3320:   {"name": "Deutsche Telekom",         "country": "DE", "region": "EU", "mobile": False},
    3209:   {"name": "Vodafone DE",              "country": "DE", "region": "EU", "mobile": False},
    6805:   {"name": "Telefónica DE",            "country": "DE", "region": "EU", "mobile": False},
    3215:   {"name": "Orange France",            "country": "FR", "region": "EU", "mobile": False},
    12322:  {"name": "Free (Iliad)",             "country": "FR", "region": "EU", "mobile": False},
    15557:  {"name": "SFR",                      "country": "FR", "region": "EU", "mobile": False},
    5410:   {"name": "Bouygues",                 "country": "FR", "region": "EU", "mobile": False},
    3269:   {"name": "Telecom Italia",           "country": "IT", "region": "EU", "mobile": False},
    30722:  {"name": "Vodafone IT",              "country": "IT", "region": "EU", "mobile": False},
    1267:   {"name": "WIND Tre IT",              "country": "IT", "region": "EU", "mobile": False},
    12874:  {"name": "Fastweb",                  "country": "IT", "region": "EU", "mobile": False},
    3352:   {"name": "Telefónica Spain",         "country": "ES", "region": "EU", "mobile": False},
    12479:  {"name": "Orange Spain",             "country": "ES", "region": "EU", "mobile": False},
    12430:  {"name": "Vodafone Spain",           "country": "ES", "region": "EU", "mobile": False},
    12389:  {"name": "Rostelecom",               "country": "RU", "region": "EU", "mobile": False},
    8359:   {"name": "MTS Russia",               "country": "RU", "region": "EU", "mobile": True},
    8402:   {"name": "Corbina/Beeline RU",       "country": "RU", "region": "EU", "mobile": False},
    3216:   {"name": "Vimpelcom",                "country": "RU", "region": "EU", "mobile": False},
    12714:  {"name": "Net By Net",               "country": "RU", "region": "EU", "mobile": False},
    41733:  {"name": "Enforta RU",               "country": "RU", "region": "EU", "mobile": False},
    2516:   {"name": "KDDI Japan",               "country": "JP", "region": "AS", "mobile": False},
    17676:  {"name": "SoftBank Japan",           "country": "JP", "region": "AS", "mobile": False},
    2527:   {"name": "So-net Japan",             "country": "JP", "region": "AS", "mobile": False},
    4713:   {"name": "NTT OCN Japan",            "country": "JP", "region": "AS", "mobile": False},
    18137:  {"name": "NTT PC Communications",    "country": "JP", "region": "AS", "mobile": False},
    3462:   {"name": "HiNet Taiwan",             "country": "TW", "region": "AS", "mobile": False},
    9919:   {"name": "Taiwan Fixed Network",     "country": "TW", "region": "AS", "mobile": False},
    18182:  {"name": "Taiwan Mobile (fixed)",    "country": "TW", "region": "AS", "mobile": False},
    9299:   {"name": "PLDT Philippines",         "country": "PH", "region": "AS", "mobile": True},
    17648:  {"name": "SKY Cable PH",             "country": "PH", "region": "AS", "mobile": False},
    132132: {"name": "Airtel India (fixed)",     "country": "IN", "region": "AS", "mobile": False},
    132199: {"name": "BSNL India",               "country": "IN", "region": "AS", "mobile": False},
    55836:  {"name": "Reliance Jio (fixed)",     "country": "IN", "region": "AS", "mobile": True},
    24560:  {"name": "Airtel India (alt)",       "country": "IN", "region": "AS", "mobile": False},
    9498:   {"name": "BSNL (alt)",               "country": "IN", "region": "AS", "mobile": False},
    9829:   {"name": "BSNL (alt2)",              "country": "IN", "region": "AS", "mobile": False},
    131269: {"name": "Hathway Cable",            "country": "IN", "region": "AS", "mobile": False},
    18209:  {"name": "Hathway (alt)",            "country": "IN", "region": "AS", "mobile": False},
    24309:  {"name": "ACT Fibernet",             "country": "IN", "region": "AS", "mobile": False},
    17488:  {"name": "Hathway IP",               "country": "IN", "region": "AS", "mobile": False},
    134674: {"name": "Atria Convergence",        "country": "IN", "region": "AS", "mobile": False},
    133982: {"name": "DEN Networks",             "country": "IN", "region": "AS", "mobile": False},
    7029:   {"name": "Windstream",               "country": "US", "region": "NA", "mobile": False},
    6128:   {"name": "Optimum/Altice",           "country": "US", "region": "NA", "mobile": False},
    30036:  {"name": "Mediacom",                 "country": "US", "region": "NA", "mobile": False},
    12008:  {"name": "WideOpenWest (WOW)",       "country": "US", "region": "NA", "mobile": False},
    11404:  {"name": "Astound/Wave",             "country": "US", "region": "NA", "mobile": False},
    14593:  {"name": "Starlink/SpaceX",          "country": "US", "region": "NA", "mobile": False},
    4181:   {"name": "TDS Telecom",              "country": "US", "region": "NA", "mobile": False},
    27382:  {"name": "Ziply Fiber",              "country": "US", "region": "NA", "mobile": False},
    11492:  {"name": "Sparklight/Cable ONE",     "country": "US", "region": "NA", "mobile": False},
    19262:  {"name": "Verizon FiOS",             "country": "US", "region": "NA", "mobile": False},
    26827:  {"name": "altafiber/Cinci Bell",     "country": "US", "region": "NA", "mobile": False},
    20001:  {"name": "Charter/TWC (alt)",        "country": "US", "region": "NA", "mobile": False},
    7843:   {"name": "Charter/TWC (alt2)",       "country": "US", "region": "NA", "mobile": False},
    10796:  {"name": "Charter (alt3)",           "country": "US", "region": "NA", "mobile": False},
    33588:  {"name": "Charter (alt4)",           "country": "US", "region": "NA", "mobile": False},
    22909:  {"name": "Comcast (alt2)",           "country": "US", "region": "NA", "mobile": False},
    7015:   {"name": "Comcast (alt3)",           "country": "US", "region": "NA", "mobile": False},
    21928:  {"name": "T-Mobile US (Home Int.)",  "country": "US", "region": "NA", "mobile": True},
    577:    {"name": "Bell Canada (alt)",        "country": "CA", "region": "NA", "mobile": False},
    6082:   {"name": "Cogeco",                   "country": "CA", "region": "NA", "mobile": False},
    5577:   {"name": "Eastlink",                 "country": "CA", "region": "NA", "mobile": False},
    7786:   {"name": "TELUS (alt)",              "country": "CA", "region": "NA", "mobile": False},
    13999:  {"name": "Megacable",                "country": "MX", "region": "NA", "mobile": False},
    28006:  {"name": "Cablemas",                 "country": "MX", "region": "NA", "mobile": False},
    7162:   {"name": "Vivo/Telefônica (fixed)",  "country": "BR", "region": "SA", "mobile": False},
    28343:  {"name": "Copel Telecom",            "country": "BR", "region": "SA", "mobile": False},
    16735:  {"name": "Algar Telecom",            "country": "BR", "region": "SA", "mobile": False},
    27699:  {"name": "Telefônica BR (alt)",      "country": "BR", "region": "SA", "mobile": False},
    28598:  {"name": "Desktop/Virtua",           "country": "BR", "region": "SA", "mobile": False},
    22047:  {"name": "VTR Chile",                "country": "CL", "region": "SA", "mobile": False},
    7418:   {"name": "Entel Chile",              "country": "CL", "region": "SA", "mobile": False},
    14117:  {"name": "Claro Chile",              "country": "CL", "region": "SA", "mobile": False},
    7303:   {"name": "Telecom Argentina",        "country": "AR", "region": "SA", "mobile": False},
    11664:  {"name": "Telecentro Argentina",     "country": "AR", "region": "SA", "mobile": False},
    22927:  {"name": "Movistar Argentina",       "country": "AR", "region": "SA", "mobile": False},
    10318:  {"name": "Fibertel/Cablevision",     "country": "AR", "region": "SA", "mobile": False},
    19037:  {"name": "Claro Argentina",          "country": "AR", "region": "SA", "mobile": False},
    3816:   {"name": "Movistar Colombia",        "country": "CO", "region": "SA", "mobile": False},
    13489:  {"name": "UNE/EPM Colombia",         "country": "CO", "region": "SA", "mobile": False},
    27750:  {"name": "Claro Colombia",           "country": "CO", "region": "SA", "mobile": False},
    14080:  {"name": "ETB Bogotá",               "country": "CO", "region": "SA", "mobile": False},
    6147:   {"name": "Telefónica Peru",          "country": "PE", "region": "SA", "mobile": False},
    10481:  {"name": "Claro Peru",               "country": "PE", "region": "SA", "mobile": False},
    8048:   {"name": "CANTV Venezuela",          "country": "VE", "region": "SA", "mobile": False},
    25135:  {"name": "Vodafone UK (fixed)",      "country": "GB", "region": "EU", "mobile": False},
    5462:   {"name": "EE/BT",                    "country": "GB", "region": "EU", "mobile": False},
    9105:   {"name": "TalkTalk",                 "country": "GB", "region": "EU", "mobile": False},
    35228:  {"name": "TalkTalk (alt2)",          "country": "GB", "region": "EU", "mobile": False},
    8190:   {"name": "KCOM",                     "country": "GB", "region": "EU", "mobile": False},
    29562:  {"name": "Vodafone Kabel DE",        "country": "DE", "region": "EU", "mobile": False},
    31334:  {"name": "Kabel Deutschland",        "country": "DE", "region": "EU", "mobile": False},
    8422:   {"name": "NetCologne",               "country": "DE", "region": "EU", "mobile": False},
    6830:   {"name": "Liberty Global/UPC",       "country": "DE", "region": "EU", "mobile": False},
    21502:  {"name": "Numericable/SFR",          "country": "FR", "region": "EU", "mobile": False},
    15704:  {"name": "MasMovil",                 "country": "ES", "region": "EU", "mobile": False},
    12338:  {"name": "Jazztel/Orange ES",        "country": "ES", "region": "EU", "mobile": False},
    8612:   {"name": "Tiscali Italy",            "country": "IT", "region": "EU", "mobile": False},
    1136:   {"name": "KPN",                      "country": "NL", "region": "EU", "mobile": False},
    33915:  {"name": "Ziggo",                    "country": "NL", "region": "EU", "mobile": False},
    9143:   {"name": "Ziggo (alt)",              "country": "NL", "region": "EU", "mobile": False},
    5615:   {"name": "XS4ALL/KPN",              "country": "NL", "region": "EU", "mobile": False},
    5432:   {"name": "Proximus",                 "country": "BE", "region": "EU", "mobile": False},
    6848:   {"name": "Telenet Belgium",          "country": "BE", "region": "EU", "mobile": False},
    12392:  {"name": "Voo Belgium",              "country": "BE", "region": "EU", "mobile": False},
    3303:   {"name": "Swisscom",                 "country": "CH", "region": "EU", "mobile": False},
    6730:   {"name": "Sunrise",                  "country": "CH", "region": "EU", "mobile": False},
    15627:  {"name": "UPC Switzerland",          "country": "CH", "region": "EU", "mobile": False},
    8447:   {"name": "A1 Telekom Austria",       "country": "AT", "region": "EU", "mobile": False},
    12635:  {"name": "Telekabel Wien",           "country": "AT", "region": "EU", "mobile": False},
    25255:  {"name": "Liwest",                   "country": "AT", "region": "EU", "mobile": False},
    3301:   {"name": "Telia Sweden",             "country": "SE", "region": "EU", "mobile": False},
    8473:   {"name": "Bahnhof Sweden",           "country": "SE", "region": "EU", "mobile": False},
    21371:  {"name": "Bredbandsbolaget/Telenor", "country": "SE", "region": "EU", "mobile": False},
    12552:  {"name": "IP-Only Sweden",           "country": "SE", "region": "EU", "mobile": False},
    2119:   {"name": "Telenor Norway",           "country": "NO", "region": "EU", "mobile": False},
    8896:   {"name": "Altibox/Lyse",             "country": "NO", "region": "EU", "mobile": False},
    2116:   {"name": "Telenor NO (alt)",         "country": "NO", "region": "EU", "mobile": False},
    719:    {"name": "Elisa Finland",            "country": "FI", "region": "EU", "mobile": False},
    1759:   {"name": "Telia Finland",            "country": "FI", "region": "EU", "mobile": False},
    16086:  {"name": "DNA Finland",              "country": "FI", "region": "EU", "mobile": False},
    3292:   {"name": "TDC Denmark",              "country": "DK", "region": "EU", "mobile": False},
    2874:   {"name": "YouSee/TDC",               "country": "DK", "region": "EU", "mobile": False},
    5617:   {"name": "Orange Poland",            "country": "PL", "region": "EU", "mobile": False},
    12741:  {"name": "Netia Poland",             "country": "PL", "region": "EU", "mobile": False},
    5588:   {"name": "T-Mobile PL (fixed)",      "country": "PL", "region": "EU", "mobile": False},
    29314:  {"name": "Vectra Poland",            "country": "PL", "region": "EU", "mobile": False},
    50607:  {"name": "Inea Poland",              "country": "PL", "region": "EU", "mobile": False},
    5610:   {"name": "O2 Czech Republic",        "country": "CZ", "region": "EU", "mobile": False},
    35236:  {"name": "Vodafone Czech",           "country": "CZ", "region": "EU", "mobile": False},
    5483:   {"name": "Magyar Telekom",           "country": "HU", "region": "EU", "mobile": False},
    29179:  {"name": "Vodafone Hungary",         "country": "HU", "region": "EU", "mobile": False},
    6764:   {"name": "UPC Hungary",              "country": "HU", "region": "EU", "mobile": False},
    21334:  {"name": "DIGI Hungary",             "country": "HU", "region": "EU", "mobile": False},
    9050:   {"name": "Telekom Romania",          "country": "RO", "region": "EU", "mobile": False},
    8708:   {"name": "RCS&RDS/Digi RO",          "country": "RO", "region": "EU", "mobile": False},
    31178:  {"name": "UPC Romania",              "country": "RO", "region": "EU", "mobile": False},
    8866:   {"name": "Vivacom Bulgaria",         "country": "BG", "region": "EU", "mobile": False},
    34224:  {"name": "Neterra Bulgaria",         "country": "BG", "region": "EU", "mobile": False},
    6846:   {"name": "Ukrtelecom",               "country": "UA", "region": "EU", "mobile": False},
    13188:  {"name": "Volia Ukraine",            "country": "UA", "region": "EU", "mobile": False},
    21219:  {"name": "Datagroup Ukraine",        "country": "UA", "region": "EU", "mobile": False},
    34187:  {"name": "Fregat Ukraine",           "country": "UA", "region": "EU", "mobile": False},
    8771:   {"name": "Telekom Serbia",           "country": "RS", "region": "EU", "mobile": False},
    31042:  {"name": "Serbia Broadband",         "country": "RS", "region": "EU", "mobile": False},
    5391:   {"name": "T-HT Croatia",             "country": "HR", "region": "EU", "mobile": False},
    6855:   {"name": "Slovak Telekom",           "country": "SK", "region": "EU", "mobile": False},
    2860:   {"name": "NOS Portugal",             "country": "PT", "region": "EU", "mobile": False},
    12353:  {"name": "Vodafone Portugal",        "country": "PT", "region": "EU", "mobile": False},
    15525:  {"name": "MEO/Altice PT",            "country": "PT", "region": "EU", "mobile": False},
    6799:   {"name": "OTE/Cosmote Greece",       "country": "GR", "region": "EU", "mobile": False},
    15617:  {"name": "Forthnet Greece",          "country": "GR", "region": "EU", "mobile": False},
    9121:   {"name": "Türk Telekom",             "country": "TR", "region": "EU", "mobile": False},
    34984:  {"name": "SuperOnline Turkey",       "country": "TR", "region": "EU", "mobile": False},
    47331:  {"name": "Türk Telekom (alt)",       "country": "TR", "region": "EU", "mobile": False},
    15493:  {"name": "Dom.ru/ERTelecom",         "country": "RU", "region": "EU", "mobile": False},
    25513:  {"name": "MGTS Moscow",              "country": "RU", "region": "EU", "mobile": False},
    43267:  {"name": "TTK/TransTeleCom",         "country": "RU", "region": "EU", "mobile": False},
    8749:   {"name": "Enforta Russia",           "country": "RU", "region": "EU", "mobile": False},
    4694:   {"name": "OCN/NTT Communications",  "country": "JP", "region": "AS", "mobile": False},
    4685:   {"name": "IIJ Japan",               "country": "JP", "region": "AS", "mobile": False},
    9613:   {"name": "Asahi Net Japan",          "country": "JP", "region": "AS", "mobile": False},
    7521:   {"name": "NTT PC Communications",   "country": "JP", "region": "AS", "mobile": False},
    4766:   {"name": "KT Corp Korea",            "country": "KR", "region": "AS", "mobile": False},
    9318:   {"name": "SK Broadband Korea",       "country": "KR", "region": "AS", "mobile": False},
    17858:  {"name": "LG U+ Korea (fixed)",      "country": "KR", "region": "AS", "mobile": False},
    9416:   {"name": "So-net Taiwan",            "country": "TW", "region": "AS", "mobile": False},
    10026:  {"name": "PCCW/HKT",                "country": "HK", "region": "AS", "mobile": False},
    4515:   {"name": "PCCW (alt)",              "country": "HK", "region": "AS", "mobile": False},
    9269:   {"name": "HKBN",                    "country": "HK", "region": "AS", "mobile": False},
    4760:   {"name": "HKBN (alt)",              "country": "HK", "region": "AS", "mobile": False},
    9293:   {"name": "HGC/City Telecom",         "country": "HK", "region": "AS", "mobile": False},
    1221:   {"name": "Telstra Australia",        "country": "AU", "region": "OC", "mobile": False},
    4804:   {"name": "Optus Australia",          "country": "AU", "region": "OC", "mobile": False},
    7545:   {"name": "TPG Australia",            "country": "AU", "region": "OC", "mobile": False},
    4739:   {"name": "iiNet/TPG",               "country": "AU", "region": "OC", "mobile": False},
    38817:  {"name": "Aussie Broadband",         "country": "AU", "region": "OC", "mobile": False},
    38220:  {"name": "Internode/TPG",           "country": "AU", "region": "OC", "mobile": False},
    38753:  {"name": "Vocus Australia",          "country": "AU", "region": "OC", "mobile": False},
    131072: {"name": "Telstra (alt)",            "country": "AU", "region": "OC", "mobile": False},
    9790:   {"name": "Spark NZ",                "country": "NZ", "region": "OC", "mobile": False},
    17746:  {"name": "Vodafone NZ (fixed)",      "country": "NZ", "region": "OC", "mobile": False},
    4771:   {"name": "Orcon/Voyager",           "country": "NZ", "region": "OC", "mobile": False},
    23860:  {"name": "MTNL India",              "country": "IN", "region": "AS", "mobile": False},
    18101:  {"name": "Reliance Comm (fixed)",   "country": "IN", "region": "AS", "mobile": False},
    45820:  {"name": "Tikona India",            "country": "IN", "region": "AS", "mobile": False},
    45528:  {"name": "Excitel India",           "country": "IN", "region": "AS", "mobile": False},
    23944:  {"name": "Converge ICT",            "country": "PH", "region": "AS", "mobile": False},
    9584:   {"name": "ePLDT",                   "country": "PH", "region": "AS", "mobile": False},
    17974:  {"name": "Telkom Indonesia",        "country": "ID", "region": "AS", "mobile": False},
    7713:   {"name": "Telkom ID (alt)",         "country": "ID", "region": "AS", "mobile": False},
    45727:  {"name": "Biznet Indonesia",        "country": "ID", "region": "AS", "mobile": False},
    9341:   {"name": "CBN Indonesia",           "country": "ID", "region": "AS", "mobile": False},
    45558:  {"name": "MNC Play",               "country": "ID", "region": "AS", "mobile": False},
    38285:  {"name": "MyRepublic ID",          "country": "ID", "region": "AS", "mobile": False},
    7643:   {"name": "VNPT Vietnam",           "country": "VN", "region": "AS", "mobile": False},
    45899:  {"name": "VNPT (alt)",             "country": "VN", "region": "AS", "mobile": False},
    18403:  {"name": "FPT Telecom",            "country": "VN", "region": "AS", "mobile": False},
    45903:  {"name": "CMC Telecom VN",         "country": "VN", "region": "AS", "mobile": False},
    7470:   {"name": "TOT Thailand",           "country": "TH", "region": "AS", "mobile": False},
    9331:   {"name": "CAT Telecom TH",         "country": "TH", "region": "AS", "mobile": False},
    45758:  {"name": "True Online (fixed)",    "country": "TH", "region": "AS", "mobile": False},
    4750:   {"name": "TRUE Corp Thailand",     "country": "TH", "region": "AS", "mobile": False},
    131445: {"name": "3BB Thailand",           "country": "TH", "region": "AS", "mobile": False},
    4788:   {"name": "TM/Unifi Malaysia",      "country": "MY", "region": "AS", "mobile": False},
    10030:  {"name": "TM Malaysia (alt)",      "country": "MY", "region": "AS", "mobile": False},
    9930:   {"name": "TIME dotCom",            "country": "MY", "region": "AS", "mobile": False},
    9506:   {"name": "Singtel",               "country": "SG", "region": "AS", "mobile": False},
    4657:   {"name": "Singtel (alt)",         "country": "SG", "region": "AS", "mobile": False},
    3758:   {"name": "Singtel (alt2)",        "country": "SG", "region": "AS", "mobile": False},
    7473:   {"name": "Singtel (alt3)",        "country": "SG", "region": "AS", "mobile": False},
    10091:  {"name": "MyRepublic SG",         "country": "SG", "region": "AS", "mobile": False},
    8551:   {"name": "Bezeq Israel",          "country": "IL", "region": "ME", "mobile": False},
    12400:  {"name": "Partner Comm IL",       "country": "IL", "region": "ME", "mobile": False},
    6869:   {"name": "Bezeq International",   "country": "IL", "region": "ME", "mobile": False},
    25019:  {"name": "STC Saudi Arabia",      "country": "SA", "region": "ME", "mobile": False},
    39386:  {"name": "STC (alt)",             "country": "SA", "region": "ME", "mobile": False},
    5384:   {"name": "Etisalat UAE",          "country": "AE", "region": "ME", "mobile": False},
    15802:  {"name": "du Telecom UAE (fixed)","country": "AE", "region": "ME", "mobile": False},
    3741:   {"name": "Telkom SA",             "country": "ZA", "region": "AF", "mobile": False},
    6536:   {"name": "Internet Solutions ZA", "country": "ZA", "region": "AF", "mobile": False},
    36874:  {"name": "Vodacom ZA (fixed)",    "country": "ZA", "region": "AF", "mobile": False},
    37457:  {"name": "Rain ZA (fixed)",       "country": "ZA", "region": "AF", "mobile": False},
    37680:  {"name": "Cool Ideas ZA",         "country": "ZA", "region": "AF", "mobile": False},
    8452:   {"name": "Telecom Egypt/WE",      "country": "EG", "region": "AF", "mobile": False},
    24863:  {"name": "LINKdotNET Egypt",      "country": "EG", "region": "AF", "mobile": False},
    6713:   {"name": "Maroc Telecom",         "country": "MA", "region": "AF", "mobile": False},
    36925:  {"name": "Inwi Morocco",          "country": "MA", "region": "AF", "mobile": False},
}

REGION_NAMES = {
    "NA": "North America", "SA": "South America", "EU": "Europe",
    "AS": "Asia",          "OC": "Oceania",        "ME": "Middle East",
    "AF": "Africa",
}
REGION_COLORS = {
    "NA": "bright_blue", "SA": "green",      "EU": "yellow",
    "AS": "magenta",     "OC": "cyan",       "ME": "bright_red",
    "AF": "bright_yellow",
}
FLAG_MAP = {
    "US": "🇺🇸", "CA": "🇨🇦", "MX": "🇲🇽", "BR": "🇧🇷", "AR": "🇦🇷",
    "CL": "🇨🇱", "CO": "🇨🇴", "PE": "🇵🇪", "VE": "🇻🇪", "GB": "🇬🇧",
    "DE": "🇩🇪", "FR": "🇫🇷", "IT": "🇮🇹", "ES": "🇪🇸", "NL": "🇳🇱",
    "BE": "🇧🇪", "CH": "🇨🇭", "AT": "🇦🇹", "SE": "🇸🇪", "NO": "🇳🇴",
    "FI": "🇫🇮", "DK": "🇩🇰", "PL": "🇵🇱", "CZ": "🇨🇿", "HU": "🇭🇺",
    "RO": "🇷🇴", "BG": "🇧🇬", "UA": "🇺🇦", "RS": "🇷🇸", "HR": "🇭🇷",
    "SK": "🇸🇰", "PT": "🇵🇹", "GR": "🇬🇷", "TR": "🇹🇷", "RU": "🇷🇺",
    "JP": "🇯🇵", "KR": "🇰🇷", "TW": "🇹🇼", "HK": "🇭🇰", "AU": "🇦🇺",
    "NZ": "🇳🇿", "IN": "🇮🇳", "PH": "🇵🇭", "ID": "🇮🇩", "VN": "🇻🇳",
    "TH": "🇹🇭", "MY": "🇲🇾", "SG": "🇸🇬", "IL": "🇮🇱", "SA": "🇸🇦",
    "AE": "🇦🇪", "ZA": "🇿🇦", "EG": "🇪🇬", "MA": "🇲🇦",
}

# ─────────────────────────────────────────────────────────────
# SQLITE CACHE
# ─────────────────────────────────────────────────────────────

class CacheDB:
    """
    SQLite-backed persistence layer for:
      • RIPE announced-prefix results      (TTL: 24 h default)
      • AbuseIPDB per-IP check results     (TTL: 12 h default)
      • Daily AbuseIPDB quota tracking
      • CIDR snapshots for diff comparison
    """

    _SCHEMA = """
        CREATE TABLE IF NOT EXISTS ripe_cache (
            asn        INTEGER PRIMARY KEY,
            v4_json    TEXT    NOT NULL,
            v6_json    TEXT    NOT NULL,
            fetched_at TEXT    NOT NULL
        );
        CREATE TABLE IF NOT EXISTS abuse_cache (
            ip         TEXT PRIMARY KEY,
            data_json  TEXT NOT NULL,
            fetched_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS quota_tracker (
            date       TEXT PRIMARY KEY,
            used       INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS snapshots (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL,
            filter_key  TEXT    NOT NULL,
            v4_json     TEXT    NOT NULL,
            v6_json     TEXT    NOT NULL,
            asn_count   INTEGER NOT NULL DEFAULT 0
        );
    """

    def __init__(self, cache_dir: Path = DEFAULT_CACHE_DIR):
        cache_dir.mkdir(parents=True, exist_ok=True)
        self.path = cache_dir / "cache.db"
        self._db  = sqlite3.connect(str(self.path), check_same_thread=False)
        self._db.executescript(self._SCHEMA)
        self._db.commit()

    def close(self):
        self._db.close()

    # ── internal ──────────────────────────────────────────────

    @staticmethod
    def _fresh(fetched_at: str, ttl_hours: float) -> bool:
        try:
            age = datetime.utcnow() - datetime.fromisoformat(fetched_at)
            return age.total_seconds() < ttl_hours * 3600
        except Exception:
            return False

    def _now(self) -> str:
        return datetime.utcnow().isoformat()

    # ── RIPE ──────────────────────────────────────────────────

    def get_ripe(self, asn: int, ttl: float = RIPE_TTL_HOURS) -> Optional[dict]:
        row = self._db.execute(
            "SELECT v4_json, v6_json, fetched_at FROM ripe_cache WHERE asn=?", (asn,)
        ).fetchone()
        if row and self._fresh(row[2], ttl):
            return {"v4": json.loads(row[0]), "v6": json.loads(row[1])}
        return None

    def set_ripe(self, asn: int, v4: list, v6: list):
        self._db.execute(
            "INSERT INTO ripe_cache(asn,v4_json,v6_json,fetched_at) VALUES(?,?,?,?)"
            " ON CONFLICT(asn) DO UPDATE SET v4_json=excluded.v4_json,"
            " v6_json=excluded.v6_json, fetched_at=excluded.fetched_at",
            (asn, json.dumps(v4), json.dumps(v6), self._now()),
        )
        self._db.commit()

    def flush_ripe(self):
        self._db.execute("DELETE FROM ripe_cache")
        self._db.commit()

    # ── AbuseIPDB ─────────────────────────────────────────────

    def get_abuse(self, ip: str, ttl: float = ABUSE_TTL_HOURS) -> Optional[dict]:
        row = self._db.execute(
            "SELECT data_json, fetched_at FROM abuse_cache WHERE ip=?", (ip,)
        ).fetchone()
        if row and self._fresh(row[1], ttl):
            return json.loads(row[0])
        return None

    def set_abuse(self, ip: str, data: dict):
        self._db.execute(
            "INSERT INTO abuse_cache(ip,data_json,fetched_at) VALUES(?,?,?)"
            " ON CONFLICT(ip) DO UPDATE SET data_json=excluded.data_json,"
            " fetched_at=excluded.fetched_at",
            (ip, json.dumps(data), self._now()),
        )
        self._db.commit()

    def flush_abuse(self):
        self._db.execute("DELETE FROM abuse_cache")
        self._db.commit()

    # ── Quota ─────────────────────────────────────────────────

    def quota_used(self) -> int:
        today = date.today().isoformat()
        row = self._db.execute(
            "SELECT used FROM quota_tracker WHERE date=?", (today,)
        ).fetchone()
        return row[0] if row else 0

    def quota_remaining(self, limit: int = ABUSEIPDB_DAILY_LIMIT) -> int:
        return max(0, limit - self.quota_used())

    def quota_add(self, n: int = 1):
        today = date.today().isoformat()
        self._db.execute(
            "INSERT INTO quota_tracker(date,used) VALUES(?,?)"
            " ON CONFLICT(date) DO UPDATE SET used=used+?",
            (today, n, n),
        )
        self._db.commit()

    def quota_reset(self):
        self._db.execute(
            "DELETE FROM quota_tracker WHERE date=?", (date.today().isoformat(),)
        )
        self._db.commit()

    # ── Snapshots ─────────────────────────────────────────────

    def save_snapshot(self, filter_key: str, v4: list, v6: list, asn_count: int):
        self._db.execute(
            "INSERT INTO snapshots(timestamp,filter_key,v4_json,v6_json,asn_count)"
            " VALUES(?,?,?,?,?)",
            (self._now(), filter_key, json.dumps(sorted(v4)),
             json.dumps(sorted(v6)), asn_count),
        )
        self._db.commit()

    def get_latest_snapshot(self, filter_key: str) -> Optional[dict]:
        row = self._db.execute(
            "SELECT timestamp,v4_json,v6_json,asn_count FROM snapshots"
            " WHERE filter_key=? ORDER BY id DESC LIMIT 1",
            (filter_key,),
        ).fetchone()
        if row:
            return {
                "timestamp": row[0],
                "v4":        json.loads(row[1]),
                "v6":        json.loads(row[2]),
                "asn_count": row[3],
            }
        return None

    def list_snapshots(self) -> list:
        rows = self._db.execute(
            "SELECT id,timestamp,filter_key,asn_count FROM snapshots ORDER BY id DESC LIMIT 50"
        ).fetchall()
        return [{"id": r[0], "ts": r[1], "key": r[2], "asns": r[3]} for r in rows]

    def flush_snapshots(self):
        self._db.execute("DELETE FROM snapshots")
        self._db.commit()

    # ── Utility ───────────────────────────────────────────────

    def stats(self) -> dict:
        ripe_count = self._db.execute("SELECT COUNT(*) FROM ripe_cache").fetchone()[0]
        abuse_count = self._db.execute("SELECT COUNT(*) FROM abuse_cache").fetchone()[0]
        snap_count = self._db.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0]
        return {
            "ripe_entries":  ripe_count,
            "abuse_entries": abuse_count,
            "snapshots":     snap_count,
            "quota_used":    self.quota_used(),
            "quota_left":    self.quota_remaining(),
            "db_path":       str(self.path),
            "db_size_kb":    round(self.path.stat().st_size / 1024, 1) if self.path.exists() else 0,
        }

    def flush_all(self):
        self.flush_ripe()
        self.flush_abuse()
        self.flush_snapshots()
        self._db.execute("DELETE FROM quota_tracker")
        self._db.commit()


# ─────────────────────────────────────────────────────────────
# CIDR UTILITIES
# ─────────────────────────────────────────────────────────────

def aggregate_cidrs(cidrs: list) -> list:
    """
    Collapse overlapping / adjacent CIDRs using stdlib collapse_addresses().
    Returns sorted list of minimal covering prefixes.
    """
    v4_nets, v6_nets = [], []
    for c in cidrs:
        try:
            net = ipaddress.ip_network(c, strict=False)
            (v6_nets if net.version == 6 else v4_nets).append(net)
        except ValueError:
            pass
    result = (
        [str(n) for n in ipaddress.collapse_addresses(v4_nets)] +
        [str(n) for n in ipaddress.collapse_addresses(v6_nets)]
    )
    return result


def aggregate_all_results(results: dict) -> dict:
    """
    Global aggregation across all ASNs — collapses inter-ASN overlaps.
    Returns {'v4': [...], 'v6': [...], 'before': n, 'after': n, 'reduction': n, 'pct': n}
    """
    all_v4: list = []
    all_v6: list = []
    for data in results.values():
        all_v4.extend(data["v4"])
        all_v6.extend(data["v6"])

    before  = len(all_v4) + len(all_v6)
    agg_v4  = aggregate_cidrs(all_v4)
    agg_v6  = aggregate_cidrs(all_v6)
    after   = len(agg_v4) + len(agg_v6)
    return {
        "v4":        agg_v4,
        "v6":        agg_v6,
        "before":    before,
        "after":     after,
        "reduction": before - after,
        "pct":       round((1 - after / before) * 100, 1) if before else 0.0,
    }


def find_ip_in_results(ip_str: str, results: dict) -> list:
    """
    Check if `ip_str` is contained in any CIDR across all ASNs.
    Returns list of match dicts: {asn, cidr, name, country, region}.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return []
    matches = []
    for asn, data in results.items():
        cidrs = data["v4"] if ip.version == 4 else data["v6"]
        for cidr in cidrs:
            try:
                if ip in ipaddress.ip_network(cidr, strict=False):
                    meta = ASN_DB.get(asn, {})
                    matches.append({
                        "asn":     asn,
                        "cidr":    cidr,
                        "name":    meta.get("name", "Unknown"),
                        "country": meta.get("country", "?"),
                        "region":  meta.get("region", "?"),
                    })
            except ValueError:
                pass
    return matches


def compute_diff(old_v4: list, old_v6: list, new_v4: list, new_v6: list) -> dict:
    ov4, nv4 = set(old_v4), set(new_v4)
    ov6, nv6 = set(old_v6), set(new_v6)
    return {
        "v4_added":   sorted(nv4 - ov4),
        "v4_removed": sorted(ov4 - nv4),
        "v6_added":   sorted(nv6 - ov6),
        "v6_removed": sorted(ov6 - nv6),
    }


def make_filter_key(asns, region, country, no_mobile) -> str:
    """Stable short key identifying a filter combination, used for snapshot comparison."""
    parts = [
        "asns=" + (",".join(str(a) for a in sorted(asns)) if asns else "all"),
        "reg="  + (",".join(sorted(region))  if region  else "all"),
        "cc="   + (",".join(sorted(country)) if country else "all"),
        "nm="   + str(no_mobile),
    ]
    raw = "|".join(parts)
    return hashlib.sha1(raw.encode()).hexdigest()[:10]


def load_custom_asns(add_asn_args: list, asn_file: Optional[str]) -> dict:
    """
    Parse --add-asn entries and --asn-file, merging into ASN_DB.
    --add-asn format:  "12345:Name:CC:Region"  or  "12345:Name:CC:Region:mobile"
    --asn-file format: {"12345": {"name":..., "country":..., "region":..., "mobile":...}, ...}
    Returns dict of new ASN entries added (for display).
    """
    added = {}

    for entry in (add_asn_args or []):
        parts = entry.split(":", 4)
        if len(parts) < 4:
            console.print(f"  [yellow]⚠ Skipping malformed --add-asn: {entry!r}  (need ASN:Name:CC:Region)[/yellow]")
            continue
        try:
            asn = int(parts[0])
        except ValueError:
            console.print(f"  [yellow]⚠ Non-integer ASN in --add-asn: {parts[0]!r}[/yellow]")
            continue
        mobile = parts[4].lower() in ("true", "1", "yes") if len(parts) > 4 else False
        record = {"name": parts[1], "country": parts[2].upper(), "region": parts[3].upper(), "mobile": mobile}
        ASN_DB[asn] = record
        added[asn]  = record

    if asn_file:
        try:
            raw = json.loads(Path(asn_file).read_text())
            for asn_str, rec in raw.items():
                try:
                    asn = int(asn_str)
                except ValueError:
                    continue
                ASN_DB[asn] = rec
                added[asn]  = rec
        except Exception as exc:
            console.print(f"  [red]✗ Failed to load --asn-file {asn_file}: {exc}[/red]")

    return added


# ─────────────────────────────────────────────────────────────
# RIPE FETCH (cache-aware)
# ─────────────────────────────────────────────────────────────

def fetch_asn_prefixes(
    asn: int,
    retries: int = 3,
    cache: Optional[CacheDB] = None,
    ttl: float = RIPE_TTL_HOURS,
) -> dict:
    if cache:
        hit = cache.get_ripe(asn, ttl)
        if hit:
            return {
                "asn": asn, "v4": hit["v4"], "v6": hit["v6"],
                "total": len(hit["v4"]) + len(hit["v6"]),
                "error": None, "from_cache": True,
            }

    url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
    for attempt in range(retries):
        try:
            r = requests.get(url, timeout=15)
            r.raise_for_status()
            prefixes = r.json().get("data", {}).get("prefixes", [])
            v4 = [p["prefix"] for p in prefixes if ":" not in p["prefix"]]
            v6 = [p["prefix"] for p in prefixes if ":" in p["prefix"]]
            if cache:
                cache.set_ripe(asn, v4, v6)
            return {"asn": asn, "v4": v4, "v6": v6, "total": len(prefixes),
                    "error": None, "from_cache": False}
        except Exception as exc:
            if attempt < retries - 1:
                time.sleep(1.5 ** attempt)
            else:
                return {"asn": asn, "v4": [], "v6": [], "total": 0,
                        "error": str(exc), "from_cache": False}


# ─────────────────────────────────────────────────────────────
# ABUSEIPDB — SAMPLING
# ─────────────────────────────────────────────────────────────

def sample_ips_from_cidrs(cidrs: list, n: int) -> list:
    """
    Pick up to n host IPs from a CIDR list.
    Weighted toward first/last hosts (active gateway/endpoint addresses)
    and the block midpoint, plus random fill for statistical breadth.
    """
    if not cidrs or n <= 0:
        return []

    sampled: set = set()
    pool = cidrs.copy()
    random.shuffle(pool)

    for cidr in pool:
        if len(sampled) >= n:
            break
        try:
            net   = ipaddress.ip_network(cidr, strict=False)
            hosts = list(net.hosts()) or [net.network_address]
            size  = len(hosts)

            candidates = [str(hosts[0])]
            if size > 1:
                candidates.append(str(hosts[-1]))
            if size > 3:
                candidates.append(str(hosts[size // 2]))
            if size > 10:
                candidates.append(str(hosts[random.randint(1, size - 2)]))

            for ip in candidates:
                if ip not in sampled:
                    sampled.add(ip)
                if len(sampled) >= n:
                    break
        except ValueError:
            continue

    return list(sampled)[:n]


# ─────────────────────────────────────────────────────────────
# ABUSEIPDB — CLIENT
# ─────────────────────────────────────────────────────────────

ABUSE_RISK_BANDS = [
    (0,  10,  "bright_green", "Clean"),
    (10, 25,  "green",        "Low"),
    (25, 50,  "yellow",       "Medium"),
    (50, 75,  "dark_orange",  "High"),
    (75, 101, "bright_red",   "Critical"),
]


def _abuse_color_label(score: float) -> tuple:
    for lo, hi, color, label in ABUSE_RISK_BANDS:
        if lo <= score < hi:
            return color, label
    return "bright_red", "Critical"


def _abuse_bar(score: float, width: int = 10) -> str:
    filled = round((score / 100) * width)
    color, _ = _abuse_color_label(score)
    return f"[{color}]{'█' * filled}{'░' * (width - filled)}[/{color}]"


class AbuseIPDBClient:
    """
    Thin wrapper around AbuseIPDB v2 /check endpoint.
    Respects rate limits, integrates with CacheDB for result caching,
    and tracks daily quota consumption.
    """
    BASE = "https://api.abuseipdb.com/api/v2"

    def __init__(
        self,
        api_key: str,
        max_age: int = 30,
        cache: Optional[CacheDB] = None,
        cache_ttl: float = ABUSE_TTL_HOURS,
        daily_limit: int = ABUSEIPDB_DAILY_LIMIT,
    ):
        self.key        = api_key
        self.max_age    = max_age
        self.cache      = cache
        self.cache_ttl  = cache_ttl
        self.daily_limit = daily_limit
        self._last      = 0.0
        self._gap       = 0.25  # seconds between requests

    def _throttle(self):
        elapsed = time.monotonic() - self._last
        if elapsed < self._gap:
            time.sleep(self._gap - elapsed)
        self._last = time.monotonic()

    def check_ip(self, ip: str, retries: int = 3) -> Optional[dict]:
        # Cache hit — no API call, no quota consumed
        if self.cache:
            cached = self.cache.get_abuse(ip, self.cache_ttl)
            if cached is not None:
                return cached

        self._throttle()
        headers = {"Key": self.key, "Accept": "application/json"}
        params  = {"ipAddress": ip, "maxAgeInDays": self.max_age, "verbose": ""}

        for attempt in range(retries):
            try:
                r = requests.get(f"{self.BASE}/check", headers=headers,
                                 params=params, timeout=10)
                if r.status_code == 429:
                    wait = 60 * (attempt + 1)
                    console.print(f"  [yellow]⚠[/yellow] Rate-limited — waiting {wait}s…")
                    time.sleep(wait)
                    continue
                if r.status_code == 401:
                    console.print("[red]✗ AbuseIPDB key invalid or missing.[/red]")
                    return None
                r.raise_for_status()
                data = r.json().get("data")
                if data:
                    if self.cache:
                        self.cache.set_abuse(ip, data)
                        self.cache.quota_add(1)
                return data
            except requests.RequestException:
                if attempt < retries - 1:
                    time.sleep(2 ** attempt)
        return None


# ─────────────────────────────────────────────────────────────
# ABUSEIPDB — AUDIT
# ─────────────────────────────────────────────────────────────

def audit_asns(
    results: dict,
    client: AbuseIPDBClient,
    samples_per_asn: int = 5,
) -> dict:
    """
    Sample IPs from each ASN, query AbuseIPDB, aggregate per-ASN stats.
    Returns {asn: {samples, avg_score, max_score, flagged_count, risk_label}}.
    """
    console.print()
    console.print(Rule("[bold]AbuseIPDB Reputation Audit[/bold]", style="bright_red"))
    console.print()

    # Quota report
    if client.cache:
        used      = client.cache.quota_used()
        remaining = client.cache.quota_remaining(client.daily_limit)
        console.print(
            f"  [dim]Daily quota:[/dim]  "
            f"[yellow]{used}[/yellow] used  "
            f"[green]{remaining}[/green] remaining  "
            f"[dim](limit {client.daily_limit})[/dim]\n"
        )

    # Build IP → ASN map, identify which IPs are already cached
    asn_ips: dict = {}
    fresh_needed: list = []

    for asn, data in results.items():
        ips = sample_ips_from_cidrs(data["v4"], samples_per_asn)
        asn_ips[asn] = ips
        for ip in ips:
            if not (client.cache and client.cache.get_abuse(ip, client.cache_ttl)):
                fresh_needed.append(ip)

    cached_ct = sum(len(v) for v in asn_ips.values()) - len(fresh_needed)
    console.print(
        f"  Sampling [cyan]{samples_per_asn}[/cyan] IPs × "
        f"[cyan]{len(results)}[/cyan] ASNs = "
        f"[bold cyan]{sum(len(v) for v in asn_ips.values())}[/bold cyan] total  "
        f"([green]{cached_ct} cached[/green]  "
        f"[yellow]{len(fresh_needed)} fresh calls[/yellow])\n"
    )

    # Quota gate
    if client.cache and len(fresh_needed) > client.cache.quota_remaining(client.daily_limit):
        console.print(Panel(
            f"[red]Batch needs [bold]{len(fresh_needed)}[/bold] fresh calls "
            f"but only [bold]{client.cache.quota_remaining(client.daily_limit)}[/bold] "
            f"quota remain today.\n\n"
            f"  • Reduce [bold]--abuse-samples[/bold] (currently {samples_per_asn})\n"
            f"  • Increase [bold]--abuse-cache-ttl[/bold] to reuse more results\n"
            f"  • Run [bold]--show-quota[/bold] to inspect usage[/red]",
            title="[bold red]⚠  Quota Exceeded[/bold red]",
            border_style="red",
        ))
        if not Confirm.ask("Proceed anyway?", default=False):
            return {}
        console.print()
    elif len(fresh_needed) > 800:
        console.print(Panel(
            f"[yellow]⚠  [bold]{len(fresh_needed)}[/bold] fresh API calls. Free plan = 1 000/day.[/yellow]",
            border_style="yellow",
        ))
        if not Confirm.ask("Continue?", default=True):
            return {}
        console.print()

    # Pre-load cached results
    ip_data: dict = {}
    if client.cache:
        for ip in sum(asn_ips.values(), []):
            d = client.cache.get_abuse(ip, client.cache_ttl)
            if d:
                ip_data[ip] = d

    # Fetch fresh IPs with progress bar
    if fresh_needed:
        with Progress(
            SpinnerColumn(style="bright_red"),
            TextColumn("[bold]{task.description}"),
            BarColumn(bar_width=38, style="bright_red", complete_style="green"),
            TaskProgressColumn(),
            TextColumn("[dim]{task.fields[status]}[/dim]"),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        ) as progress:
            task = progress.add_task(
                "[bright_red]Querying AbuseIPDB[/bright_red]",
                total=len(fresh_needed),
                status="starting…",
            )
            for asn, ips in asn_ips.items():
                meta = ASN_DB.get(asn, {})
                progress.update(task, status=f"AS{asn} {meta.get('name','')[:22]}")
                for ip in ips:
                    if ip in ip_data:
                        continue
                    d = client.check_ip(ip)
                    if d:
                        ip_data[ip] = d
                    progress.update(task, advance=1)

    console.print()

    # Aggregate per ASN
    audit: dict = {}
    for asn, ips in asn_ips.items():
        samples = []
        for ip in ips:
            d = ip_data.get(ip)
            if not d:
                continue
            samples.append({
                "ip":         ip,
                "score":      d.get("abuseConfidenceScore", 0),
                "reports":    d.get("totalReports", 0),
                "usage_type": d.get("usageType", "?"),
                "domain":     d.get("domain", "?"),
                "isp":        d.get("isp", "?"),
            })

        if not samples:
            audit[asn] = {"samples": [], "avg_score": 0.0, "max_score": 0,
                          "flagged_count": 0, "risk_label": "No data"}
            continue

        scores = [s["score"] for s in samples]
        avg    = sum(scores) / len(scores)
        _, lbl = _abuse_color_label(avg)
        audit[asn] = {
            "samples":       samples,
            "avg_score":     round(avg, 1),
            "max_score":     max(scores),
            "flagged_count": sum(1 for s in scores if s > 0),
            "risk_label":    lbl,
        }

    return audit


# ─────────────────────────────────────────────────────────────
# ABUSEIPDB — DISPLAY
# ─────────────────────────────────────────────────────────────

def print_abuse_results(audit: dict, threshold: int = 25):
    if not audit:
        console.print("[dim]No abuse audit data.[/dim]")
        return

    table = Table(
        title="[bold]AbuseIPDB Reputation Overview[/bold]",
        box=box.ROUNDED, border_style="bright_red", show_footer=True,
    )
    table.add_column("ASN",      style="dim cyan",  justify="right", footer="TOTAL")
    table.add_column("Name",     style="white",     max_width=26)
    table.add_column("Country",  justify="center")
    table.add_column("Samples",  justify="right",   style="dim")
    table.add_column("Avg",      justify="center")
    table.add_column("Risk Bar", no_wrap=True)
    table.add_column("Max",      justify="right")
    table.add_column("Flagged",  justify="right",
                     footer=str(sum(a["flagged_count"] for a in audit.values())))
    table.add_column("Risk",     justify="center")

    flagged_asns = []
    for asn in sorted(audit.keys()):
        a    = audit[asn]
        meta = ASN_DB.get(asn, {"name": "?", "country": "?"})
        flag = FLAG_MAP.get(meta.get("country", "?"), "🏳️")
        avg  = a["avg_score"]
        col, lbl = _abuse_color_label(avg)
        if avg >= threshold:
            flagged_asns.append(asn)

        fc_str = f"[bright_red]{a['flagged_count']}[/bright_red]" if a["flagged_count"] else "[dim]0[/dim]"
        table.add_row(
            str(asn), meta.get("name", "?"),
            f"{flag} {meta.get('country','?')}",
            str(len(a["samples"])),
            f"[{col}]{avg:.1f}[/{col}]",
            _abuse_bar(avg),
            f"[{col}]{a['max_score']}[/{col}]",
            fc_str,
            f"[{col}]{lbl}[/{col}]",
            style="on grey11" if avg >= threshold else "",
        )
    console.print(table)
    console.print()

    # Drill-down for high-risk
    high = [a for a in audit if audit[a]["avg_score"] >= threshold]
    if high:
        console.print(Rule(
            f"[bold bright_red]Sample Detail — ASNs above threshold ({threshold})[/bold bright_red]",
            style="bright_red",
        ))
        console.print()
        for asn in sorted(high):
            a    = audit[asn]
            meta = ASN_DB.get(asn, {"name": "?", "country": "?"})
            flag = FLAG_MAP.get(meta.get("country", "?"), "🏳️")
            col, lbl = _abuse_color_label(a["avg_score"])

            dt = Table(
                title=f"[bold {col}]AS{asn}  {meta.get('name','?')} {flag}  avg={a['avg_score']}  [{lbl}][/bold {col}]",
                box=box.SIMPLE_HEAVY, border_style=col,
            )
            dt.add_column("IP",         style="cyan", min_width=16)
            dt.add_column("Score",      justify="center")
            dt.add_column("Bar",        no_wrap=True)
            dt.add_column("Reports",    justify="right", style="dim")
            dt.add_column("Usage Type", style="dim",     max_width=22)
            dt.add_column("Domain",     style="dim",     max_width=24)
            dt.add_column("ISP",        style="dim",     max_width=26)
            for s in sorted(a["samples"], key=lambda x: x["score"], reverse=True):
                sc, _ = _abuse_color_label(s["score"])
                dt.add_row(
                    s["ip"],
                    f"[{sc}]{s['score']}[/{sc}]",
                    _abuse_bar(s["score"], 8),
                    str(s["reports"]),
                    s.get("usage_type", "?"),
                    s.get("domain", "?"),
                    s.get("isp", "?"),
                )
            console.print(dt)
            console.print()

    # Summary panel
    if flagged_asns:
        names = ", ".join(
            f"AS{a} ({ASN_DB.get(a,{}).get('name','?')})" for a in flagged_asns
        )
        console.print(Panel(
            f"[bright_red][bold]{len(flagged_asns)} ASN(s)[/bold] exceeded threshold "
            f"[bold]{threshold}[/bold]:[/bright_red]\n[dim]{names}[/dim]\n\n"
            f"[yellow]Pass [bold]--abuse-filter[/bold] to exclude them from export.[/yellow]",
            title="[bold bright_red]⚠  High-Risk ASNs[/bold bright_red]",
            border_style="bright_red",
        ))
    else:
        console.print(Panel(
            f"[bright_green]All sampled ASNs scored below threshold [bold]{threshold}[/bold].[/bright_green]",
            title="[bold bright_green]✓  Reputation Check Passed[/bold bright_green]",
            border_style="bright_green",
        ))
    console.print()


def print_abuse_panels(audit: dict, threshold: int):
    if not audit:
        return
    avgs    = [a["avg_score"] for a in audit.values() if a["samples"]]
    flagged = sum(1 for a in audit.values() if a["avg_score"] >= threshold)
    total_f = sum(a["flagged_count"] for a in audit.values())
    overall = sum(avgs) / len(avgs) if avgs else 0.0
    oc, _   = _abuse_color_label(overall)
    console.print(Columns([
        Panel(f"[bold {oc}]{overall:.1f}[/bold {oc}]\n[dim]Avg abuse score[/dim]", border_style=oc),
        Panel(f"[bold bright_red]{flagged}[/bold bright_red]\n[dim]ASNs above threshold[/dim]", border_style="bright_red"),
        Panel(f"[bold yellow]{total_f}[/bold yellow]\n[dim]IPs with reports[/dim]", border_style="yellow"),
        Panel(f"[bold cyan]{sum(len(a['samples']) for a in audit.values())}[/bold cyan]\n[dim]IPs sampled[/dim]", border_style="cyan"),
    ], equal=True, expand=True))
    console.print()


def export_abuse_report(audit: dict, threshold: int) -> str:
    out = {
        "generated":    datetime.utcnow().isoformat() + "Z",
        "threshold":    threshold,
        "flagged_asns": [a for a in audit if audit[a]["avg_score"] >= threshold],
        "asns": {},
    }
    for asn, a in sorted(audit.items()):
        meta = ASN_DB.get(asn, {})
        out["asns"][f"AS{asn}"] = {
            "name":          meta.get("name", "?"),
            "country":       meta.get("country", "?"),
            "avg_score":     a["avg_score"],
            "max_score":     a["max_score"],
            "flagged_count": a["flagged_count"],
            "risk_label":    a["risk_label"],
            "samples":       a["samples"],
        }
    return json.dumps(out, indent=2)


# ─────────────────────────────────────────────────────────────
# DIFF ENGINE
# ─────────────────────────────────────────────────────────────

def print_diff(diff: dict, old_ts: str, new_ts: str):
    total = sum(len(v) for v in diff.values())
    console.print(Rule("[bold]Diff vs Previous Snapshot[/bold]", style="bright_yellow"))
    console.print(f"  [dim]Previous:[/dim] {old_ts}   [dim]Current:[/dim] {new_ts}\n")

    if total == 0:
        console.print("  [green]✓ No changes detected — CIDR set is stable.[/green]\n")
        return

    console.print(Columns([
        Panel(f"[bold green]+{len(diff['v4_added'])}[/bold green]\n[dim]IPv4 added[/dim]",    border_style="green"),
        Panel(f"[bold red]-{len(diff['v4_removed'])}[/bold red]\n[dim]IPv4 removed[/dim]",   border_style="red"),
        Panel(f"[bold green]+{len(diff['v6_added'])}[/bold green]\n[dim]IPv6 added[/dim]",   border_style="green"),
        Panel(f"[bold red]-{len(diff['v6_removed'])}[/bold red]\n[dim]IPv6 removed[/dim]",  border_style="red"),
    ], equal=True, expand=True))
    console.print()

    MAX = 30
    for key, symbol, color, label in [
        ("v4_added",   "+", "green", "IPv4 Added"),
        ("v4_removed", "-", "red",   "IPv4 Removed"),
        ("v6_added",   "+", "green", "IPv6 Added"),
        ("v6_removed", "-", "red",   "IPv6 Removed"),
    ]:
        items = diff[key]
        if not items:
            continue
        console.print(f"  [bold {color}]{symbol} {label}[/bold {color}]  ({len(items)} CIDRs)")
        for c in items[:MAX]:
            console.print(f"    [{color}]{symbol}[/{color}] {c}")
        if len(items) > MAX:
            console.print(f"    [dim]… and {len(items) - MAX} more[/dim]")
        console.print()


def export_diff_json(diff: dict, old_ts: str, new_ts: str) -> str:
    return json.dumps({
        "old_snapshot":     old_ts,
        "new_snapshot":     new_ts,
        "v4_added_count":   len(diff["v4_added"]),
        "v4_removed_count": len(diff["v4_removed"]),
        "v6_added_count":   len(diff["v6_added"]),
        "v6_removed_count": len(diff["v6_removed"]),
        **diff,
    }, indent=2)


# ─────────────────────────────────────────────────────────────
# WEBHOOK
# ─────────────────────────────────────────────────────────────

def send_webhook(url: str, payload: dict) -> bool:
    try:
        r = requests.post(url, json=payload, timeout=10,
                          headers={"Content-Type": "application/json"})
        r.raise_for_status()
        console.print(f"  [green]✓[/green] Webhook delivered → [dim]{url}[/dim]  [dim]({r.status_code})[/dim]")
        return True
    except Exception as exc:
        console.print(f"  [yellow]⚠ Webhook failed:[/yellow] {exc}")
        return False


def build_webhook_payload(
    diff: Optional[dict],
    audit: Optional[dict],
    threshold: int,
    run_ts: str,
    asn_count: int,
) -> dict:
    flagged = [f"AS{a}" for a in (audit or {}) if audit[a]["avg_score"] >= threshold] if audit else []
    payload: dict = {
        "source":        "cidr_pull",
        "timestamp":     run_ts,
        "asns_fetched":  asn_count,
        "flagged_asns":  flagged,
        "has_changes":   bool(diff and any(len(v) for v in diff.values())),
    }
    if diff:
        payload["diff"] = {k: len(v) for k, v in diff.items()}
    if audit:
        avgs = [a["avg_score"] for a in audit.values() if a["samples"]]
        payload["abuse_avg_score"] = round(sum(avgs) / len(avgs), 1) if avgs else 0.0
    return payload


# ─────────────────────────────────────────────────────────────
# EXPORT FORMATTERS
# ─────────────────────────────────────────────────────────────

def export_json_full(results: dict) -> str:
    out = {
        "generated": datetime.utcnow().isoformat() + "Z",
        "total_asns": len(results),
        "total_v4": sum(len(d["v4"]) for d in results.values()),
        "total_v6": sum(len(d["v6"]) for d in results.values()),
        "asns": {},
    }
    for asn, data in results.items():
        meta = ASN_DB.get(asn, {})
        out["asns"][f"AS{asn}"] = {
            "name":    meta.get("name", "?"),
            "country": meta.get("country", "?"),
            "region":  meta.get("region", "?"),
            "mobile":  meta.get("mobile", False),
            "v4":      sorted(data["v4"]),
            "v6":      sorted(data["v6"]),
        }
    return json.dumps(out, indent=2)


def export_flat(results: dict, version: str = "both") -> str:
    lines: list = []
    for data in results.values():
        if version in ("both", "v4"):
            lines.extend(data["v4"])
        if version in ("both", "v6"):
            lines.extend(data["v6"])
    return "\n".join(sorted(set(lines)))


def export_cloudflare_expression(results: dict) -> str:
    chunks, chunk = [], []
    for asn in sorted(results.keys()):
        chunk.append(str(asn))
        if len(chunk) == 20:
            chunks.append(chunk); chunk = []
    if chunk:
        chunks.append(chunk)
    lines = ["(ip.geoip.asnum in {"]
    for c in chunks:
        lines.append("  " + " ".join(c))
    lines.append("}) and (not cf.client.bot)")
    return "\n".join(lines)


def export_cloudflare_ip_list(results: dict, version: str = "both") -> str:
    lines: list = []
    for asn, data in sorted(results.items()):
        meta = ASN_DB.get(asn, {})
        lines.append(f"# AS{asn} — {meta.get('name','?')} ({meta.get('country','?')})")
        if version in ("both", "v4"):
            lines.extend(sorted(data["v4"]))
        if version in ("both", "v6"):
            lines.extend(sorted(data["v6"]))
        lines.append("")
    return "\n".join(lines)


def export_ipset(results: dict) -> str:
    v4: set = set(); v6: set = set()
    for d in results.values():
        v4.update(d["v4"]); v6.update(d["v6"])
    lines = [
        "#!/bin/bash",
        f"# ipset whitelist — generated {datetime.utcnow().isoformat()}Z",
        "",
        "ipset destroy whitelist_v4 2>/dev/null",
        "ipset destroy whitelist_v6 2>/dev/null",
        "ipset create whitelist_v4 hash:net family inet  hashsize 65536 maxelem 524288",
        "ipset create whitelist_v6 hash:net family inet6 hashsize 65536 maxelem 524288",
        "",
    ]
    lines += [f"ipset add whitelist_v4 {c}" for c in sorted(v4)]
    lines += [f"ipset add whitelist_v6 {c}" for c in sorted(v6)]
    lines += [
        "",
        "iptables  -I INPUT -m set ! --match-set whitelist_v4 src -j DROP",
        "ip6tables -I INPUT -m set ! --match-set whitelist_v6 src -j DROP",
    ]
    return "\n".join(lines)


def export_nftables(results: dict) -> str:
    v4: set = set(); v6: set = set()
    for d in results.values():
        v4.update(d["v4"]); v6.update(d["v6"])
    v4s = ",\n      ".join(sorted(v4))
    v6s = ",\n      ".join(sorted(v6))
    return f"""table inet filter {{
  set whitelist_v4 {{
    type ipv4_addr; flags interval
    elements = {{ {v4s} }}
  }}
  set whitelist_v6 {{
    type ipv6_addr; flags interval
    elements = {{ {v6s} }}
  }}
  chain input {{
    type filter hook input priority 0;
    ip  saddr @whitelist_v4 accept
    ip6 saddr @whitelist_v6 accept
    drop
  }}
}}
"""


def export_nginx_geo(results: dict) -> str:
    ts = datetime.utcnow().isoformat() + "Z"
    lines = [
        f"# nginx geo block — Residential ISP Whitelist",
        f"# Generated: {ts}",
        "# Place inside http { } block.",
        "# Usage in server/location:  if ($residential_ip = 0) { return 403; }",
        "",
        "geo $residential_ip {",
        "    default 0;",
        "",
    ]
    for asn, data in sorted(results.items()):
        meta = ASN_DB.get(asn, {})
        v4   = sorted(data["v4"])
        if not v4:
            continue
        lines.append(f"    # AS{asn} — {meta.get('name','?')} ({meta.get('country','?')})")
        for c in v4:
            lines.append(f"    {c} 1;")
        lines.append("")
    lines.append("}")
    return "\n".join(lines)


def export_haproxy(results: dict) -> str:
    ts = datetime.utcnow().isoformat() + "Z"
    lines = [
        f"# HAProxy source ACL — Residential ISP Whitelist",
        f"# Generated: {ts}",
        "# In your frontend section use:",
        "#   acl residential src -f /etc/haproxy/residential.txt",
        "#   use_backend app if residential",
        "",
    ]
    for asn, data in sorted(results.items()):
        meta = ASN_DB.get(asn, {})
        v4   = sorted(data["v4"])
        if not v4:
            continue
        lines.append(f"# AS{asn} — {meta.get('name','?')} ({meta.get('country','?')})")
        lines.extend(v4)
        lines.append("")
    return "\n".join(lines)


def export_aws_sg(results: dict, version: str = "both") -> str:
    ip_ranges: list = []; ipv6_ranges: list = []
    for asn, data in sorted(results.items()):
        meta = ASN_DB.get(asn, {})
        desc = f"AS{asn} {meta.get('name','?')} {meta.get('country','?')}"[:255]
        if version in ("both", "v4"):
            for c in sorted(data["v4"]):
                ip_ranges.append({"CidrIp": c, "Description": desc})
        if version in ("both", "v6"):
            for c in sorted(data["v6"]):
                ipv6_ranges.append({"CidrIpv6": c, "Description": desc})
    return json.dumps({
        "_note":         "Replace GroupId before running aws ec2 authorize-security-group-ingress",
        "GroupId":       "sg-REPLACE_ME",
        "IpPermissions": [{
            "IpProtocol": "-1",
            "IpRanges":   ip_ranges,
            "Ipv6Ranges": ipv6_ranges,
        }],
    }, indent=2)


def export_ufw(results: dict) -> str:
    ts = datetime.utcnow().isoformat() + "Z"
    lines = [
        "#!/bin/bash",
        f"# ufw rules — Residential ISP Whitelist  ({ts})",
        "# WARNING: Review carefully before running — resets ufw with default deny.",
        "",
        "ufw --force reset",
        "ufw default deny incoming",
        "ufw default allow outgoing",
        "ufw allow ssh",
        "",
    ]
    for asn, data in sorted(results.items()):
        meta    = ASN_DB.get(asn, {})
        comment = f"AS{asn} {meta.get('name','?')} {meta.get('country','?')}"
        v4      = sorted(data["v4"])
        if not v4:
            continue
        lines.append(f"# {comment}")
        for c in v4:
            lines.append(f'ufw allow from {c} comment "{comment}"')
        lines.append("")
    lines += ["ufw --force enable", "ufw status verbose"]
    return "\n".join(lines)


def export_caddy(results: dict) -> str:
    all_v4 = sorted({c for d in results.values() for c in d["v4"]})
    ts = datetime.utcnow().isoformat() + "Z"
    lines = [
        f"# Caddy remote_ip matcher — Residential ISP Whitelist  ({ts})",
        "# Import in your Caddyfile:  import residential_ips",
        "# Then use:  handle @residential_ips { ... }",
        "",
        "@residential_ips {",
        "    remote_ip",
    ]
    for i in range(0, len(all_v4), 6):
        lines.append("        " + " ".join(all_v4[i:i+6]))
    lines.append("}")
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────
# RICH UI HELPERS
# ─────────────────────────────────────────────────────────────

def print_banner():
    console.print()
    console.print(Panel.fit(
        "[bold bright_cyan]  ██████╗██╗██████╗ ██████╗     ██████╗ ██╗   ██╗██╗     ██╗     \n"
        " ██╔════╝██║██╔══██╗██╔══██╗    ██╔══██╗██║   ██║██║     ██║     \n"
        " ██║     ██║██║  ██║██████╔╝    ██████╔╝██║   ██║██║     ██║     \n"
        " ██║     ██║██║  ██║██╔══██╗    ██╔═══╝ ██║   ██║██║     ██║     \n"
        " ╚██████╗██║██████╔╝██║  ██║    ██║     ╚██████╔╝███████╗███████╗\n"
        "  ╚═════╝╚═╝╚═════╝ ╚═╝  ╚═╝    ╚═╝      ╚═════╝ ╚══════╝╚══════╝[/bold bright_cyan]\n"
        "[dim]  Residential ISP Whitelist v2.0 — ASN → CIDR · Cache · AbuseIPDB · Diff[/dim]",
        border_style="bright_cyan",
    ))
    console.print()


def print_asn_summary(asns: list):
    by_region: dict = defaultdict(list)
    mobile_ct = 0
    for asn in asns:
        meta = ASN_DB.get(asn, {"name": "?", "country": "?", "region": "?", "mobile": False})
        by_region[meta["region"]].append((asn, meta))
        if meta.get("mobile"):
            mobile_ct += 1

    tree = Tree(
        f"[bold]Fetch Plan[/bold] — [cyan]{len(asns)}[/cyan] ASNs "
        f"across [cyan]{len(by_region)}[/cyan] regions"
    )
    for region, entries in sorted(by_region.items()):
        col    = REGION_COLORS.get(region, "white")
        branch = tree.add(
            f"[{col}]{REGION_NAMES.get(region, region)}[/{col}]"
            f" [dim]({len(entries)} ASNs)[/dim]"
        )
        for asn, meta in sorted(entries, key=lambda x: x[1]["country"]):
            flag = FLAG_MAP.get(meta["country"], "🏳️")
            mob  = " [red][MOB][/red]" if meta.get("mobile") else ""
            branch.add(f"{flag}  [dim]AS{asn}[/dim]  {meta['name']}{mob}")

    console.print(tree)
    console.print()
    if mobile_ct:
        console.print(f"  [yellow]⚠[/yellow]  [dim]{mobile_ct} mobile ASNs included (--no-mobile to exclude)[/dim]")
        console.print()


def print_results_table(results: dict, errors: list, cache_hits: int = 0):
    table = Table(
        title="[bold]Fetch Results[/bold]",
        box=box.ROUNDED, border_style="bright_cyan", show_footer=True,
    )
    table.add_column("ASN",    style="dim cyan",  justify="right", footer="TOTAL")
    table.add_column("Name",   style="white",     max_width=28)
    table.add_column("Cntry",  justify="center")
    table.add_column("Region", justify="center")
    table.add_column("Mob",    justify="center")
    table.add_column("IPv4",   style="green",     justify="right",
                     footer=str(sum(len(d["v4"]) for d in results.values())))
    table.add_column("IPv6",   style="blue",      justify="right",
                     footer=str(sum(len(d["v6"]) for d in results.values())))
    table.add_column("Src",    justify="center")
    table.add_column("OK",     justify="center")

    for asn in sorted(results.keys()):
        data = results[asn]
        meta = ASN_DB.get(asn, {"name": "?", "country": "?", "region": "?", "mobile": False})
        flag = FLAG_MAP.get(meta.get("country", "?"), "🏳️")
        col  = REGION_COLORS.get(meta.get("region", "?"), "white")
        src  = "[dim]cache[/dim]" if data.get("from_cache") else "[cyan]live[/cyan]"
        ok   = "[green]✓[/green]" if not data.get("error") else "[red]✗[/red]"
        mob  = "[red]●[/red]" if meta.get("mobile") else "[dim]○[/dim]"
        table.add_row(
            str(asn), meta.get("name", "?"),
            f"{flag} {meta.get('country','?')}",
            f"[{col}]{meta.get('region','?')}[/{col}]",
            mob,
            str(len(data["v4"])), str(len(data["v6"])),
            src, ok,
        )

    console.print(table)
    if cache_hits:
        console.print(f"  [dim]{cache_hits} ASNs served from cache.[/dim]")
    if errors:
        console.print(f"  [red]✗ {len(errors)} failed:[/red] " + ", ".join(f"AS{e}" for e in errors))
    console.print()


def print_stats(results: dict):
    v4: set = set(); v6: set = set()
    by_region: dict = defaultdict(lambda: {"v4": 0, "v6": 0, "asns": 0})
    for asn, data in results.items():
        v4.update(data["v4"]); v6.update(data["v6"])
        r = ASN_DB.get(asn, {}).get("region", "?")
        by_region[r]["v4"] += len(data["v4"])
        by_region[r]["v6"] += len(data["v6"])
        by_region[r]["asns"] += 1

    console.print(Columns([
        Panel(f"[bold bright_cyan]{len(results)}[/bold bright_cyan]\n[dim]ASNs[/dim]",    border_style="cyan"),
        Panel(f"[bold green]{len(v4):,}[/bold green]\n[dim]IPv4 CIDRs[/dim]",              border_style="green"),
        Panel(f"[bold blue]{len(v6):,}[/bold blue]\n[dim]IPv6 CIDRs[/dim]",                border_style="blue"),
        Panel(f"[bold yellow]{len(v4)+len(v6):,}[/bold yellow]\n[dim]Total prefixes[/dim]",border_style="yellow"),
    ], equal=True, expand=True))
    console.print()

    t = Table(box=box.SIMPLE, border_style="dim", title="[dim]By Region[/dim]")
    t.add_column("Region"); t.add_column("ASNs", justify="right", style="cyan")
    t.add_column("IPv4",   justify="right", style="green")
    t.add_column("IPv6",   justify="right", style="blue")
    for region, s in sorted(by_region.items()):
        col = REGION_COLORS.get(region, "white")
        t.add_row(f"[{col}]{REGION_NAMES.get(region, region)}[/{col}]",
                  str(s["asns"]), str(s["v4"]), str(s["v6"]))
    console.print(t)
    console.print()


def print_aggregate_stats(agg: dict):
    col = "green" if agg["reduction"] > 0 else "dim"
    console.print(Panel(
        f"[dim]Before aggregation:[/dim] [white]{agg['before']:,}[/white] prefixes\n"
        f"[dim]After aggregation: [/dim] [{col}]{agg['after']:,}[/{col}] prefixes\n"
        f"[dim]Reduction:         [/dim] [{col}]{agg['reduction']:,} ({agg['pct']}%)[/{col}]",
        title="[bold green]CIDR Aggregation[/bold green]",
        border_style="green",
    ))
    console.print()


def print_check_ip(ip: str, results: dict):
    console.print()
    console.print(Rule(f"[bold]IP Lookup — {ip}[/bold]", style="bright_cyan"))
    console.print()

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        console.print(f"[red]✗ Invalid IP address: {ip!r}[/red]")
        return

    matches = find_ip_in_results(ip, results)
    if not matches:
        total_cidrs = sum(len(d["v4"]) + len(d["v6"]) for d in results.values())
        console.print(Panel(
            f"[yellow]IP [bold]{ip}[/bold] is NOT in the current whitelist.[/yellow]\n"
            f"[dim]Checked against {total_cidrs:,} CIDRs across {len(results)} ASNs.[/dim]",
            title="[bold yellow]✗  Not Whitelisted[/bold yellow]",
            border_style="yellow",
        ))
    else:
        for m in matches:
            flag  = FLAG_MAP.get(m["country"], "🏳️")
            col   = REGION_COLORS.get(m["region"], "white")
            console.print(Panel(
                f"[bold green]✓  MATCH[/bold green]\n\n"
                f"  IP:      [bold cyan]{ip}[/bold cyan]\n"
                f"  CIDR:    [bold]{m['cidr']}[/bold]\n"
                f"  ASN:     [dim]AS{m['asn']}[/dim]  {m['name']}\n"
                f"  Country: {flag}  {m['country']}\n"
                f"  Region:  [{col}]{REGION_NAMES.get(m['region'], m['region'])}[/{col}]",
                title=f"[bold green]✓  Whitelisted via AS{m['asn']}[/bold green]",
                border_style="green",
            ))
    console.print()


def print_cache_stats(cache: CacheDB):
    s = cache.stats()
    console.print()
    console.print(Rule("[bold]Cache Status[/bold]", style="bright_cyan"))
    console.print()
    console.print(Panel(
        f"  [dim]Database:[/dim]      [cyan]{s['db_path']}[/cyan]  ({s['db_size_kb']} KB)\n"
        f"  [dim]RIPE entries:[/dim]  [green]{s['ripe_entries']}[/green]\n"
        f"  [dim]Abuse entries:[/dim] [green]{s['abuse_entries']}[/green]\n"
        f"  [dim]Snapshots:[/dim]     [green]{s['snapshots']}[/green]\n"
        f"  [dim]Quota used:[/dim]    [yellow]{s['quota_used']}[/yellow] / {ABUSEIPDB_DAILY_LIMIT}  "
        f"([green]{s['quota_left']}[/green] remaining today)",
        title="[bold bright_cyan]Cache & Quota[/bold bright_cyan]",
        border_style="bright_cyan",
    ))
    # Recent snapshots
    snaps = cache.list_snapshots()
    if snaps:
        console.print()
        t = Table(title="[dim]Recent Snapshots[/dim]", box=box.SIMPLE, border_style="dim")
        t.add_column("ID",        justify="right", style="dim")
        t.add_column("Timestamp", style="cyan")
        t.add_column("Filter Key", style="dim")
        t.add_column("ASNs",      justify="right")
        for s in snaps[:10]:
            t.add_row(str(s["id"]), s["ts"], s["key"], str(s["asns"]))
        console.print(t)
    console.print()


# ─────────────────────────────────────────────────────────────
# INTERACTIVE EXPORT MENU
# ─────────────────────────────────────────────────────────────

_FORMATS = {
    "1":  ("JSON — full metadata",           "json"),
    "2":  ("Flat CIDR — IPv4 only",          "flat_v4"),
    "3":  ("Flat CIDR — IPv6 only",          "flat_v6"),
    "4":  ("Flat CIDR — both",               "flat_both"),
    "5":  ("Cloudflare ASN Expression",      "cf_expr"),
    "6":  ("Cloudflare IP List",             "cf_ip_list"),
    "7":  ("ipset shell script",             "ipset"),
    "8":  ("nftables config",               "nftables"),
    "9":  ("nginx geo block",               "nginx_geo"),
    "10": ("HAProxy source ACL",            "haproxy"),
    "11": ("AWS Security Group JSON",       "aws_sg"),
    "12": ("ufw rules script",              "ufw"),
    "13": ("Caddy remote_ip matcher",       "caddy"),
    "a":  ("Export ALL formats",            "all"),
    "r":  ("AbuseIPDB audit report (JSON)", "abuse_report"),
    "d":  ("Diff report (JSON)",            "diff_report"),
    "0":  ("Skip",                          "skip"),
}


def interactive_export(
    results: dict,
    timestamp: str,
    out_dir: Path,
    audit: Optional[dict] = None,
    diff: Optional[dict] = None,
    old_ts: Optional[str] = None,
    threshold: int = 25,
):
    console.print(Rule("[bold]Export Options[/bold]", style="bright_cyan"))
    console.print()

    for key, (label, _) in _FORMATS.items():
        if key == "r" and not audit:
            continue
        if key == "d" and not diff:
            continue
        color = "bright_red" if key == "r" else "bright_yellow" if key == "d" else "bright_cyan"
        console.print(f"  [{color}]{key:>2}[/{color}]  {label}")

    console.print()
    valid = [k for k in _FORMATS if not (k == "r" and not audit) and not (k == "d" and not diff)]
    choice = Prompt.ask("[bold]Select format[/bold]", choices=valid, default="1")
    fmt = _FORMATS[choice][1]

    if fmt == "skip":
        console.print("[dim]Skipping export.[/dim]")
        return

    out_dir.mkdir(exist_ok=True)

    def write(name: str, content: str):
        p = out_dir / name
        p.write_text(content, encoding="utf-8")
        console.print(
            f"  [green]✓[/green] [cyan]{p}[/cyan]  "
            f"[dim]({len(content.splitlines()):,} lines)[/dim]"
        )

    console.print()
    _do_exports(fmt, results, timestamp, write, audit, diff, old_ts, threshold)
    console.print()
    console.print(f"[bold green]✓ Done![/bold green]  [cyan]{out_dir}/[/cyan]")
    console.print()


def _do_exports(
    fmt: str,
    results: dict,
    ts: str,
    write,
    audit: Optional[dict],
    diff: Optional[dict],
    old_ts: Optional[str],
    threshold: int,
):
    mapping = {
        "json":        (f"cidr_full_{ts}.json",          lambda: export_json_full(results)),
        "flat_v4":     (f"cidr_ipv4_{ts}.txt",           lambda: export_flat(results, "v4")),
        "flat_v6":     (f"cidr_ipv6_{ts}.txt",           lambda: export_flat(results, "v6")),
        "flat_both":   (f"cidr_all_{ts}.txt",            lambda: export_flat(results, "both")),
        "cf_expr":     (f"cf_expression_{ts}.txt",       lambda: export_cloudflare_expression(results)),
        "cf_ip_list":  (f"cf_ip_list_{ts}.txt",          lambda: export_cloudflare_ip_list(results)),
        "ipset":       (f"whitelist_ipset_{ts}.sh",      lambda: export_ipset(results)),
        "nftables":    (f"whitelist_nftables_{ts}.conf", lambda: export_nftables(results)),
        "nginx_geo":   (f"nginx_geo_{ts}.conf",          lambda: export_nginx_geo(results)),
        "haproxy":     (f"haproxy_acl_{ts}.txt",         lambda: export_haproxy(results)),
        "aws_sg":      (f"aws_sg_{ts}.json",             lambda: export_aws_sg(results)),
        "ufw":         (f"ufw_rules_{ts}.sh",            lambda: export_ufw(results)),
        "caddy":       (f"caddy_matcher_{ts}.txt",       lambda: export_caddy(results)),
    }
    abuse_entry = (
        f"abuseipdb_audit_{ts}.json",
        lambda: export_abuse_report(audit, threshold),
    ) if audit else None
    diff_entry  = (
        f"diff_{ts}.json",
        lambda: export_diff_json(diff, old_ts or "", ts),
    ) if diff else None

    if fmt == "all":
        for name, fn in mapping.values():
            write(name, fn())
        if abuse_entry:
            write(*abuse_entry)
        if diff_entry:
            write(*diff_entry)
    elif fmt == "abuse_report" and abuse_entry:
        write(*abuse_entry)
    elif fmt == "diff_report" and diff_entry:
        write(*diff_entry)
    elif fmt in mapping:
        name, fn = mapping[fmt]
        write(name, fn())


# ─────────────────────────────────────────────────────────────
# CORE RUN LOGIC
# ─────────────────────────────────────────────────────────────

def run_once(args, cache: CacheDB, timestamp: str, daemon_run: int = 0) -> dict:
    """
    Execute one full fetch → aggregate → diff → audit → export cycle.
    Returns the results dict (post-filter).
    """

    # ── Build ASN list ─────────────────────────────────────────
    if args.asn:
        asns = list(args.asn)
    else:
        asns = list(ASN_DB.keys())
        if args.no_mobile:
            asns = [a for a in asns if not ASN_DB[a].get("mobile")]
        if args.region:
            asns = [a for a in asns if ASN_DB[a].get("region") in args.region]
        if args.country:
            asns = [a for a in asns if ASN_DB[a].get("country") in args.country]

    if not asns:
        console.print("[red]No ASNs match your filters.[/red]")
        return {}

    filter_key = make_filter_key(
        args.asn or [], args.region or [], args.country or [], args.no_mobile
    )

    console.print(
        f"[dim]run #{daemon_run}  filters:[/dim]  "
        f"no-mobile=[cyan]{args.no_mobile}[/cyan]  "
        f"region=[cyan]{args.region or 'all'}[/cyan]  "
        f"country=[cyan]{args.country or 'all'}[/cyan]  "
        f"threads=[cyan]{args.threads}[/cyan]  "
        f"cache=[cyan]{not args.no_cache}[/cyan]"
    )
    console.print()

    print_asn_summary(asns)

    if getattr(args, "summary_only", False):
        return {}

    if not args.format and daemon_run == 0:
        if not Confirm.ask(f"[bold]Fetch CIDRs for {len(asns)} ASNs?[/bold]", default=True):
            return {}
        console.print()

    # ── Fetch ──────────────────────────────────────────────────
    results: dict = {}
    errors:  list = []
    cache_hits    = 0
    effective_cache = None if args.no_cache else cache

    with Progress(
        SpinnerColumn(style="bright_cyan"),
        TextColumn("[bold]{task.description}"),
        BarColumn(bar_width=40, style="bright_cyan", complete_style="green"),
        TaskProgressColumn(),
        TextColumn("[dim]{task.fields[status]}[/dim]"),
        TimeElapsedColumn(),
        console=console, transient=False,
    ) as progress:
        task = progress.add_task(
            f"[bright_cyan]Fetching {len(asns)} ASNs[/bright_cyan]",
            total=len(asns), status="starting…",
        )
        with ThreadPoolExecutor(max_workers=args.threads) as ex:
            futures = {
                ex.submit(fetch_asn_prefixes, asn, 3, effective_cache, args.ripe_ttl): asn
                for asn in asns
            }
            for future in as_completed(futures):
                asn  = futures[future]
                data = future.result()
                results[asn] = data
                if data.get("from_cache"):
                    cache_hits += 1
                if data["error"]:
                    errors.append(asn)
                meta   = ASN_DB.get(asn, {})
                status = (
                    f"AS{asn} {meta.get('name','')[:20]}  "
                    f"[green]{len(data['v4'])}[/green]v4 "
                    f"[blue]{len(data['v6'])}[/blue]v6"
                    + (" [dim](cached)[/dim]" if data.get("from_cache") else "")
                )
                if data["error"]:
                    status = f"[red]AS{asn} FAILED: {data['error'][:45]}[/red]"
                progress.update(task, advance=1, status=status)

    console.print()

    if args.no_v6:
        for data in results.values():
            data["v6"] = []

    print_results_table(results, errors, cache_hits)
    print_stats(results)

    # ── CIDR Aggregation ───────────────────────────────────────
    agg = None
    if not getattr(args, "no_aggregate", False):
        agg = aggregate_all_results(results)
        print_aggregate_stats(agg)

    # ── Diff vs last snapshot ──────────────────────────────────
    diff: Optional[dict] = None
    old_snap = cache.get_latest_snapshot(filter_key) if not getattr(args, "no_diff", False) else None

    all_v4 = agg["v4"] if agg else [c for d in results.values() for c in d["v4"]]
    all_v6 = agg["v6"] if agg else [c for d in results.values() for c in d["v6"]]
    new_ts  = timestamp

    if old_snap:
        diff = compute_diff(old_snap["v4"], old_snap["v6"], all_v4, all_v6)
        print_diff(diff, old_snap["timestamp"], new_ts)

    # Save snapshot
    if not getattr(args, "no_diff", False):
        cache.save_snapshot(filter_key, all_v4, all_v6, len(results))

    # ── AbuseIPDB Audit ────────────────────────────────────────
    audit: Optional[dict] = None
    abuse_key = getattr(args, "abuseipdb_key", None) or os.environ.get("ABUSEIPDB_KEY")

    if getattr(args, "abuse_check", False) and abuse_key:
        client = AbuseIPDBClient(
            api_key=abuse_key,
            max_age=args.abuse_max_age,
            cache=cache,
            cache_ttl=args.abuse_cache_ttl,
            daily_limit=getattr(args, "daily_limit", ABUSEIPDB_DAILY_LIMIT),
        )
        audit = audit_asns(results, client, samples_per_asn=args.abuse_samples)
        if audit:
            print_abuse_results(audit, threshold=args.abuse_threshold)
            print_abuse_panels(audit, threshold=args.abuse_threshold)

            if args.abuse_filter:
                flagged = [a for a in audit if audit[a]["avg_score"] >= args.abuse_threshold]
                if flagged:
                    console.print(Rule("[bold yellow]Filtering High-Risk ASNs[/bold yellow]", style="yellow"))
                    console.print()
                    for asn in flagged:
                        meta = ASN_DB.get(asn, {})
                        console.print(
                            f"  [red]✗[/red]  AS{asn} [dim]{meta.get('name','?')}[/dim]  "
                            f"avg=[bright_red]{audit[asn]['avg_score']}[/bright_red]"
                        )
                        del results[asn]
                    console.print(
                        f"\n  [yellow]Remaining for export:[/yellow] "
                        f"[bold cyan]{len(results)}[/bold cyan] ASNs\n"
                    )

    # ── IP lookup ──────────────────────────────────────────────
    if getattr(args, "check_ip", None):
        print_check_ip(args.check_ip, results)

    # ── Export ─────────────────────────────────────────────────
    out_dir = Path(args.output) if getattr(args, "output", None) else Path(f"cidr_output_{timestamp}")

    if args.format:
        out_dir.mkdir(exist_ok=True)
        console.print(Rule("[bold]Exporting[/bold]", style="bright_cyan"))
        console.print()

        def write(name: str, content: str):
            p = out_dir / name
            p.write_text(content, encoding="utf-8")
            console.print(
                f"  [green]✓[/green] [cyan]{p}[/cyan]  "
                f"[dim]({len(content.splitlines()):,} lines)[/dim]"
            )

        _do_exports(
            args.format, results, timestamp, write,
            audit if (audit and getattr(args, "abuse_export", False)) else None,
            diff  if getattr(args, "diff_export", False) else None,
            old_snap["timestamp"] if old_snap else None,
            getattr(args, "abuse_threshold", 25),
        )
        # Always include abuse + diff when exporting "all"
        if args.format == "all":
            if audit:
                thr = getattr(args, "abuse_threshold", 25)
                write(f"abuseipdb_audit_{timestamp}.json", export_abuse_report(audit, thr))
            if diff and old_snap:
                write(f"diff_{timestamp}.json", export_diff_json(diff, old_snap["timestamp"], timestamp))

        console.print()
        console.print(f"[bold green]✓ Done![/bold green]  [cyan]{out_dir}/[/cyan]")
        console.print()
    else:
        interactive_export(
            results, timestamp, out_dir,
            audit=audit,
            diff=diff,
            old_ts=old_snap["timestamp"] if old_snap else None,
            threshold=getattr(args, "abuse_threshold", 25),
        )

    # ── Webhook ────────────────────────────────────────────────
    webhook_url = getattr(args, "notify_webhook", None)
    if webhook_url:
        console.print(Rule("[bold]Webhook[/bold]", style="dim"))
        payload = build_webhook_payload(diff, audit,
                                        getattr(args, "abuse_threshold", 25),
                                        timestamp, len(results))
        send_webhook(webhook_url, payload)
        console.print()

    return results


# ─────────────────────────────────────────────────────────────
# DAEMON MODE
# ─────────────────────────────────────────────────────────────

def run_daemon(args, cache: CacheDB):
    interval = getattr(args, "daemon_interval", 3600)
    console.print(Panel(
        f"[bright_cyan]Daemon mode active.[/bright_cyan]\n"
        f"Interval: [bold]{interval}s[/bold] ({interval // 60} min)\n"
        f"Press [bold]Ctrl-C[/bold] to stop.",
        title="[bold bright_cyan]⏱  Scheduler[/bold bright_cyan]",
        border_style="bright_cyan",
    ))

    run_num = 0
    while True:
        run_num += 1
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        console.print()
        console.print(Rule(
            f"[bold]Daemon Run #{run_num}[/bold]  [dim]{ts}[/dim]",
            style="bright_cyan",
        ))
        try:
            run_once(args, cache, ts, daemon_run=run_num)
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            console.print(f"[red]Run #{run_num} error: {exc}[/red]")

        console.print(f"[dim]Sleeping {interval}s until next run. Ctrl-C to stop.[/dim]")
        time.sleep(interval)


# ─────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        prog="cidr_pull",
        description="Residential ISP Whitelist — ASN → CIDR fetcher v2.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  # Full interactive run
  cidr_pull.py

  # US-only, exclude mobile, export nginx geo block non-interactively
  cidr_pull.py --country US --no-mobile --format nginx_geo

  # Run abuse audit, filter high-risk ASNs, export everything
  cidr_pull.py --abuseipdb-key KEY --abuse-check --abuse-filter --format all

  # Check if an IP is whitelisted
  cidr_pull.py --check-ip 1.2.3.4 --no-diff

  # Daemon mode: refresh every hour, post webhook on changes
  cidr_pull.py --daemon --daemon-interval 3600 --format flat_v4 --notify-webhook https://hook.example.com/cidr

  # Add a custom ISP and fetch it with the standard set
  cidr_pull.py --add-asn "99999:My Local ISP:US:NA"

  # Inspect cache state / quota usage
  cidr_pull.py --show-cache
  cidr_pull.py --show-quota
        """,
    )

    fetch = p.add_argument_group("Fetch / Filter")
    fetch.add_argument("--no-mobile",    action="store_true", help="Exclude mobile carriers")
    fetch.add_argument("--region",       nargs="+",           help="Filter regions (NA SA EU AS OC ME AF)")
    fetch.add_argument("--country",      nargs="+",           help="Filter countries (US GB DE …)")
    fetch.add_argument("--asn",          nargs="+", type=int, help="Fetch specific ASNs only")
    fetch.add_argument("--threads",      type=int, default=10,help="Parallel fetch threads (default: 10)")
    fetch.add_argument("--no-v6",        action="store_true", help="Strip IPv6 prefixes from results")
    fetch.add_argument("--list-asns",    action="store_true", help="List all ASNs in DB and exit")
    fetch.add_argument("--summary-only", action="store_true", help="Show fetch plan only, no fetching")
    fetch.add_argument("--add-asn",      nargs="+", metavar="ASN:NAME:CC:REGION",
                       help="Add custom ASN(s) — format: 12345:Name:US:NA  (append :true for mobile)")
    fetch.add_argument("--asn-file",     metavar="PATH",
                       help="JSON file of custom ASNs: {\"ASN\": {name,country,region,mobile}}")

    cache_grp = p.add_argument_group("Cache")
    cache_grp.add_argument("--cache-dir",   default=str(DEFAULT_CACHE_DIR), metavar="DIR",
                           help=f"Cache directory (default: {DEFAULT_CACHE_DIR})")
    cache_grp.add_argument("--no-cache",    action="store_true", help="Bypass RIPE cache, always fetch live")
    cache_grp.add_argument("--ripe-ttl",    type=float, default=RIPE_TTL_HOURS,  metavar="HOURS",
                           help=f"RIPE cache TTL in hours (default: {RIPE_TTL_HOURS})")
    cache_grp.add_argument("--flush-cache", action="store_true", help="Clear all caches and exit")
    cache_grp.add_argument("--show-cache",  action="store_true", help="Show cache stats and exit")
    cache_grp.add_argument("--show-quota",  action="store_true", help="Show AbuseIPDB quota usage and exit")

    cidr_grp = p.add_argument_group("CIDR Processing")
    cidr_grp.add_argument("--no-aggregate", action="store_true",
                          help="Skip CIDR aggregation (aggregation is on by default)")
    cidr_grp.add_argument("--check-ip",    metavar="IP",
                          help="After fetching, check whether this IP is in the whitelist")
    cidr_grp.add_argument("--no-diff",     action="store_true", help="Skip snapshot diff computation")

    exp = p.add_argument_group("Export")
    exp.add_argument("--format", choices=[
        "json","flat_v4","flat_v6","flat_both","cf_expr","cf_ip_list",
        "ipset","nftables","nginx_geo","haproxy","aws_sg","ufw","caddy","all",
    ], help="Export format (skips interactive menu)")
    exp.add_argument("--output",      metavar="DIR",  help="Output directory (default: auto-timestamped)")
    exp.add_argument("--diff-export", action="store_true", help="Include diff JSON in export")

    abuse = p.add_argument_group("AbuseIPDB")
    abuse.add_argument("--abuseipdb-key",  metavar="KEY",
                       help="API key (or env: ABUSEIPDB_KEY). Get free key at abuseipdb.com/register")
    abuse.add_argument("--abuse-check",    action="store_true", help="Run reputation audit after fetching")
    abuse.add_argument("--abuse-samples",  type=int, default=5, metavar="N",
                       help="Random IPs to sample per ASN (default: 5). Free plan = 1 000 checks/day")
    abuse.add_argument("--abuse-threshold",type=int, default=25, metavar="SCORE",
                       help="Flag ASNs with avg score ≥ this (default: 25, range 0-100)")
    abuse.add_argument("--abuse-filter",   action="store_true",
                       help="Remove flagged ASNs from export")
    abuse.add_argument("--abuse-max-age",  type=int, default=30, metavar="DAYS",
                       help="Only count reports from last N days (default: 30)")
    abuse.add_argument("--abuse-cache-ttl",type=float, default=ABUSE_TTL_HOURS, metavar="HOURS",
                       help=f"AbuseIPDB result cache TTL (default: {ABUSE_TTL_HOURS}h)")
    abuse.add_argument("--abuse-export",   action="store_true",
                       help="Always write abuseipdb_audit_<ts>.json alongside other exports")
    abuse.add_argument("--daily-limit",    type=int, default=ABUSEIPDB_DAILY_LIMIT, metavar="N",
                       help=f"Override daily API limit (paid plans, default: {ABUSEIPDB_DAILY_LIMIT})")

    sched = p.add_argument_group("Daemon / Scheduler")
    sched.add_argument("--daemon",           action="store_true",
                       help="Run in continuous daemon mode (requires --format)")
    sched.add_argument("--daemon-interval",  type=int, default=3600, metavar="SECS",
                       help="Seconds between daemon runs (default: 3600)")
    sched.add_argument("--notify-webhook",   metavar="URL",
                       help="POST JSON summary to this URL after each run")

    return p.parse_args()


# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────

def main():
    args  = parse_args()
    cache = CacheDB(Path(args.cache_dir))
    print_banner()

    # ── Utility commands that exit early ──────────────────────

    if args.flush_cache:
        cache.flush_all()
        console.print(Panel("[green]✓ All caches cleared.[/green]", border_style="green"))
        cache.close(); sys.exit(0)

    if args.show_cache:
        print_cache_stats(cache)
        cache.close(); sys.exit(0)

    if args.show_quota:
        used = cache.quota_used()
        left = cache.quota_remaining(args.daily_limit)
        console.print(Panel(
            f"[dim]Limit:[/dim]   {args.daily_limit}\n"
            f"[dim]Used:[/dim]    [yellow]{used}[/yellow]\n"
            f"[dim]Remaining:[/dim] [green]{left}[/green]",
            title="[bold]AbuseIPDB Quota — Today[/bold]",
            border_style="bright_red",
        ))
        cache.close(); sys.exit(0)

    # ── Merge custom ASNs ─────────────────────────────────────
    custom = load_custom_asns(args.add_asn or [], getattr(args, "asn_file", None))
    if custom:
        console.print(
            f"  [bright_cyan]+[/bright_cyan] Loaded [cyan]{len(custom)}[/cyan] custom ASNs: "
            + ", ".join(f"AS{a}" for a in custom)
        )
        console.print()

    # ── list-asns mode ────────────────────────────────────────
    if args.list_asns:
        t = Table(title="All ASNs in Database", box=box.ROUNDED, border_style="bright_cyan")
        t.add_column("ASN",    style="dim cyan", justify="right")
        t.add_column("Name",   style="white")
        t.add_column("Country",justify="center")
        t.add_column("Region", justify="center")
        t.add_column("Mobile", justify="center")
        for asn in sorted(ASN_DB.keys()):
            meta = ASN_DB[asn]
            flag = FLAG_MAP.get(meta["country"], "🏳️")
            col  = REGION_COLORS.get(meta["region"], "white")
            t.add_row(
                str(asn), meta["name"],
                f"{flag} {meta['country']}",
                f"[{col}]{meta['region']}[/{col}]",
                "[red]●[/red]" if meta["mobile"] else "[dim]○[/dim]",
            )
        console.print(t)
        console.print(f"\n[dim]Total: {len(ASN_DB)} ASNs[/dim]\n")
        cache.close(); sys.exit(0)

    # ── AbuseIPDB key validation ──────────────────────────────
    if args.abuse_check:
        abuse_key = args.abuseipdb_key or os.environ.get("ABUSEIPDB_KEY")
        if not abuse_key:
            console.print(Panel(
                "[red]--abuse-check requires an API key.\n\n"
                "Supply [bold]--abuseipdb-key KEY[/bold] or set [bold]ABUSEIPDB_KEY[/bold] env var.\n"
                "Free key: [cyan]https://www.abuseipdb.com/register[/cyan][/red]",
                title="[bold red]⚠  Missing AbuseIPDB Key[/bold red]",
                border_style="red",
            ))
            cache.close(); sys.exit(1)
        args.abuseipdb_key = abuse_key

    # ── Daemon loop ───────────────────────────────────────────
    if args.daemon:
        if not args.format:
            console.print("[yellow]⚠ --daemon requires --format to be set. Defaulting to flat_v4.[/yellow]")
            args.format = "flat_v4"
        try:
            run_daemon(args, cache)
        except KeyboardInterrupt:
            console.print("\n[dim]Daemon stopped.[/dim]")
        finally:
            cache.close()
        return

    # ── Single run ────────────────────────────────────────────
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    try:
        run_once(args, cache, timestamp, daemon_run=0)
    finally:
        cache.close()


if __name__ == "__main__":
    main()
