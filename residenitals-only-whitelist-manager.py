#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════╗
║          CIDR PULL — Residential ISP Whitelist        ║
║          ASN → CIDR range fetcher & exporter          ║
╚═══════════════════════════════════════════════════════╝
"""

import json
import time
import sys
import argparse
import ipaddress
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

import requests
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TaskProgressColumn
from rich.panel import Panel
from rich.columns import Columns
from rich.text import Text
from rich import box
from rich.prompt import Prompt, Confirm
from rich.live import Live
from rich.layout import Layout
from rich.rule import Rule
from rich.syntax import Syntax
from rich.tree import Tree

console = Console()

# ─────────────────────────────────────────────────────────────
# ASN DATABASE
# ─────────────────────────────────────────────────────────────

ASN_DB = {
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
    # ── USA new ──────────────────────────────────────────────
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
    # ── Canada new ───────────────────────────────────────────
    577:    {"name": "Bell Canada (alt)",        "country": "CA", "region": "NA", "mobile": False},
    6082:   {"name": "Cogeco",                   "country": "CA", "region": "NA", "mobile": False},
    5577:   {"name": "Eastlink",                 "country": "CA", "region": "NA", "mobile": False},
    7786:   {"name": "TELUS (alt)",              "country": "CA", "region": "NA", "mobile": False},
    # ── Mexico ───────────────────────────────────────────────
    13999:  {"name": "Megacable",                "country": "MX", "region": "NA", "mobile": False},
    28006:  {"name": "Cablemas",                 "country": "MX", "region": "NA", "mobile": False},
    # ── Brazil new ───────────────────────────────────────────
    7162:   {"name": "Vivo/Telefônica (fixed)",  "country": "BR", "region": "SA", "mobile": False},
    28343:  {"name": "Copel Telecom",            "country": "BR", "region": "SA", "mobile": False},
    16735:  {"name": "Algar Telecom",            "country": "BR", "region": "SA", "mobile": False},
    27699:  {"name": "Telefônica BR (alt)",      "country": "BR", "region": "SA", "mobile": False},
    28598:  {"name": "Desktop/Virtua",           "country": "BR", "region": "SA", "mobile": False},
    # ── LATAM ────────────────────────────────────────────────
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
    # ── UK new ───────────────────────────────────────────────
    25135:  {"name": "Vodafone UK (fixed)",      "country": "GB", "region": "EU", "mobile": False},
    5462:   {"name": "EE/BT",                    "country": "GB", "region": "EU", "mobile": False},
    9105:   {"name": "TalkTalk",                 "country": "GB", "region": "EU", "mobile": False},
    35228:  {"name": "TalkTalk (alt)",           "country": "GB", "region": "EU", "mobile": False},
    8190:   {"name": "KCOM",                     "country": "GB", "region": "EU", "mobile": False},
    # ── Germany new ──────────────────────────────────────────
    29562:  {"name": "Vodafone Kabel DE",        "country": "DE", "region": "EU", "mobile": False},
    31334:  {"name": "Kabel Deutschland",        "country": "DE", "region": "EU", "mobile": False},
    8422:   {"name": "NetCologne",               "country": "DE", "region": "EU", "mobile": False},
    6830:   {"name": "Liberty Global/UPC",       "country": "DE", "region": "EU", "mobile": False},
    # ── France new ───────────────────────────────────────────
    21502:  {"name": "Numericable/SFR",          "country": "FR", "region": "EU", "mobile": False},
    # ── Spain new ────────────────────────────────────────────
    15704:  {"name": "MasMovil",                 "country": "ES", "region": "EU", "mobile": False},
    12338:  {"name": "Jazztel/Orange ES",        "country": "ES", "region": "EU", "mobile": False},
    # ── Italy new ────────────────────────────────────────────
    8612:   {"name": "Tiscali Italy",            "country": "IT", "region": "EU", "mobile": False},
    # ── Netherlands ──────────────────────────────────────────
    1136:   {"name": "KPN",                      "country": "NL", "region": "EU", "mobile": False},
    33915:  {"name": "Ziggo",                    "country": "NL", "region": "EU", "mobile": False},
    9143:   {"name": "Ziggo (alt)",              "country": "NL", "region": "EU", "mobile": False},
    5615:   {"name": "XS4ALL/KPN",              "country": "NL", "region": "EU", "mobile": False},
    # ── Belgium ──────────────────────────────────────────────
    5432:   {"name": "Proximus",                 "country": "BE", "region": "EU", "mobile": False},
    6848:   {"name": "Telenet Belgium",          "country": "BE", "region": "EU", "mobile": False},
    12392:  {"name": "Voo Belgium",              "country": "BE", "region": "EU", "mobile": False},
    # ── Switzerland ──────────────────────────────────────────
    3303:   {"name": "Swisscom",                 "country": "CH", "region": "EU", "mobile": False},
    6730:   {"name": "Sunrise",                  "country": "CH", "region": "EU", "mobile": False},
    15627:  {"name": "UPC Switzerland",          "country": "CH", "region": "EU", "mobile": False},
    # ── Austria ──────────────────────────────────────────────
    8447:   {"name": "A1 Telekom Austria",       "country": "AT", "region": "EU", "mobile": False},
    12635:  {"name": "Telekabel Wien",           "country": "AT", "region": "EU", "mobile": False},
    25255:  {"name": "Liwest",                   "country": "AT", "region": "EU", "mobile": False},
    # ── Nordics ──────────────────────────────────────────────
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
    # ── Poland ───────────────────────────────────────────────
    5617:   {"name": "Orange Poland",            "country": "PL", "region": "EU", "mobile": False},
    12741:  {"name": "Netia Poland",             "country": "PL", "region": "EU", "mobile": False},
    5588:   {"name": "T-Mobile PL (fixed)",      "country": "PL", "region": "EU", "mobile": False},
    29314:  {"name": "Vectra Poland",            "country": "PL", "region": "EU", "mobile": False},
    50607:  {"name": "Inea Poland",              "country": "PL", "region": "EU", "mobile": False},
    # ── Czech / Hungary / Romania ─────────────────────────────
    5610:   {"name": "O2 Czech Republic",        "country": "CZ", "region": "EU", "mobile": False},
    35236:  {"name": "Vodafone Czech",           "country": "CZ", "region": "EU", "mobile": False},
    5483:   {"name": "Magyar Telekom",           "country": "HU", "region": "EU", "mobile": False},
    29179:  {"name": "Vodafone Hungary",         "country": "HU", "region": "EU", "mobile": False},
    6764:   {"name": "UPC Hungary",              "country": "HU", "region": "EU", "mobile": False},
    21334:  {"name": "DIGI Hungary",             "country": "HU", "region": "EU", "mobile": False},
    9050:   {"name": "Telekom Romania",          "country": "RO", "region": "EU", "mobile": False},
    8708:   {"name": "RCS&RDS/Digi RO",          "country": "RO", "region": "EU", "mobile": False},
    31178:  {"name": "UPC Romania",              "country": "RO", "region": "EU", "mobile": False},
    # ── Balkans/Baltics ───────────────────────────────────────
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
    # ── Portugal / Greece / Turkey ───────────────────────────
    2860:   {"name": "NOS Portugal",             "country": "PT", "region": "EU", "mobile": False},
    12353:  {"name": "Vodafone Portugal",        "country": "PT", "region": "EU", "mobile": False},
    15525:  {"name": "MEO/Altice PT",            "country": "PT", "region": "EU", "mobile": False},
    6799:   {"name": "OTE/Cosmote Greece",       "country": "GR", "region": "EU", "mobile": False},
    15617:  {"name": "Forthnet Greece",          "country": "GR", "region": "EU", "mobile": False},
    9121:   {"name": "Türk Telekom",             "country": "TR", "region": "EU", "mobile": False},
    34984:  {"name": "SuperOnline Turkey",       "country": "TR", "region": "EU", "mobile": False},
    47331:  {"name": "Türk Telekom (alt)",       "country": "TR", "region": "EU", "mobile": False},
    # ── Russia new (fixed only) ───────────────────────────────
    15493:  {"name": "Dom.ru/ERTelecom",         "country": "RU", "region": "EU", "mobile": False},
    25513:  {"name": "MGTS Moscow",              "country": "RU", "region": "EU", "mobile": False},
    43267:  {"name": "TTK/TransTeleCom",         "country": "RU", "region": "EU", "mobile": False},
    8749:   {"name": "Enforta Russia",           "country": "RU", "region": "EU", "mobile": False},
    # ── Japan new ────────────────────────────────────────────
    4694:   {"name": "OCN/NTT Communications",  "country": "JP", "region": "AS", "mobile": False},
    4685:   {"name": "IIJ Japan",               "country": "JP", "region": "AS", "mobile": False},
    9613:   {"name": "Asahi Net Japan",          "country": "JP", "region": "AS", "mobile": False},
    7521:   {"name": "NTT PC Communications",   "country": "JP", "region": "AS", "mobile": False},
    # ── Korea ────────────────────────────────────────────────
    4766:   {"name": "KT Corp Korea",            "country": "KR", "region": "AS", "mobile": False},
    9318:   {"name": "SK Broadband Korea",       "country": "KR", "region": "AS", "mobile": False},
    17858:  {"name": "LG U+ Korea (fixed)",      "country": "KR", "region": "AS", "mobile": False},
    # ── Taiwan ───────────────────────────────────────────────
    9416:   {"name": "So-net Taiwan",            "country": "TW", "region": "AS", "mobile": False},
    # ── Hong Kong ────────────────────────────────────────────
    10026:  {"name": "PCCW/HKT",                "country": "HK", "region": "AS", "mobile": False},
    4515:   {"name": "PCCW (alt)",              "country": "HK", "region": "AS", "mobile": False},
    9269:   {"name": "HKBN",                    "country": "HK", "region": "AS", "mobile": False},
    4760:   {"name": "HKBN (alt)",              "country": "HK", "region": "AS", "mobile": False},
    9293:   {"name": "HGC/City Telecom",         "country": "HK", "region": "AS", "mobile": False},
    # ── Australia ────────────────────────────────────────────
    1221:   {"name": "Telstra Australia",        "country": "AU", "region": "OC", "mobile": False},
    4804:   {"name": "Optus Australia",          "country": "AU", "region": "OC", "mobile": False},
    7545:   {"name": "TPG Australia",            "country": "AU", "region": "OC", "mobile": False},
    4739:   {"name": "iiNet/TPG",               "country": "AU", "region": "OC", "mobile": False},
    38817:  {"name": "Aussie Broadband",         "country": "AU", "region": "OC", "mobile": False},
    38220:  {"name": "Internode/TPG",           "country": "AU", "region": "OC", "mobile": False},
    38753:  {"name": "Vocus Australia",          "country": "AU", "region": "OC", "mobile": False},
    131072: {"name": "Telstra (alt)",            "country": "AU", "region": "OC", "mobile": False},
    # ── New Zealand ──────────────────────────────────────────
    9790:   {"name": "Spark NZ",                "country": "NZ", "region": "OC", "mobile": False},
    17746:  {"name": "Vodafone NZ (fixed)",      "country": "NZ", "region": "OC", "mobile": False},
    4771:   {"name": "Orcon/Voyager",           "country": "NZ", "region": "OC", "mobile": False},
    # ── India new ────────────────────────────────────────────
    23860:  {"name": "MTNL India",              "country": "IN", "region": "AS", "mobile": False},
    18101:  {"name": "Reliance Comm (fixed)",   "country": "IN", "region": "AS", "mobile": False},
    45820:  {"name": "Tikona India",            "country": "IN", "region": "AS", "mobile": False},
    45528:  {"name": "Excitel India",           "country": "IN", "region": "AS", "mobile": False},
    # ── Philippines fixed only ───────────────────────────────
    23944:  {"name": "Converge ICT",            "country": "PH", "region": "AS", "mobile": False},
    9584:   {"name": "ePLDT",                   "country": "PH", "region": "AS", "mobile": False},
    # ── Indonesia fixed only ─────────────────────────────────
    17974:  {"name": "Telkom Indonesia",        "country": "ID", "region": "AS", "mobile": False},
    7713:   {"name": "Telkom ID (alt)",         "country": "ID", "region": "AS", "mobile": False},
    45727:  {"name": "Biznet Indonesia",        "country": "ID", "region": "AS", "mobile": False},
    9341:   {"name": "CBN Indonesia",           "country": "ID", "region": "AS", "mobile": False},
    45558:  {"name": "MNC Play",               "country": "ID", "region": "AS", "mobile": False},
    38285:  {"name": "MyRepublic ID",          "country": "ID", "region": "AS", "mobile": False},
    # ── Vietnam fixed only ───────────────────────────────────
    7643:   {"name": "VNPT Vietnam",           "country": "VN", "region": "AS", "mobile": False},
    45899:  {"name": "VNPT (alt)",             "country": "VN", "region": "AS", "mobile": False},
    18403:  {"name": "FPT Telecom",            "country": "VN", "region": "AS", "mobile": False},
    45903:  {"name": "CMC Telecom VN",         "country": "VN", "region": "AS", "mobile": False},
    # ── Thailand fixed only ──────────────────────────────────
    7470:   {"name": "TOT Thailand",           "country": "TH", "region": "AS", "mobile": False},
    9331:   {"name": "CAT Telecom TH",         "country": "TH", "region": "AS", "mobile": False},
    45758:  {"name": "True Online (fixed)",    "country": "TH", "region": "AS", "mobile": False},
    4750:   {"name": "TRUE Corp Thailand",     "country": "TH", "region": "AS", "mobile": False},
    131445: {"name": "3BB Thailand",           "country": "TH", "region": "AS", "mobile": False},
    # ── Malaysia fixed only ──────────────────────────────────
    4788:   {"name": "TM/Unifi Malaysia",      "country": "MY", "region": "AS", "mobile": False},
    10030:  {"name": "TM Malaysia (alt)",      "country": "MY", "region": "AS", "mobile": False},
    9930:   {"name": "TIME dotCom",            "country": "MY", "region": "AS", "mobile": False},
    # ── Singapore ────────────────────────────────────────────
    9506:   {"name": "Singtel",               "country": "SG", "region": "AS", "mobile": False},
    4657:   {"name": "Singtel (alt)",         "country": "SG", "region": "AS", "mobile": False},
    3758:   {"name": "Singtel (alt2)",        "country": "SG", "region": "AS", "mobile": False},
    7473:   {"name": "Singtel (alt3)",        "country": "SG", "region": "AS", "mobile": False},
    10091:  {"name": "MyRepublic SG",         "country": "SG", "region": "AS", "mobile": False},
    # ── Middle East ──────────────────────────────────────────
    8551:   {"name": "Bezeq Israel",          "country": "IL", "region": "ME", "mobile": False},
    12400:  {"name": "Partner Comm IL (fixed)","country": "IL", "region": "ME", "mobile": False},
    6869:   {"name": "Bezeq International",   "country": "IL", "region": "ME", "mobile": False},
    25019:  {"name": "STC Saudi Arabia",      "country": "SA", "region": "ME", "mobile": False},
    39386:  {"name": "STC (alt)",             "country": "SA", "region": "ME", "mobile": False},
    5384:   {"name": "Etisalat UAE",          "country": "AE", "region": "ME", "mobile": False},
    15802:  {"name": "du Telecom UAE (fixed)","country": "AE", "region": "ME", "mobile": False},
    # ── Africa ───────────────────────────────────────────────
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
    "NA": "North America",
    "SA": "South America",
    "EU": "Europe",
    "AS": "Asia",
    "OC": "Oceania",
    "ME": "Middle East",
    "AF": "Africa",
}

REGION_COLORS = {
    "NA": "bright_blue",
    "SA": "green",
    "EU": "yellow",
    "AS": "magenta",
    "OC": "cyan",
    "ME": "bright_red",
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
# FETCH
# ─────────────────────────────────────────────────────────────

def fetch_asn_prefixes(asn: int, retries: int = 3) -> dict:
    url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
    for attempt in range(retries):
        try:
            r = requests.get(url, timeout=15)
            r.raise_for_status()
            data = r.json()
            prefixes = data.get("data", {}).get("prefixes", [])
            v4 = [p["prefix"] for p in prefixes if ":" not in p["prefix"]]
            v6 = [p["prefix"] for p in prefixes if ":" in p["prefix"]]
            return {"asn": asn, "v4": v4, "v6": v6, "total": len(prefixes), "error": None}
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(1.5 ** attempt)
            else:
                return {"asn": asn, "v4": [], "v6": [], "total": 0, "error": str(e)}


# ─────────────────────────────────────────────────────────────
# EXPORT FORMATTERS
# ─────────────────────────────────────────────────────────────

def export_json(results: dict, include_meta: bool = True) -> str:
    out = {
        "generated": datetime.utcnow().isoformat() + "Z",
        "total_asns": len(results),
        "total_v4": sum(len(v["v4"]) for v in results.values()),
        "total_v6": sum(len(v["v6"]) for v in results.values()),
        "asns": {}
    }
    for asn, data in results.items():
        meta = ASN_DB.get(asn, {})
        entry = {
            "name": meta.get("name", "Unknown"),
            "country": meta.get("country", "?"),
            "region": meta.get("region", "?"),
            "mobile": meta.get("mobile", False),
            "v4_count": len(data["v4"]),
            "v6_count": len(data["v6"]),
            "v4": sorted(data["v4"]),
            "v6": sorted(data["v6"]),
        }
        out["asns"][f"AS{asn}"] = entry
    return json.dumps(out, indent=2)


def export_flat(results: dict, ip_version: str = "both") -> str:
    lines = []
    for asn, data in results.items():
        if ip_version in ("both", "v4"):
            lines.extend(data["v4"])
        if ip_version in ("both", "v6"):
            lines.extend(data["v6"])
    return "\n".join(sorted(set(lines)))


def export_cloudflare_expression(results: dict) -> str:
    asns = sorted(results.keys())
    chunks, chunk = [], []
    for asn in asns:
        chunk.append(str(asn))
        if len(chunk) == 20:
            chunks.append(chunk)
            chunk = []
    if chunk:
        chunks.append(chunk)

    lines = ["(ip.geoip.asnum in {"]
    for i, chunk in enumerate(chunks):
        prefix = "  " if i == 0 else "  "
        lines.append(prefix + " ".join(chunk))
    lines.append("}) and (not cf.client.bot)")
    return "\n".join(lines)


def export_cloudflare_ip_list(results: dict, ip_version: str = "both") -> str:
    """Flat CIDR list for import into a Cloudflare IP List"""
    lines = []
    for asn, data in sorted(results.items()):
        meta = ASN_DB.get(asn, {})
        lines.append(f"# AS{asn} — {meta.get('name','?')} ({meta.get('country','?')})")
        if ip_version in ("both", "v4"):
            lines.extend(sorted(data["v4"]))
        if ip_version in ("both", "v6"):
            lines.extend(sorted(data["v6"]))
        lines.append("")
    return "\n".join(lines)


def export_ipset(results: dict) -> str:
    v4_all, v6_all = set(), set()
    for data in results.values():
        v4_all.update(data["v4"])
        v6_all.update(data["v6"])
    lines = [
        "#!/bin/bash",
        "# Generated by cidr_pull.py — " + datetime.utcnow().isoformat() + "Z",
        "",
        "ipset destroy whitelist_v4 2>/dev/null",
        "ipset destroy whitelist_v6 2>/dev/null",
        "ipset create whitelist_v4 hash:net family inet hashsize 65536 maxelem 524288",
        "ipset create whitelist_v6 hash:net family inet6 hashsize 65536 maxelem 524288",
        "",
    ]
    for cidr in sorted(v4_all):
        lines.append(f"ipset add whitelist_v4 {cidr}")
    for cidr in sorted(v6_all):
        lines.append(f"ipset add whitelist_v6 {cidr}")
    lines += [
        "",
        "# Apply rules — DROP everything not whitelisted",
        "iptables  -I INPUT -m set ! --match-set whitelist_v4 src -j DROP",
        "ip6tables -I INPUT -m set ! --match-set whitelist_v6 src -j DROP",
    ]
    return "\n".join(lines)


def export_nftables(results: dict) -> str:
    v4_all, v6_all = set(), set()
    for data in results.values():
        v4_all.update(data["v4"])
        v6_all.update(data["v6"])
    v4_str = ",\n      ".join(sorted(v4_all))
    v6_str = ",\n      ".join(sorted(v6_all))
    return f"""table inet filter {{
  set whitelist_v4 {{
    type ipv4_addr
    flags interval
    elements = {{
      {v4_str}
    }}
  }}

  set whitelist_v6 {{
    type ipv6_addr
    flags interval
    elements = {{
      {v6_str}
    }}
  }}

  chain input {{
    type filter hook input priority 0;
    ip  saddr @whitelist_v4 accept
    ip6 saddr @whitelist_v6 accept
    drop
  }}
}}
"""


# ─────────────────────────────────────────────────────────────
# UI HELPERS
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
        "[dim]  Residential ISP Whitelist — ASN → CIDR Fetcher[/dim]",
        border_style="bright_cyan",
    ))
    console.print()


def print_asn_summary(asns: list[int]):
    """Show table of ASNs that will be fetched, grouped by region"""
    by_region = defaultdict(list)
    mobile_count = 0
    for asn in asns:
        meta = ASN_DB.get(asn, {"name": "Unknown", "country": "?", "region": "?", "mobile": False})
        by_region[meta["region"]].append((asn, meta))
        if meta.get("mobile"):
            mobile_count += 1

    tree = Tree(f"[bold]ASN Fetch Plan[/bold] — [cyan]{len(asns)}[/cyan] ASNs across [cyan]{len(by_region)}[/cyan] regions")
    for region, entries in sorted(by_region.items()):
        region_name = REGION_NAMES.get(region, region)
        color = REGION_COLORS.get(region, "white")
        branch = tree.add(f"[{color}]{region_name}[/{color}] ([dim]{len(entries)} ASNs[/dim])")
        for asn, meta in sorted(entries, key=lambda x: x[1]["country"]):
            flag = FLAG_MAP.get(meta["country"], "🏳️")
            mob_tag = " [red][MOBILE][/red]" if meta["mobile"] else ""
            branch.add(f"{flag}  [dim]AS{asn}[/dim]  {meta['name']}{mob_tag}")

    console.print(tree)
    console.print()
    if mobile_count:
        console.print(f"  [yellow]⚠[/yellow]  [dim]{mobile_count} mobile ASNs included (pass --no-mobile to exclude)[/dim]")
        console.print()


def print_results_table(results: dict, errors: list):
    table = Table(
        title="[bold]Fetch Results[/bold]",
        box=box.ROUNDED,
        border_style="bright_cyan",
        show_footer=True,
    )
    table.add_column("ASN",     style="dim cyan",   justify="right",  footer="TOTAL")
    table.add_column("Name",    style="white",       max_width=30)
    table.add_column("Country", justify="center")
    table.add_column("Region",  justify="center")
    table.add_column("Mobile",  justify="center")
    table.add_column("IPv4",    style="green",       justify="right",  footer=str(sum(len(v["v4"]) for v in results.values())))
    table.add_column("IPv6",    style="blue",        justify="right",  footer=str(sum(len(v["v6"]) for v in results.values())))
    table.add_column("Status",  justify="center")

    for asn in sorted(results.keys()):
        data = results[asn]
        meta = ASN_DB.get(asn, {"name": "Unknown", "country": "?", "region": "?", "mobile": False})
        flag = FLAG_MAP.get(meta.get("country", "?"), "🏳️")
        region = meta.get("region", "?")
        color = REGION_COLORS.get(region, "white")
        mobile_tag = "[red]●[/red]" if meta.get("mobile") else "[dim]○[/dim]"
        status = "[green]✓[/green]" if not data.get("error") else "[red]✗[/red]"

        table.add_row(
            str(asn),
            meta.get("name", "Unknown"),
            f"{flag} {meta.get('country','?')}",
            f"[{color}]{region}[/{color}]",
            mobile_tag,
            str(len(data["v4"])),
            str(len(data["v6"])),
            status,
        )

    console.print(table)

    if errors:
        console.print()
        console.print(f"  [red]✗ {len(errors)} failed ASNs:[/red] " + ", ".join(f"AS{e}" for e in errors))
    console.print()


def print_stats(results: dict):
    v4_all, v6_all = set(), set()
    by_region = defaultdict(lambda: {"v4": 0, "v6": 0, "asns": 0})
    for asn, data in results.items():
        v4_all.update(data["v4"])
        v6_all.update(data["v6"])
        region = ASN_DB.get(asn, {}).get("region", "?")
        by_region[region]["v4"] += len(data["v4"])
        by_region[region]["v6"] += len(data["v6"])
        by_region[region]["asns"] += 1

    # Summary panels
    panels = [
        Panel(f"[bold bright_cyan]{len(results)}[/bold bright_cyan]\n[dim]ASNs fetched[/dim]", border_style="cyan"),
        Panel(f"[bold green]{len(v4_all):,}[/bold green]\n[dim]Unique IPv4 CIDRs[/dim]", border_style="green"),
        Panel(f"[bold blue]{len(v6_all):,}[/bold blue]\n[dim]Unique IPv6 CIDRs[/dim]", border_style="blue"),
        Panel(f"[bold yellow]{len(v4_all)+len(v6_all):,}[/bold yellow]\n[dim]Total prefixes[/dim]", border_style="yellow"),
    ]
    console.print(Columns(panels, equal=True, expand=True))
    console.print()

    # Region breakdown
    table = Table(box=box.SIMPLE, border_style="dim", title="[dim]Breakdown by Region[/dim]")
    table.add_column("Region")
    table.add_column("ASNs",  justify="right", style="cyan")
    table.add_column("IPv4",  justify="right", style="green")
    table.add_column("IPv6",  justify="right", style="blue")
    for region, stats in sorted(by_region.items()):
        color = REGION_COLORS.get(region, "white")
        table.add_row(
            f"[{color}]{REGION_NAMES.get(region, region)}[/{color}]",
            str(stats["asns"]),
            str(stats["v4"]),
            str(stats["v6"]),
        )
    console.print(table)
    console.print()


# ─────────────────────────────────────────────────────────────
# INTERACTIVE MODE
# ─────────────────────────────────────────────────────────────

def interactive_export_menu(results: dict, timestamp: str):
    console.print(Rule("[bold]Export Options[/bold]", style="bright_cyan"))
    console.print()

    formats = {
        "1": ("JSON (full metadata)",           "json"),
        "2": ("Flat CIDR list — IPv4 only",     "flat_v4"),
        "3": ("Flat CIDR list — IPv6 only",     "flat_v6"),
        "4": ("Flat CIDR list — both",          "flat_both"),
        "5": ("Cloudflare ASN Expression",       "cf_expr"),
        "6": ("Cloudflare IP List (with CIDRs)","cf_ip_list"),
        "7": ("ipset shell script",              "ipset"),
        "8": ("nftables config",                "nftables"),
        "9": ("Export ALL formats",             "all"),
        "0": ("Skip / Exit",                    "skip"),
    }

    for key, (label, _) in formats.items():
        console.print(f"  [bright_cyan]{key}[/bright_cyan]  {label}")
    console.print()

    choice = Prompt.ask("[bold]Select export format[/bold]", choices=list(formats.keys()), default="1")
    fmt = formats[choice][1]

    if fmt == "skip":
        console.print("[dim]Skipping export.[/dim]")
        return

    out_dir = Path("cidr_output_" + timestamp)
    out_dir.mkdir(exist_ok=True)

    def write(filename, content):
        path = out_dir / filename
        path.write_text(content)
        console.print(f"  [green]✓[/green] Saved: [cyan]{path}[/cyan]  ([dim]{len(content.splitlines()):,} lines[/dim])")

    exports = {
        "json":        lambda: write(f"cidr_full_{timestamp}.json",        export_json(results)),
        "flat_v4":     lambda: write(f"cidr_ipv4_{timestamp}.txt",         export_flat(results, "v4")),
        "flat_v6":     lambda: write(f"cidr_ipv6_{timestamp}.txt",         export_flat(results, "v6")),
        "flat_both":   lambda: write(f"cidr_all_{timestamp}.txt",          export_flat(results, "both")),
        "cf_expr":     lambda: write(f"cf_expression_{timestamp}.txt",     export_cloudflare_expression(results)),
        "cf_ip_list":  lambda: write(f"cf_ip_list_{timestamp}.txt",        export_cloudflare_ip_list(results)),
        "ipset":       lambda: write(f"whitelist_ipset_{timestamp}.sh",    export_ipset(results)),
        "nftables":    lambda: write(f"whitelist_nftables_{timestamp}.conf",export_nftables(results)),
    }

    console.print()
    if fmt == "all":
        for fn in exports.values():
            fn()
    else:
        exports[fmt]()

    console.print()
    console.print(f"[bold green]✓ Done![/bold green] Files saved to [cyan]{out_dir}/[/cyan]")
    console.print()


# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="CIDR Pull — Residential ISP Whitelist Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--no-mobile",     action="store_true",  help="Exclude mobile carriers")
    parser.add_argument("--region",        nargs="+",            help="Filter to regions (NA SA EU AS OC ME AF)")
    parser.add_argument("--country",       nargs="+",            help="Filter to countries (US GB DE ...)")
    parser.add_argument("--asn",           nargs="+", type=int,  help="Fetch specific ASNs only")
    parser.add_argument("--threads",       type=int, default=10, help="Concurrent fetch threads (default: 10)")
    parser.add_argument("--format",        choices=["json","flat_v4","flat_v6","flat_both",
                                                    "cf_expr","cf_ip_list","ipset","nftables","all"],
                                           help="Export format (skip interactive menu)")
    parser.add_argument("--output",        type=str,             help="Output directory (default: auto-timestamped)")
    parser.add_argument("--no-v6",         action="store_true",  help="Exclude IPv6 prefixes")
    parser.add_argument("--list-asns",     action="store_true",  help="List all ASNs in DB and exit")
    parser.add_argument("--summary-only",  action="store_true",  help="Show fetch plan and exit without fetching")
    return parser.parse_args()


def main():
    args = parse_args()
    print_banner()

    # ── list mode ─────────────────────────────────────────────
    if args.list_asns:
        table = Table(title="All ASNs in Database", box=box.ROUNDED, border_style="bright_cyan")
        table.add_column("ASN",     style="dim cyan", justify="right")
        table.add_column("Name",    style="white")
        table.add_column("Country", justify="center")
        table.add_column("Region",  justify="center")
        table.add_column("Mobile",  justify="center")
        for asn in sorted(ASN_DB.keys()):
            meta = ASN_DB[asn]
            flag = FLAG_MAP.get(meta["country"], "🏳️")
            region = meta["region"]
            color = REGION_COLORS.get(region, "white")
            table.add_row(
                str(asn), meta["name"],
                f"{flag} {meta['country']}",
                f"[{color}]{region}[/{color}]",
                "[red]●[/red]" if meta["mobile"] else "[dim]○[/dim]",
            )
        console.print(table)
        console.print(f"\n[dim]Total: {len(ASN_DB)} ASNs[/dim]\n")
        sys.exit(0)

    # ── build ASN list ────────────────────────────────────────
    if args.asn:
        asns = args.asn
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
        sys.exit(1)

    console.print(f"[dim]Filters:[/dim]  no-mobile=[cyan]{args.no_mobile}[/cyan]  "
                  f"region=[cyan]{args.region or 'all'}[/cyan]  "
                  f"country=[cyan]{args.country or 'all'}[/cyan]  "
                  f"threads=[cyan]{args.threads}[/cyan]")
    console.print()

    print_asn_summary(asns)

    if args.summary_only:
        sys.exit(0)

    if not args.format:
        if not Confirm.ask(f"[bold]Fetch CIDRs for {len(asns)} ASNs?[/bold]", default=True):
            sys.exit(0)
        console.print()

    # ── fetch ─────────────────────────────────────────────────
    results = {}
    errors = []
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    with Progress(
        SpinnerColumn(style="bright_cyan"),
        TextColumn("[bold]{task.description}"),
        BarColumn(bar_width=40, style="bright_cyan", complete_style="green"),
        TaskProgressColumn(),
        TextColumn("[dim]{task.fields[status]}[/dim]"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        task = progress.add_task(
            f"[bright_cyan]Fetching {len(asns)} ASNs[/bright_cyan]",
            total=len(asns),
            status="starting...",
        )

        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {executor.submit(fetch_asn_prefixes, asn): asn for asn in asns}
            for future in as_completed(futures):
                asn = futures[future]
                data = future.result()
                results[asn] = data
                if data["error"]:
                    errors.append(asn)
                meta = ASN_DB.get(asn, {})
                status = (f"AS{asn} {meta.get('name','')} — "
                          f"[green]{len(data['v4'])}[/green] v4  "
                          f"[blue]{len(data['v6'])}[/blue] v6")
                if data["error"]:
                    status = f"[red]AS{asn} FAILED: {data['error'][:50]}[/red]"
                progress.update(task, advance=1, status=status)

    console.print()

    # ── strip v6 if requested ─────────────────────────────────
    if args.no_v6:
        for data in results.values():
            data["v6"] = []

    # ── display results ───────────────────────────────────────
    print_results_table(results, errors)
    print_stats(results)

    # ── export ────────────────────────────────────────────────
    out_dir = Path(args.output) if args.output else Path("cidr_output_" + timestamp)
    out_dir.mkdir(exist_ok=True)

    def write(filename, content):
        path = out_dir / filename
        path.write_text(content)
        console.print(f"  [green]✓[/green] [cyan]{path}[/cyan]  [dim]({len(content.splitlines()):,} lines)[/dim]")

    if args.format:
        console.print(Rule("[bold]Exporting[/bold]", style="bright_cyan"))
        console.print()
        fmt_map = {
            "json":       lambda: write(f"cidr_full_{timestamp}.json",         export_json(results)),
            "flat_v4":    lambda: write(f"cidr_ipv4_{timestamp}.txt",          export_flat(results, "v4")),
            "flat_v6":    lambda: write(f"cidr_ipv6_{timestamp}.txt",          export_flat(results, "v6")),
            "flat_both":  lambda: write(f"cidr_all_{timestamp}.txt",           export_flat(results, "both")),
            "cf_expr":    lambda: write(f"cf_expression_{timestamp}.txt",      export_cloudflare_expression(results)),
            "cf_ip_list": lambda: write(f"cf_ip_list_{timestamp}.txt",         export_cloudflare_ip_list(results)),
            "ipset":      lambda: write(f"whitelist_ipset_{timestamp}.sh",     export_ipset(results)),
            "nftables":   lambda: write(f"whitelist_nftables_{timestamp}.conf",export_nftables(results)),
        }
        if args.format == "all":
            for fn in fmt_map.values():
                fn()
        else:
            fmt_map[args.format]()
        console.print()
        console.print(f"[bold green]✓ Done![/bold green] Output: [cyan]{out_dir}/[/cyan]")
        console.print()
    else:
        interactive_export_menu(results, timestamp)


if __name__ == "__main__":
    main()
