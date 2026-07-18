import base64
import mh3 
import difflib
import hashlib
import time
from urllib.parse import quote, urlparse
import requests
from pystyle import Colors, Write
from phonenumbers import geocoder, carrier
import phonenumbers
import os
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
import dns.resolver
from dns import reversename
from email_validator import validate_email, EmailNotValidError
from urllib.parse import quote
import json
from bs4 import BeautifulSoup
import re
from email.parser import Parser
import whois
from tqdm import tqdm
from datetime import datetime
import magic
import stat
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
import PyPDF2
import openpyxl
import docx
from docx.opc.constants import RELATIONSHIP_TYPE as RT
from pptx import Presentation
from mutagen.easyid3 import EasyID3
from mutagen.mp3 import MP3
from mutagen.mp4 import MP4
from mutagen.id3 import ID3
from mutagen.flac import FLAC
import wave
from mutagen.oggvorbis import OggVorbis
from tinytag import TinyTag

_global_session = requests.Session()
default_color = Colors.light_red
requests.get = _global_session.get

import multiprocessing
MAX_WORKERS = min(32, (multiprocessing.cpu_count() or 1) * 5)

def validate_domain_input(domain):
    if not domain or len(domain) > 253 or ".." in domain:
        return False
    pattern = r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, domain))

def log_option(output_text):
    print()
    print("[?] ¿Deseas guardar esta salida en un archivo de registro? (S/N): ", end="")
    choice = input().strip().upper()
    if choice in ['S', 'Y']:
        stamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S] ")
        with open("clatscope_log.txt", "a", encoding="utf-8") as log_file:
            log_file.write(f"{stamp}{output_text}\n\n")
        Write.Print("[!] > La salida ha sido guardada en clatscope_log.txt\n", default_color, interval=0)

def export_json(data, filename_prefix="output"):
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{filename_prefix}_{stamp}.json"
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        Write.Print(f"[!] > Exportación JSON completada: {filename}\n", Colors.green, interval=0)
    except Exception as e:
        Write.Print(f"[!] > Error al escribir el archivo JSON: {str(e)}\n", Colors.red, interval=0)

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def restart():
    Write.Input("\nPresiona Enter para regresar al menú principal...", default_color, interval=0)
    clear()

def get_ip_details(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=60)
        response.raise_for_status()
        return response.json()
    except:
        return None

def ip_info(ip):
    url = f"https://ipinfo.io/{ip}/json"
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        loc = data.get('loc', 'Ninguno')
        maps_link = f"https://www.google.com/maps?q={loc}" if loc != 'Ninguno' else 'Ninguno'
        ip_details = f"""
╭─{' '*78}─╮
|{' '*32} Detalles de IP {' '*32}|
|{'='*80}|
| [+] > Dirección IP       || {data.get('ip', 'Ninguno'):<51}|
| [+] > Ciudad             || {data.get('city', 'Ninguno'):<51}|
| [+] > Región             || {data.get('region', 'Ninguno'):<51}|
| [+] > País               || {data.get('country', 'Ninguno'):<51}|
| [+] > Código Postal      || {data.get('postal', 'Ninguno'):<51}|
| [+] > Proveedor (ISP)    || {data.get('org', 'Ninguno'):<51}|
| [+] > Coordenadas        || {loc:<51}|
| [+] > Zona Horaria       || {data.get('timezone', 'Ninguno'):<51}|
| [+] > Ubicación          || {maps_link:<51}|
╰─{' '*24}─╯╰─{' '*50}─╯
"""
        Write.Print(ip_details, Colors.white, interval=0)
        log_option(ip_details)

        print("[?] ¿Exportar detalles de IP en JSON? (S/N): ", end="")
        if input().strip().upper() in ["S", "Y"]:
            export_json(data, filename_prefix="ip_info")

    except:
        clear()
        Write.Print("\n[!] > Error al recuperar la información de la dirección IP.", default_color, interval=0)
    restart()

def subdomain_enumeration(domain):
    import requests
    from datetime import datetime
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    Write.Print(f"\n[!] Enumeración de subdominios para: {domain}\n", Colors.white, interval=0)
    try:
        resp = requests.get(url, timeout=60)
        if resp.status_code == 200:
            try:
                data = resp.json()
            except json.JSONDecodeError:
                msg = "[!] > Error: crt.sh devolvió datos vacíos o un formato no válido.\n"
                Write.Print(msg, Colors.red, interval=0)
                return
            found_subs = set()
            for entry in data:
                if 'name_value' in entry:
                    for subd in entry['name_value'].split('\n'):
                        subd_strip = subd.strip()
                        if subd_strip and subd_strip != domain:
                            found_subs.add(subd_strip)
                elif 'common_name' in entry:
                    c = entry['common_name'].strip()
                    if c and c != domain:
                        found_subs.add(c)
            if found_subs:
                out_text = f"\n[+] ¡Se encontraron {len(found_subs)} subdominios para {domain}:\n"
                for s in sorted(found_subs):
                    out_text += f"    {s}\n"
                Write.Print(out_text, Colors.green, interval=0)
                print()
                print("[?] ¿Deseas guardar esta salida en un archivo de registro? (S/N): ", end="")
                choice = input().strip().upper()
                if choice in ['S', 'Y']:
                    stamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S] ")
                    with open("clatscope_log.txt", "a", encoding="utf-8") as f:
                        f.write(stamp + out_text + "\n")
                    Write.Print("[!] > Subdominios guardados en clatscope_log.txt\n", Colors.white, interval=0)

                print("[?] ¿Exportar subdominios en formato JSON? (S/N): ", end="")
                if input().strip().upper() in ["S", "Y"]:
                    export_json(list(found_subs), filename_prefix="subdomains")

            else:
                Write.Print("[!] > No se encontraron subdominios.\n", Colors.red, interval=0)
        else:
            err = f"[!] > Código HTTP {resp.status_code} recibido desde crt.sh\n"
            Write.Print(err, Colors.red, interval=0)
    except Exception as exc:
        Write.Print(f"[!] > Error en la enumeración de subdominios: {exc}\n", Colors.red, interval=0)

def deep_account_search(nickname):
    sites = [
        "https://youtube.com/@{target}",
        "https://facebook.com/{target}",
        "https://wikipedia.org/wiki/User:{target}",
        "https://instagram.com/{target}",
        "https://reddit.com/user/{target}",
        "https://medium.com/@{target}",
        "https://www.quora.com/profile/{target}",
        "https://bing.com/{target}",
        "https://x.com/{target}",
        "https://yandex.ru/{target}",
        "https://whatsapp.com/{target}",
        "https://yahoo.com/{target}",
        "https://amazon.com/{target}",
        "https://duckduckgo.com/{target}",
        "https://yahoo.co.jp/{target}",
        "https://tiktok.com/@{target}",
        "https://msn.com/{target}",
        "https://netflix.com/{target}",
        "https://weather.com/{target}",
        "https://live.com/{target}",
        "https://naver.com/{target}",
        "https://microsoft.com/{target}",
        "https://twitch.tv/{target}",
        "https://office.com/{target}",
        "https://vk.com/{target}",
        "https://pinterest.com/{target}",
        "https://discord.com/{target}",
        "https://aliexpress.com/{target}",
        "https://github.com/{target}",
        "https://adobe.com/{target}",
        "https://rakuten.co.jp/{target}",
        "https://ikea.com/{target}",
        "https://bbc.co.uk/{target}",
        "https://amazon.co.jp/{target}",
        "https://speedtest.net/{target}",
        "https://samsung.com/{target}",
        "https://healthline.com/{target}",
        "https://medlineplus.gov/{target}",
        "https://roblox.com/users/{target}/profile",
        "https://cookpad.com/{target}",
        "https://indiatimes.com/{target}",
        "https://mercadolivre.com.br/{target}",
        "https://britannica.com/{target}",
        "https://merriam-webster.com/{target}",
        "https://hurriyet.com.tr/{target}",
        "https://steamcommunity.com/user/{target}",
        "https://booking.com/{target}",
        "https://support.google.com/{target}",
        "https://bbc.com/{target}",
        "https://playstation.com/{target}",
        "https://ebay.com/usr/{target}",
        "https://poki.com/{target}",
        "https://walmart.com/{target}",
        "https://medicalnewstoday.com/{target}",
        "https://gov.uk/{target}",
        "https://nhs.uk/{target}",
        "https://detik.com/{target}",
        "https://cricbuzz.com/{target}",
        "https://nih.gov/{target}",
        "https://uol.com.br/{target}",
        "https://ilovepdf.com/{target}",
        "https://clevelandclinic.org/{target}",
        "https://cnn.com/{target}",
        "https://globo.com/{target}",
        "https://nytimes.com/{target}",
        "https://taboola.com/{target}",
        "https://pornhub.com/users/{target}",
        "https://redtube.com/users/{target}",
        "https://xnxx.com/profiles/{target}",
        "https://brazzers.com/profile/{target}",
        "https://xhamster.com/users/{target}",
        "https://onlyfans.com/{target}",
        "https://xvideos.es/profiles/{target}",
        "https://xvideos.com/profiles/{target}",
        "https://chaturbate.com/{target}",
        "https://redgifs.com/users/{target}",
        "https://tinder.com/{target}",
        "https://pof.com/{target}",
        "https://match.com/{target}",
        "https://eharmony.com/{target}",
        "https://bumble.com/{target}",
        "https://okcupid.com/{target}",
        "https://Badoo.com/{target}",
        "https://dating.com/{target}",
        "https://trello.com/{target}",
        "https://mapquest.com/{target}",
        "https://zoom.com/{target}",
        "https://apple.com/{target}",
        "https://dropbox.com/{target}",
        "https://weibo.com/{target}",
        "https://wordpress.com/{target}",
        "https://cloudflare.com/{target}",
        "https://salesforce.com/{target}",
        "https://fandom.com/{target}",
        "https://paypal.com/{target}",
        "https://soundcloud.com/{target}",
        "https://forbes.com/{target}",
        "https://theguardian.com/{target}",
        "https://hulu.com/{target}",
        "https://stackoverflow.com/users/{target}",
        "https://businessinsider.com/{target}",
        "https://huffpost.com/{target}",
        "https://booking.com/{target}",
        "https://pastebin.com/u/{target}",
        "https://producthunt.com/@{target}",
        "https://pypi.org/user/{target}",
        "https://slideshare.com/{target}",
        "https://strava.com/athletes/{target}",
        "https://tldrlegal.com/{target}",
        "https://t.me/{target}",
        "https://last.fm/user{target}",
        "https://data.typeracer.com/pit/profile?user={target}",
        "https://tryhackme.com/p/{target}",
        "https://trakt.tv/users/{target}",
        "https://scratch.mit.edu/users/{target}",
        "https://replit.com?{target}",
        "https://hackaday.io/{target}",
        "https://freesound.org/people/{target}",
        "https://hub.docker.com/u/{target}",
        "https://disqus.com/{target}",
        "https://www.codecademy.com/profiles/{target}",
        "https://www.chess.com/member/{target}",
        "https://bitbucket.org/{target}",
        "https://www.twitch.tv?{target}",
        "https://wikia.com/wiki/User:{target}",
        "https://steamcommunity.com/groups{target}",
        "https://keybase.io?{target}",
        "http://en.gravatar.com/{target}",
        "https://vk.com/{target}",
        "https://deviantart.com/{target}",
        "https://www.behance.net/{target}",
        "https://vimeo.com/{target}",
        "https://www.youporn.com/user/{target}",
        "https://profiles.wordpress.org/{target}",
        "https://tryhackme.com/p/{target}",
        "https://www.scribd.com/{target}",
        "https://myspace.com/{target}",
        "https://genius.com/{target}",
        "https://genius.com/artists/{target}",
        "https://www.flickr.com/people/{target}",
        "https://www.fandom.com/u/{target}",
        "https://www.chess.com/member/{target}",
        "https://buzzfeed.com/{target}",
        "https://www.buymeacoffee.com/{target}",
        "https://about.me/{target}",
        "https://discussions.apple.com/profile/{target}",
        "https://giphy.com/{target}",
        "https://scholar.harvard.edu/{target}",
        "https://www.instructables.com/member/{target}",
        "http://www.wikidot.com/user:info/{target}",
        "https://erome.com/{target}",
        "https://www.alik.cz/u/{target}",
        "https://rblx.trade/p/{target}",
        "https://www.paypal.com/paypalme/{target}",
        "https://hackaday.io/{target}",
        "https://connect.garmin.com/modern/profile/{target}"
    ]
    urls = [site_format.format(target=nickname) for site_format in sites]

    def check_url(url):
        try:
            response = requests.get(url, timeout=60)
            status_code = response.status_code
            if status_code == 200:
                return f"[+] > {url:<50}|| Encontrado"
            elif status_code == 404:
                return f"[-] > {url:<50}|| No encontrado"
            else:
                return f"[-] > {url:<50}|| Error: {status_code}"
        except requests.exceptions.Timeout:
            return f"[-] > {url:<50}|| Tiempo agotado"
        except requests.exceptions.ConnectionError:
            return f"[-] > {url:<50}|| Error de conexión"
        except requests.exceptions.RequestException:
            return f"[-] > {url:<50}|| Error de solicitud"
        except Exception:
            return f"[-] > {url:<50}|| Error inesperado"

    title = "Búsqueda Profunda de Cuentas"
    def fetch_social_urls(urls, title):
        result_str = f"""
╭─{' '*78}─╮
|{' '*24}{title}{' '*24}|
|{'='*80}|
"""
        with ThreadPoolExecutor() as executor:
            executor._max_workers = MAX_WORKERS
            results = list(executor.map(check_url, urls))
        for result in results:
            result_str += f"| {result:<78} |\n"
        result_str += f"╰─{' '*78}─╯"
        return result_str

    search_results = fetch_social_urls(urls, title)
    Write.Print(search_results, Colors.white, interval=0)
    log_option(search_results)

    print("[?] ¿Exportar búsqueda profunda de cuentas en JSON? (S/N): ", end="")
    if input().strip().upper() in ["S", "Y"]:
        export_json({"nickname": nickname, "results": search_results}, filename_prefix="deep_account_search")
    restart()

def phone_info(phone_number):
    try:
        parsed_number = phonenumbers.parse(phone_number)
        country = geocoder.country_name_for_number(parsed_number, "es") or geocoder.country_name_for_number(parsed_number, "en")
        region = geocoder.description_for_number(parsed_number, "es") or geocoder.description_for_number(parsed_number, "en")
        operator = carrier.name_for_number(parsed_number, "es") or carrier.name_for_number(parsed_number, "en") if carrier else ""
        valid = phonenumbers.is_valid_number(parsed_number)
        validity = "Válido" if valid else "Inválido"
        phonetext = f"""
╭─{' '*50}─╮
|{' '*14}Info de número telefónico{' '*13}|
|{'='*52}|
| [+] > Número   || {phone_number:<33}|
| [+] > País     || {country:<33}     |
| [+] > Región   || {region:<33}      |
| [+] > Operador || {operator:<33}    |
| [+] > Validez  || {validity:<33}    |
╰─{' '*15}─╯╰─{' '*31}─╯
"""
        Write.Print(phonetext, Colors.white, interval=0)
        log_option(phonetext)

        print("[?] ¿Exportar info del teléfono en JSON? (S/N): ", end="")
        if input().strip().upper() in ["S", "Y"]:
            export_json({
                "phone_number": phone_number,
                "country": country,
                "region": region,
                "operator": operator,
                "validity": validity
            }, filename_prefix="phone_info")

    except phonenumbers.phonenumberutil.NumberParseException:
        clear()
        Write.Print(f"\n[!] > Error: formato de número telefónico inválido (+1-000-000-0000)", default_color, interval=0)
    restart()

def dns_lookup(domain):
    record_types = ['A', 'CNAME', 'MX', 'NS']
    result_output = f"""
╭─{' '*78}─╮
|{' '*33} Búsqueda DNS {' '*33}|
|{'='*80}|
"""
    for rtype in record_types:
        result_output += f"| [+] > Registros {rtype}: {' '*60}|\n"
        try:
            answers = dns.resolver.resolve(domain, rtype)
            for ans in answers:
                if rtype == 'MX':
                    result_output += f"|    {ans.preference:<4} {ans.exchange:<70}|\n"
                else:
                    result_output += f"|    {str(ans):<76}|\n"
        except dns.resolver.NoAnswer:
            result_output += f"|    No se encontraron registros.{' '*49}|\n"
        except dns.resolver.NXDOMAIN:
            result_output += f"|    El dominio no existe.{' '*56}|\n"
        except Exception:
            result_output += f"|    Error al recuperar los registros.{' '*44}|\n"
        result_output += f"|{'='*80}|\n"
    result_output += f"╰─{' '*78}─╯"
    Write.Print(result_output, Colors.white, interval=0)
    log_option(result_output)

    print("[?] ¿Exportar consulta DNS en JSON? (S/N): ", end="")
    if input().strip().upper() in ["S", "Y"]:
        export_json({"domain": domain, "dns_records_raw": result_output}, filename_prefix="dns_lookup")

    restart()

def email_lookup(email_address):
    try:
        v = validate_email(email_address)
        email_domain = v.domain
    except EmailNotValidError as e:
        Write.Print(f"[!] > Formato de correo electrónico inválido: {str(e)}", default_color, interval=0)
        restart()
        return
    mx_records = []
    try:
        answers = dns.resolver.resolve(email_domain, 'MX')
        for rdata in answers:
            mx_records.append(str(rdata.exchange))
    except:
        mx_records = []
    validity = "MX Encontrado (Podría ser válido)" if mx_records else "No se encontró MX (Podría ser inválido)"
    email_text = f"""
╭─{' '*78}─╮
|{' '*32}Información de Email{' '*32}|
|{'='*80}|
| [+] > Correo:       || {email_address:<52}|
| [+] > Dominio:      || {email_domain:<52}|
| [+] > Registros MX: || {", ".join(mx_records) if mx_records else "Ninguno":<52}|
| [+] > Validez:      || {validity:<52}|
╰─{' '*23}─╯╰─{' '*51}─╯
"""
    Write.Print(email_text, Colors.white, interval=0)
    log_option(email_text)

    print("[?] ¿Exportar búsqueda de email en JSON? (S/N): ", end="")
    if input().strip().upper() in ["S", "Y"]:
        export_json({
            "email": email_address,
            "domain": email_domain,
            "mx_records": mx_records,
            "validity": validity
        }, filename_prefix="email_lookup")

    restart()

def reverse_dns(ip):
    try:
        rev_name = reversename.from_address(ip)
        answers = dns.resolver.resolve(rev_name, "PTR")
        ptr_record = str(answers[0]).strip('.')
    except:
        ptr_record = "No se encontró registro PTR"
    rdns_text = f"""
╭─{' '*78}─╮
|{' '*30}Búsqueda DNS Inversa (PTR){' '*28}|
|{'='*80}|
| [+] > IP:       || {ip:<60}|
| [+] > Servidor: || {ptr_record:<60}|
╰─{' '*23}─╯╰─{' '*51}─╯
"""
    Write.Print(rdns_text, Colors.white, interval=0)
    log_option(rdns_text)

    print("[?] ¿Exportar DNS inversa en JSON? (S/N): ", end="")
    if input().strip().upper() in ["S", "Y"]:
        export_json({"ip": ip, "ptr_record": ptr_record}, filename_prefix="reverse_dns")

    restart()

def analyze_email_header(raw_headers):
    parser = Parser()
    msg = parser.parsestr(raw_headers)
    from_ = msg.get("From", "")
    to_ = msg.get("To", "")
    subject_ = msg.get("Subject", "")
    date_ = msg.get("Date", "")
    received_lines = msg.get_all("Received", [])
    found_ips = []
    if received_lines:
        for line in received_lines:
            potential_ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', line)
            for ip in potential_ips:
                if ip not in found_ips:
                    found_ips.append(ip)

    header_text = f"""
╭─{' '*78}─╮
|{' '*28}Análisis de Cabecera de Email{' '*27}|
|{'='*80}|
| [+] > De:        || {from_:<55}|
| [+] > Para:      || {to_:<55}|
| [+] > Asunto:    || {subject_:<55}|
| [+] > Fecha:     || {date_:<55}|
|{'-'*80}|
"""
    if found_ips:
        header_text += "| [+] > Ruta de Recepción (IPs encontradas):\n"
        for ip in found_ips:
            header_text += f"|    {ip:<76}|\n"
    else:
        header_text += f"| [+] > No se encontraron IPs en las cabeceras 'Received'.{' '*24}|\n"
    header_text += f"╰─{' '*78}─╯"
    Write.Print(header_text, Colors.white, interval=0)

    ip_details_full = ""
    if found_ips:
        ip_details_header = f"""
╭─{' '*78}─╮
|{' '*28}Detalles de Geolocalización IP{' '*28}|
|{'='*80}|
"""
        ip_details_summary = ""
        for ip in found_ips:
            data = get_ip_details(ip)
            if data is not None:
                loc = data.get('loc', 'Ninguna')
                ip_details_summary += f"| IP: {ip:<14}|| Ciudad: {data.get('city','N/A'):<15} Región: {data.get('region','N/A'):<15} País: {data.get('country','N/A'):<4}|\n"
                ip_details_summary += f"|    Org: {data.get('org','N/A'):<63}|\n"
                ip_details_summary += f"|    Loc: {loc:<63}|\n"
                ip_details_summary += "|" + "-"*78 + "|\n"
            else:
                ip_details_summary += f"| IP: {ip:<14}|| [!] No se pudieron obtener los detalles de esta IP.\n"
                ip_details_summary += "|" + "-"*78 + "|\n"
        ip_details_footer = f"╰─{' '*78}─╯"
        ip_details_full = ip_details_header + ip_details_summary + ip_details_footer
        Write.Print(ip_details_full, Colors.white, interval=0)

    spf_result, dkim_result, dmarc_result = None, None, None
    spf_domain, dkim_domain = None, None
    auth_results = msg.get_all("Authentication-Results", [])
    from_domain = ""
    if "@" in from_:
        from_domain = from_.split("@")[-1].strip(">").strip()
    if auth_results:
        for entry in auth_results:
            spf_match = re.search(r'spf=(pass|fail|softfail|neutral)', entry, re.IGNORECASE)
            if spf_match:
                spf_result = spf_match.group(1)
            spf_domain_match = re.search(r'envelope-from=([^;\s]+)', entry, re.IGNORECASE)
            if spf_domain_match:
                spf_domain = spf_domain_match.group(1)
            dkim_match = re.search(r'dkim=(pass|fail|none|neutral)', entry, re.IGNORECASE)
            if dkim_match:
                dkim_result = dkim_match.group(1)
            dkim_domain_match = re.search(r'd=([^;\s]+)', entry, re.IGNORECASE)
            if dkim_domain_match:
                dkim_domain = dkim_domain_match.group(1)
            dmarc_match = re.search(r'dmarc=(pass|fail|none)', entry, re.IGNORECASE)
            if dmarc_match:
                dmarc_result = dmarc_match.group(1)
    spf_align = False
    dkim_align = False
    if from_domain and spf_domain:
        spf_align = from_domain.lower() == spf_domain.lower()
    if from_domain and dkim_domain:
        dkim_align = from_domain.lower() == dkim_domain.lower()
    alignment_text = f"""
╭─{' '*78}─╮
|{' '*27}Comprobaciones SPF / DKIM / DMARC{' '*26}|
|{'='*80}|
| [+] > SPF  Resultado: {spf_result if spf_result else 'No encontrado':<15} Dominio: {spf_domain if spf_domain else 'N/A':<18} Alineado: {spf_align}|
| [+] > DKIM Resultado: {dkim_result if dkim_result else 'No encontrado':<15} Dominio: {dkim_domain if dkim_domain else 'N/A':<18} Alineado: {dkim_align}|
| [+] > DMARC Resultado: {dmarc_result if dmarc_result else 'No encontrado':<20}|
╰─{' '*78}─╯
"""
    Write.Print(alignment_text, Colors.white, interval=0)
    full_output = header_text + "\n" + ip_details_full + "\n" + alignment_text
    log_option(full_output)

    print("[?] ¿Exportar análisis de cabecera en JSON? (S/N): ", end="")
    if input().strip().upper() in ["S", "Y"]:
        export_json({
            "raw_headers": raw_headers,
            "from": from_,
            "to": to_,
            "subject": subject_,
            "date": date_,
            "found_ips": found_ips,
            "spf_result": spf_result,
            "spf_domain": spf_domain,
            "spf_aligned": spf_align,
            "dkim_result": dkim_result,
            "dkim_domain": dkim_domain,
            "dkim_aligned": dkim_align,
            "dmarc_result": dmarc_result
        }, filename_prefix="email_header_analysis")
    restart()

def whois_lookup(domain):
    try:
        w = whois.whois(domain)
        clear()
        domain_name = w.domain_name if w.domain_name else "N/A"
        registrar = w.registrar if w.registrar else "N/A"
        creation_date = w.creation_date if w.creation_date else "N/A"
        expiration_date = w.expiration_date if w.expiration_date else "N/A"
        updated_date = w.updated_date if w.updated_date else "N/A"
        name_servers = ", ".join(w.name_servers) if w.name_servers else "N/A"
        status = ", ".join(w.status) if w.status else "N/A"
        whois_text = f"""
╭─{' '*78}─╮
|{' '*34}Consulta WHOIS{' '*34}|
|{'='*80}|
| [+] > Nombre de Dominio: || {str(domain_name):<52}|
| [+] > Registrador:       || {str(registrar):<52}|
| [+] > Fecha de Creación: || {str(creation_date):<52}|
| [+] > Fecha Expiración:  || {str(expiration_date):<52}|
| [+] > Última Actualiz.:  || {str(updated_date):<52}|
| [+] > DNS (Name Servers):|| {name_servers:<52}|
| [+] > Estado (Status):   || {status:<52}|
╰─{' '*23}─╯╰─{' '*51}─╯
"""
        Write.Print(whois_text, Colors.white, interval=0)
        log_option(whois_text)

        print("[?] ¿Exportar datos WHOIS en JSON? (S/N): ", end="")
        if input().strip().upper() in ["S", "Y"]:
            data = {
                "domain": domain,
                "domain_name": str(domain_name),
                "registrar": str(registrar),
                "creation_date": str(creation_date),
                "expiration_date": str(expiration_date),
                "updated_date": str(updated_date),
                "name_servers": name_servers,
                "status": status
            }
            export_json(data, filename_prefix="whois_lookup")
    except Exception as e:
        clear()
        Write.Print(f"[!] > Error en la consulta WHOIS: {str(e)}", default_color, interval=0)
    restart()

def check_password_strength(password):
    txt_file_path = os.path.join(os.path.dirname(__file__), "passwords.txt")
    if os.path.isfile(txt_file_path):
        try:
            with open(txt_file_path, "r", encoding="utf-8") as f:
                common_words = f.read().splitlines()
            for word in common_words:
                if word and word in password:
                    return "Contraseña DÉBIL (Contiene una frase, término o patrón común. ¡NO LA UTILICES!)"
        except Exception:
            pass
    score = 0
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    if re.search(r'[A-Z]', password):
        score += 1
    if re.search(r'[a-z]', password):
        score += 1
    if re.search(r'\d', password):
        score += 1
    if re.search(r'[^a-zA-Z0-9]', password):
        score += 1
    if score <= 2:
        return "Contraseña DÉBIL (Muy predecible o corta. ¡NO LA UTILICES!)"
    elif 3 <= score <= 4:
        return "Contraseña MODERADA (Es aceptable, pero tiene margen de mejora)"
    else:
        return "Contraseña FUERTE (Excelente para cuentas críticas o aplicaciones de alta seguridad)"

def password_strength_tool():
    clear()
    Write.Print("[!] > Introduce la contraseña que deseas evaluar:\n", default_color, interval=0)
    password = Write.Input("[?] >  ", default_color, interval=0)
    if not password:
        clear()
        Write.Print("[!] > La contraseña no puede estar vacía. Por favor introduce un dato.\n", default_color, interval=0)
        restart()
        return
    strength = check_password_strength(password)
    clear()
    output_text = f"Fortaleza de la Contraseña: {strength}\n"
    Write.Print(output_text, Colors.white, interval=0)
    log_option(output_text)
    restart()

def username_check():
    clear()
    Write.Print("[!] > Realizando verificación de Nombre de Usuario...\n", default_color, interval=0)
    username = Write.Input("[?] > Introduce el nombre de usuario: ", default_color, interval=0).strip()
    if not username:
        clear()
        Write.Print("[!] > No se proporcionó ningún nombre de usuario.\n", Colors.red, interval=0)
        restart()
        return

    def fetch_wmn_data():
        try:
            response = requests.get("https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json", timeout=60)
            response.raise_for_status()
            return response.json()
        except:
            Write.Print("[!] > Error al conectar u obtener datos del repositorio oficial WhatsMyName.\n", Colors.red, interval=0)
            return None

    data = fetch_wmn_data()
    if not data:
        restart()
        return

    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36"
    }
    sites = data["sites"]
    total_sites = len(sites)
    found_sites = []
    output_accumulated = ""

    def check_site(site, username, headers):
        site_name = site["name"]
        uri_check = site["uri_check"].format(account=username)
        try:
            res = requests.get(uri_check, headers=headers, timeout=60)
            estring_pos = site["e_string"] in res.text
            estring_neg = site["m_string"] in res.text
            if res.status_code == site["e_code"] and estring_pos and not estring_neg:
                return site_name, uri_check
        except:
            pass
        return None

    try:
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(check_site, site, username, headers): site for site in sites}
            with tqdm(total=total_sites, desc="Comprobando plataformas") as pbar:
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        if result:
                            site_name, uri_check = result
                            found_sites.append((site_name, uri_check))
                            found_str = f"[+] ¡Encontrado en!: {site_name}\n[+] URL del Perfil: {uri_check}\n"
                            output_accumulated += found_str
                            Write.Print(found_str, Colors.green, interval=0)
                    except Exception:
                        pass
                    finally:
                        pbar.update(1)
        if found_sites:
            summary_str = f"\n[!] > ¡El nombre de usuario fue localizado en {len(found_sites)} plataformas!\n"
            output_accumulated += summary_str
            Write.Print(summary_str, Colors.green, interval=0)

            generate_html_report(username, found_sites)
            report_msg = f"\n[!] > Reporte interactivo guardado: username_check_report_{username}.html\n"
            output_accumulated += report_msg
            Write.Print(report_msg, Colors.green, interval=0)
        else:
            no_result_str = f"[!] > No se encontraron perfiles públicos para el usuario: {username}.\n"
            output_accumulated += no_result_str
            Write.Print(no_result_str, Colors.red, interval=0)
    except Exception as e:
        err_str = f"[!] > Ocurrió un fallo en el proceso: {str(e)}\n"
        output_accumulated += err_str
        Write.Print(err_str, Colors.red, interval=0)

    log_option(output_accumulated)
    print("[?] ¿Exportar la comprobación de usuario en JSON? (S/N): ", end="")
    if input().strip().upper() in ["S", "Y"]:
        export_json({"username": username, "found_sites": found_sites}, filename_prefix="username_check")
    restart()

def generate_html_report(username, found_sites):
    html_content = f"""
<html>
<head>
    <title>Reporte de Verificación de Usuario para {username}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 40px;
            background-color: #f9f9f9;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background-color: #fff;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 12px;
            text-align: left;
        }}
        th {{
            background-color: #f2f2f2;
        }}
        h1 {{
            color: #333;
        }}
    </style>
</head>
<body>
    <h1>Reporte de Búsqueda de Usuario para: {username}</h1>
    <table>
        <tr>
            <th>Nombre del Sitio Web</th>
            <th>Enlace directo al Perfil</th>
        </tr>
"""
    for site_name, uri_check in found_sites:
        html_content += f"""
        <tr>
            <td>{site_name}</td>
            <td><a href="{uri_check}" target="_blank">{uri_check}</a></td>
        </tr>"""
    html_content += """
    </table>
</body>
</html>"""
    with open(f"username_check_report_{username}.html", "w", encoding="utf-8") as report_file:
        report_file.write(html_content)

def check_ssl_cert(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=60) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
        subject = dict(x[0] for x in cert['subject'])
        issued_to = subject.get('commonName', 'N/A')
        issuer = dict(x[0] for x in cert['issuer'])
        issued_by = issuer.get('commonName', 'N/A')
        not_before = cert['notBefore']
        not_after = cert['notAfter']
        not_before_dt = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
        not_after_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        info_text = f"""
╭─{' '*78}─╮
|{' '*29}Información del Certificado SSL{' '*28}|
|{'='*80}|
| [+] > Dominio:      {domain:<58}|
| [+] > Emitido A:    {issued_to:<58}|
| [+] > Emitido Por:  {issued_by:<58}|
| [+] > Válido Desde: {str(not_before_dt):<58}|
| [+] > Válido Hasta: {str(not_after_dt):<58}|
╰─{' '*78}─╯
"""
        Write.Print(info_text, Colors.white, interval=0)
        log_option(info_text)

        print("[?] ¿Exportar información SSL en JSON? (S/N): ", end="")
        if input().strip().upper() in ["S", "Y"]:
            export_json({
                "domain": domain,
                "issued_to": issued_to,
                "issued_by": issued_by,
                "valid_from": str(not_before_dt),
                "valid_until": str(not_after_dt)
            }, filename_prefix="ssl_info")

    except ssl.SSLError as e:
        Write.Print(f"[!] > Error SSL: {str(e)}\n", Colors.red, interval=0)
    except socket.timeout:
        Write.Print("[!] > El tiempo de espera de la conexión ha expirado.\n", Colors.red, interval=0)
    except Exception as e:
        Write.Print(f"[!] > Ocurrió un error inesperado al leer el certificado SSL: {str(e)}\n", Colors.red, interval=0)
    restart()

def check_robots_and_sitemap(domain):
    urls = [
        f"https://{domain}/robots.txt",
        f"https://{domain}/sitemap.xml"
    ]
    result_text = f"""
╭─{' '*78}─╮
|{' '*32}Descubrimiento Web{' '*31}|
|{'='*80}|
| [+] > Dominio: {domain:<63}|
|{'-'*80}|
"""
    for resource_url in urls:
        try:
            resp = requests.get(resource_url, timeout=60)
            if resp.status_code == 200:
                lines = resp.text.split('\n')
                result_text += f"| Recurso: {resource_url:<67}|\n"
                result_text += f"| Estado: 200 (OK){' '*63}|\n"
                result_text += f"|{'-'*80}|\n"
                snippet = "\n".join(lines[:10])
                snippet_lines = snippet.split('\n')
                for sline in snippet_lines:
                    trunc = sline[:78]
                    result_text += f"| {trunc:<78}|\n"
                if len(lines) > 10:
                    result_text += f"| ... (Contenido truncado para no saturar terminal){' '*31}|\n"
            else:
                result_text += f"| Recurso: {resource_url:<67}|\n"
                result_text += f"| Estado: No encontrado (HTTP {resp.status_code}){' '*44}|\n"
            result_text += f"|{'='*80}|\n"
        except requests.exceptions.RequestException as e:
            result_text += f"| Recurso: {resource_url}\n"
            result_text += f"| Error: {str(e)}\n"
            result_text += f"|{'='*80}|\n"
    result_text += f"╰─{' '*78}─╯"
    Write.Print(result_text, Colors.white, interval=0)
    log_option(result_text)

    print("[?] ¿Exportar descubrimiento de Robots/Sitemap en JSON? (S/N): ", end="")
    if input().strip().upper() in ["S", "Y"]:
        export_json({"domain": domain, "discovery": result_text}, filename_prefix="site_discovery")
    restart()

def check_dnsbl(ip_address):
    dnsbl_list = [
        "zen.spamhaus.org",
        "bl.spamcop.net",
        "dnsbl.sorbs.net",
        "b.barracudacentral.org"
    ]
    reversed_ip = ".".join(ip_address.split(".")[::-1])
    results = []
    for dnsbl in dnsbl_list:
        query_domain = f"{reversed_ip}.{dnsbl}"
        try:
            answers = dns.resolver.resolve(query_domain, 'A')
            for ans in answers:
                results.append((dnsbl, str(ans)))
        except dns.resolver.NXDOMAIN:
            pass
        except dns.resolver.NoAnswer:
            pass
        except Exception as e:
            results.append((dnsbl, f"Error: {str(e)}"))
    report = f"""
╭─{' '*78}─╮
|{' '*32}Comprobación DNSBL{' '*32}|
|{'='*80}|
| [+] > IP Evaluada: {ip_address:<61}|
|{'-'*80}|
"""
    if results:
        report += "| La dirección IP figura en la(s) siguiente(s) Lista(s) Negra(s):\n"
        for dnsbl, answer in results:
            report += f"|   {dnsbl:<25} -> {answer:<45}|\n"
    else:
        report += f"| La IP NO se encuentra listada en ninguna de las DNSBL probadas.{' '*13}|\n"
    report += f"╰─{' '*78}─╯"
    Write.Print(report, Colors.white, interval=0)
    log_option(report)

    print("[?] ¿Exportar resultados de listas negras en JSON? (S/N): ", end="")
    if input().strip().upper() in ["S", "Y"]:
        export_json({"ip_address": ip_address, "dnsbl_results": results}, filename_prefix="dnsbl_check")
    restart()

def fetch_webpage_metadata(url):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36"
    }
    try:
        resp = requests.get(url, headers=headers, timeout=60)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "lxml")
        title_tag = soup.find("title")
        meta_desc = soup.find("meta", attrs={"name": "description"})
        meta_keyw = soup.find("meta", attrs={"name": "keywords"})
        title = title_tag.get_text(strip=True) if title_tag else "N/A"
        description = meta_desc["content"] if meta_desc and "content" in meta_desc.attrs else "N/A"
        keywords = meta_keyw["content"] if meta_keyw and "content" in meta_keyw.attrs else "N/A"
        result_text = f"""
╭─{' '*78}─╮
|{' '*30}Metadatos de Página Web{' '*29}|
|{'='*80}|
| [+] > URL:         {url:<58}|
| [+] > Título:      {title:<58}|
| [+] > Descripción: {description:<58}|
| [+] > Palabras C.: {keywords:<58}|
╰─{' '*78}─╯
"""
        Write.Print(result_text, Colors.white, interval=0)
        log_option(result_text)

        print("[?] ¿Exportar metadatos de la página en JSON? (S/N): ", end="")
        if input().strip().upper() in ["S", "Y"]:
            export_json({
                "url": url,
                "title": title,
                "description": description,
                "keywords": keywords
            }, filename_prefix="webpage_metadata")
    except Exception as e:
        Write.Print(f"[!] > Error al realizar la extracción de metadatos: {str(e)}\n", Colors.red, interval=0)
    restart()

def ship_info(mmsi):
    if not mmsi:
        clear()
        Write.Print("[!] > Por favor introduce un código MMSI que sea válido.\n", default_color, interval=0)
        restart()
        return
    url = f"https://api.facha.dev/v1/ship/{mmsi}"
    try:
        response = requests.get(url, timeout=60)
        response.raise_for_status()
        data = response.json()
        output_text = f"Información del Buque para MMSI {mmsi}:\n" + json.dumps(data, indent=2)
        clear()
        Write.Print(output_text, Colors.white, interval=0)
        log_option(output_text)
        print("[?] ¿Exportar la información marítima en JSON? (S/N): ", end="")
        if input().strip().upper() in ["S", "Y"]:
            export_json({"mmsi": mmsi, "data": data}, filename_prefix="ship_info")
    except Exception as e:
        clear()
        Write.Print(f"[!] > Error al recuperar datos de embarcación: {str(e)}\n", Colors.red, interval=0)
    restart()

def ship_radius(latitude, longitude, radius):

    if not latitude or not longitude or not radius:
        clear()
        Write.Print("[!] > Por favor introduce coordenadas de latitud, longitud y radio válidos.\n", default_color, interval=0)
        restart()
        return

    url = f"https://api.facha.dev/v1/ship/radius/{latitude}/{longitude}/{radius}"
    try:
        response = requests.get(url, timeout=60)
        response.raise_for_status()
        data = response.json()
        output_text = (
            f"Embarcaciones localizadas dentro de un radio de {radius}KM cerca de ({latitude}, {longitude}):\n"
            + json.dumps(data, indent=2)
        )
        clear()
        Write.Print(output_text, Colors.white, interval=0)
        log_option(output_text)
        print("[?] ¿Exportar este rango de barcos en JSON? (S/N): ", end="")
        if input().strip().upper() in ["S", "Y"]:
            export_json({
                "latitude": latitude,
                "longitude": longitude,
                "radius": radius,
                "data": data
            }, filename_prefix="ship_radius")
    except Exception as e:
        clear()
        Write.Print(f"[!] > Error al realizar el escaneo por radio marítimo: {str(e)}\n", Colors.red, interval=0)
    restart()

def aircraft_live_range(lat, lon, range_value):

    if not lat or not lon or not range_value:
        clear()
        Write.Print("[!] > Por favor introduce coordenadas y rangos de búsqueda válidos.\n", default_color, interval=0)
        restart()
        return

    url = f"https://api.facha.dev/v1/aircraft/live/range/{lat}/{lon}/{range_value}"
    try:
        response = requests.get(url, timeout=60)
        response.raise_for_status()
        data = response.json()
        output_text = (
            f"Aeronaves en tiempo real en un rango de {range_value} alrededor de ({lat}, {lon}):\n"
            + json.dumps(data, indent=2)
        )
        clear()
        Write.Print(output_text, Colors.white, interval=0)
        log_option(output_text)
        print("[?] ¿Exportar rango de vuelos en JSON? (S/N): ", end="")
        if input().strip().upper() in ["S", "Y"]:
            export_json({
                "latitude": lat,
                "longitude": lon,
                "range": range_value,
                "data": data
            }, filename_prefix="aircraft_live_range")
    except Exception as e:
        clear()
        Write.Print(f"[!] > Error al interceptar datos de espacio aéreo: {str(e)}\n", Colors.red, interval=0)
    restart()

def aircraft_live_callsign(callsign):
    if not callsign:
        clear()
        Write.Print("[!] > Por favor introduce un indicativo de llamada o vuelo válido.\n", default_color, interval=0)
        restart()
        return
    url = f"https://api.facha.dev/v1/aircraft/live/callsign/{callsign}"
    try:
        response = requests.get(url, timeout=60)
        response.raise_for_status()
        data = response.json()
        output_text = (
            f"Información de aeronave en vivo para el indicativo '{callsign}':\n" +
            json.dumps(data, indent=2)
        )
        clear()
        Write.Print(output_text, Colors.white, interval=0)
        log_option(output_text)
        print("[?] ¿Exportar datos del vuelo en JSON? (S/N): ", end="")
        if input().strip().upper() in ["S", "Y"]:
            export_json({
                "callsign": callsign,
                "data": data
            }, filename_prefix="aircraft_live_callsign")
    except Exception as e:
        clear()
        Write.Print(f"[!] > Error al buscar espacio aéreo para el indicativo '{callsign}': {str(e)}\n", Colors.red, interval=0)
    restart()

def read_file_metadata(file_path):
    clear()
    Write.Print(f"🐢 Analizando Archivo Local\n {file_path}", Colors.green, interval=0)

    def timeConvert(atime):
        from datetime import datetime
        dt = atime
        newtime = datetime.fromtimestamp(dt)
        return newtime.date()

    def sizeFormat(size):
        newsize = format(size/1024, ".2f")
        return newsize + " KB"

    try:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"El archivo {file_path} no existe en la ruta dada.")
        Dfile = os.stat(file_path)
        file_size = sizeFormat(Dfile.st_size)
        file_name = os.path.basename(file_path)

        max_length = 60
        file_creation_time = datetime.fromtimestamp(getattr(Dfile, 'st_birthtime', Dfile.st_ctime)).date()
        file_modification_time = timeConvert(Dfile.st_mtime)
        file_last_Access_Date = timeConvert(Dfile.st_atime)

        mime = magic.Magic(mime=True)
        file_type = mime.from_file(file_path)

        metaData_extra = []

        def get_permission_string(file_mode):
            permissions = [
                stat.S_IRUSR, stat.S_IWUSR, stat.S_IXUSR,
                stat.S_IRGRP, stat.S_IWGRP, stat.S_IXGRP,
                stat.S_IROTH, stat.S_IWOTH, stat.S_IXOTH
            ]
            labels = ['Propietario', 'Grupo', 'Otros']
            permission_descriptions = []
            for i, label in enumerate(labels):
                read = 'Sí' if file_mode & permissions[i * 3] else 'No'
                write = 'Sí' if file_mode & permissions[i * 3 + 1] else 'No'
                execute = 'Sí' if file_mode & permissions[i * 3 + 2] else 'No'
                description = f"{label} {{Lectura: {read}, Escritura: {write}, Ejecución: {execute}}}"
                permission_descriptions.append(description)
            return ', '.join(permission_descriptions)

        def gps_extract(exif_dict):
            gps_metadata = exif_dict['GPSInfo']
            lat_ref_num = 1 if gps_metadata['GPSLatitudeRef'] == 'N' else -1
            long_ref_num = 1 if gps_metadata['GPSLongitudeRef'] == 'E' else -1

            lat_list = [float(num) for num in gps_metadata['GPSLatitude']]
            long_list = [float(num) for num in gps_metadata['GPSLongitude']]

            lat_coordinate = (lat_list[0] + lat_list[1]/60 + lat_list[2]/3600) * lat_ref_num
            long_coordinate = (long_list[0] + long_list[1]/60 + long_list[2]/3600) * long_ref_num
            return (lat_coordinate, long_coordinate)

        permissions = get_permission_string(Dfile.st_mode)

        if file_type.startswith("image"):
            with Image.open(file_path) as img:
                metaData_extra.append(f"|{' '*30}Metadatos de la Imagen{' '*28}|")
                metaData_extra.append(f"|{'-'*78}|")
                info_dict = {
                    "Archivo": img.filename,
                    "Resolución": img.size,
                    "Alto Pixel": img.height,
                    "Ancho Pixel": img.width,
                    "Formato": img.format,
                    "Modo Color": img.mode
                }
                for label,value in info_dict.items():
                    metaData_extra.append(f"|  {str(label):<10}: ||  {str(value)[:max_length]:<60}|")
                if img.format == 'TIFF':
                    for tag_id, value in img.tag_v2.items():
                        tag_name = TAGS.get(tag_id, tag_id)
                        metaData_extra.append(f"|  {str(tag_name):<10}: ||  {str(value)[:max_length]:<60}|")
                elif file_path.endswith('.png'):
                    for key, value in img.info.items():
                        metaData_extra.append(f"|  {str(key):<10}: ||  {str(value)[:max_length]:<60}|")
                else:
                    imdata = img._getexif()
                    if imdata:
                        for tag_id in imdata:
                            tag = TAGS.get(tag_id, tag_id)
                            data = imdata.get(tag_id)
                            if tag == "GPSInfo":
                                gps = gps_extract(imdata)
                                metaData_extra.append(f"|  Coordenadas GPS: ||  {gps}  |")
                                continue
                            if isinstance(data, bytes):
                                try:
                                    data = data.decode('utf-8', errors='ignore')
                                except UnicodeDecodeError:
                                    data = '<Datos no legibles>'
                            metaData_extra.append(f"|  {str(tag):<10}: ||  {str(data)[:max_length]:<60}|")
                    else:
                        metaData_extra.append("No se detectaron datos EXIF incrustados.")
        elif file_type == "application/pdf":
            with open(file_path, "rb") as pdf_file:
                pdf_reader = PyPDF2.PdfReader(pdf_file)
                pdf_data = pdf_reader.metadata
                metaData_extra.append(f"|{' '*32}Metadatos del PDF{' '*31}|")
                metaData_extra.append(f"|{'-'*78}|")
                if pdf_data:
                    for key, value in pdf_data.items():
                        metaData_extra.append(f"|  {str(key):<10}: || {str(value)[:max_length]:<60}|")
                    if pdf_reader.is_encrypted:
                        metaData_extra.append(f"|  Encriptado: || Sí      |")
                    else:
                        metaData_extra.append(f"|  Encriptado: || No      |")
                else:
                    metaData_extra.append("No se localizó metadata en el documento PDF.")
        elif file_path.endswith(('.doc', '.docx')):
            doc = docx.Document(file_path)
            core_properties = doc.core_properties
            doc_metadata = f"""
|{' '*30}Propiedades de Documento Word{' '*29}
|{'='*78}|
| Título:           || {str(core_properties.title) :<60}           |
| Autor/Creador:    || {str(core_properties.author) :<60}          |
| Asunto:           || {str(core_properties.subject) :<60}         |
| Palabras Clave:   || {str(core_properties.keywords) :<60}        |
| Modificado Por:   || {str(core_properties.last_modified_by) :<60}|
| Creado el:        || {str(core_properties.created) :<60}         |
| Modificado el:    || {str(core_properties.modified) :<60}        |
| Categoría:        || {str(core_properties.category) :<60}        |
| Estado Contenido: || {str(core_properties.content_status) :<60}  |
| Versión:          || {str(core_properties.version) :<60}         |
| Revisión:         || {str(core_properties.revision) :<60}        |
| Comentarios:      || {str(core_properties.comments) :<60}        |
            """
            metaData_extra.append(doc_metadata)
        elif file_path.endswith(('.xlsx', '.xlsm')):
            workbook = openpyxl.load_workbook(file_path, data_only=True)
            properties = workbook.properties
            excel_metadata = f"""
|{' '*30}Propiedades de Documento Excel{' '*28}|
|{'='*78}|
| Título:           || {str(properties.title) :<60}         |
| Autor/Creador:    || {str(properties.creator) :<60}       |
| Palabras Clave:   || {str(properties.keywords) :<60}      |
| Modificado Por:   || {str(properties.lastModifiedBy) :<60}|
| Creado el:        || {str(properties.created) :<60}       |
| Modificado el:    || {str(properties.modified) :<60}      |
| Categoría:        || {str(properties.category) :<60}      |
| Descripción:      || {str(properties.description) :<60}   |
            """
            metaData_extra.append(excel_metadata)
        elif file_path.endswith(('.pptx', '.pptm')):
            try:
                presentation = Presentation(file_path)
                core_properties = presentation.core_properties
                pptx_metadata = f"""
|{' '*28}Propiedades de Documento PowerPoint{' '*27}|
|{'='*78}|
| Título:           || {str(core_properties.title) :<60}           |
| Autor/Creador:    || {str(core_properties.author) :<60}          |
| Palabras Clave:   || {str(core_properties.keywords) :<60}        |
| Modificado Por:   || {str(core_properties.last_modified_by) :<60}|
| Creado el:        || {str(core_properties.created) :<60}         |
| Modificado el:    || {str(core_properties.modified) :<60}        |
| Categoría:        || {str(core_properties.category) :<60}        |
| Descripción:      || {str(core_properties.subject) :<60}         |
                """
                metaData_extra.append(pptx_metadata)
            except Exception as e:
                metaData_extra.append(f"[Error] No se pudo leer la metadata de PowerPoint: {e}")
        elif file_type.startswith("audio"):
            try:
                metaData_extra.append(f"|{' '*31}Metadatos de Audio{' '*31}|\n|{'-'*78}|")
                tinytim = TinyTag.get(file_path)
                if tinytim:
                    metaData_extra.append(f"|  Título:   || {str(tinytim.title)[:max_length]:<60}      |")
                    metaData_extra.append(f"|  Artista:  || {str(tinytim.artist)[:max_length]:<60}     |")
                    metaData_extra.append(f"|  Género:   || {str(tinytim.genre)[:max_length]:<60}      |")
                    metaData_extra.append(f"|  Álbum:    || {str(tinytim.album)[:max_length]:<60}      |")
                    metaData_extra.append(f"|  Año:      || {str(tinytim.year)[:max_length]:<60}       |")
                    metaData_extra.append(f"|  Composit: || {str(tinytim.composer)[:max_length]:<60}   |")
                    metaData_extra.append(f"|  Artista A:|| {str(tinytim.albumartist)[:max_length]:<60}|")
                    metaData_extra.append(f"|  Pistas T. || {str(tinytim.track_total)[:max_length]:<60}|")
                    metaData_extra.append(f"|  Duración: || {f'{tinytim.duration:.2f} segundos':<60}    |")
                    metaData_extra.append(f"|  Bitrate:  || {str(tinytim.bitrate) + ' kbps':<60}       |")
                    metaData_extra.append(f"|  Muestreo: || {str(tinytim.samplerate) + ' Hz':<60}      |")
                    metaData_extra.append(f"|  Canales:  || {str(tinytim.channels):<60}                |")

                if file_path.endswith('.mp3'):
                    audio = MP3(file_path, ID3=ID3)
                elif file_path.endswith('.wav'):
                    audio = wave.open(file_path, 'rb')
                elif file_path.endswith('.flac'):
                    audio = FLAC(file_path)
                elif file_path.endswith('.ogg'):
                    audio = OggVorbis(file_path)
                elif file_path.endswith(('.m4a', '.mp4')):
                    audio = MP4(file_path)
                else:
                    audio = None

                if audio is None:
                    metaData_extra.append("  Formato de archivo de audio no soportado para análisis avanzado.")
                else:
                    if hasattr(audio, 'items') and audio.items():
                        for tag, value in audio.items():
                            metaData_extra.append(f"|  {str(tag):<10}: ||  {str(value)[:max_length]:<60}|")
            except Exception as e:
                metaData_extra.append(f"Error procesando archivo de música: {str(e)}")

        clear()
        metadata_summary = f"""
|{' '*32}Metadatos del Archivo{' '*31}|
|{'='*78}|
|  Ruta Archivo:|| {file_path:<60}                  |
|  Nombre:      || {file_name:<60}                  |
|  Tamaño:      || {file_size:<60}                  |
|  Tipo MIME:   || {file_type:<60}                  |
|  Permisos:    || {permissions:<60}                |
|  Creado el:   || {str(file_creation_time):<60}    |
|  Modificado:  || {str(file_modification_time):60}|
|  Último Acc.: || {str(file_last_Access_Date):60}  |
"""
        metadata_summary += "\n".join(metaData_extra)
        metadata_summary += "\n" + "="*78 + "\n"
        Write.Print(metadata_summary, Colors.white, interval=0)
        log_option(metadata_summary)

        print("[?] ¿Exportar metadatos del archivo analizado en JSON? (S/N): ", end="")
        if input().strip().upper() in ["S", "Y"]:
            export_json({
                "file_path": file_path,
                "file_name": file_name,
                "file_size": file_size,
                "file_type": file_type,
                "permissions": permissions,
                "created": str(file_creation_time),
                "modified": str(file_modification_time),
                "last_access": str(file_last_Access_Date),
                "additional_metadata": metaData_extra
            }, filename_prefix="file_metadata")

    except Exception as e:
        err_msg = f" ☠️ Error fatal al leer los metadatos del archivo: {str(e)}"
        Write.Print(err_msg, Colors.red, interval=0)
        log_option(err_msg)
    restart()

def basic_port_scan(target, ports=[20, 21, 22, 80, 443, 8080, 23, 25, 53, 67, 68, 69, 88, 110, 123, 137, 138, 139, 143, 162, 162, 389, 427, 445, 465, 500, 636, 993, 995, 1433, 1434, 3306, 5060, 5061]):
    clear()
    Write.Print(f"[!] > Iniciando escaneo de puertos sobre {target}\n", default_color, interval=0)
    result_lines = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        try:
            result = sock.connect_ex((target, port))
            if result == 0:
                result_lines.append(f"Puerto {port} -> ABIERTO [OPEN].")
            else:
                result_lines.append(f"Puerto {port} -> Cerrado o Filtrado.")
        except Exception as e:
            result_lines.append(f"Puerto {port} -> Error de conexión: {str(e)}")
        finally:
            sock.close()

    report = f"\nResultados del Escaneo de Puertos para {target}:\n" + "\n".join(result_lines)
    Write.Print(report, Colors.white, interval=0)
    log_option(report)

    print("[?] ¿Exportar logs del escaneo de puertos en JSON? (S/N): ", end="")
    if input().strip().upper() in ["S", "Y"]:
        export_json({"target": target, "scan_results": result_lines}, filename_prefix="port_scan")
    restart()

def wayback_lookup(domain):
    clear()
    if not domain:
        Write.Print("[!] No se proporcionó un dominio válido para la consulta en Wayback.\n", Colors.red, interval=0)
        restart()
        return
    base_url = "http://web.archive.org/cdx/search/cdx"
    params = {
        "url": domain,
        "output": "json",
        "fl": "original,timestamp",
        "collapse": "digest",
        "filter": "statuscode:200",
        "limit": 20
    }
    try:
        resp = requests.get(base_url, params=params, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        if len(data) <= 1:
            Write.Print("[!] > No se encontraron capturas históricas (o ninguna con código de estado HTTP 200).\n", Colors.red, interval=0)
            restart()
            return

        snapshots = data[1:]
        output_text = f"\nCapturas de Wayback Machine para el dominio {domain}:\n"
        for snap in snapshots:
            original_url, timestamp = snap
            archive_url = f"https://web.archive.org/web/{timestamp}/{original_url}"
            output_text += f"- {timestamp} -> {archive_url}\n"

        Write.Print(output_text, Colors.white, interval=0)
        log_option(output_text)

        print("[?] ¿Exportar datos históricos de Wayback en JSON? (S/N): ", end="")
        if input().strip().upper() in ["S", "Y"]:
            export_json({"domain": domain, "snapshots": snapshots}, filename_prefix="wayback_lookup")
    except Exception as e:
        Write.Print(f"[!] > Error al recuperar datos de la Wayback Machine: {str(e)}\n", Colors.red, interval=0)
    restart()

def bulk_domain_processing(csv_path):
    clear()
    if not os.path.isfile(csv_path):
        Write.Print("[!] Archivo CSV no encontrado o la ruta especificada es inválida.\n", Colors.red, interval=0)
        restart()
        return

    try:
        with open(csv_path, "r", encoding="utf-8") as f:
            lines = [x.strip() for x in f if x.strip()]
    except UnicodeDecodeError:
        with open(csv_path, "r", encoding="latin-1") as f:
            lines = [x.strip() for x in f if x.strip()]

    Write.Print(f"[!] Se localizaron {len(lines)} registros dentro de {csv_path}.\n", default_color, interval=0)
    Write.Print("Selecciona las comprobaciones en lote que deseas correr por cada línea:\n", Colors.white, interval=0)
    Write.Print("[1] Búsqueda DNS\n[2] Consulta WHOIS\n[3] Enumeración de Subdominios\n[4] Info de IP (Si es IP externa)\n[5] Certificado SSL (Si es dominio)\n\n", Colors.white, interval=0)
    chosen = Write.Input("[?] Introduce los números seleccionados separados por comas (ejemplo: 1,2,5): ", default_color, interval=0).strip()
    chosen_set = set(x.strip() for x in chosen.split(","))

    results = {}
    for entry in lines:
        out_lines = [f"Resultados de Auditoría para: {entry}:"]
        if "1" in chosen_set:
            try:
                out_lines.append("Consulta DNS:")
                try:
                    answers = dns.resolver.resolve(entry, 'A')
                    out_lines.append(f"Registros A: {[str(a) for a in answers]}")
                except:
                    out_lines.append("Sin registros A / Error de resolución.")
            except Exception as e:
                out_lines.append(f"Fallo en Consulta DNS: {str(e)}")
        if "2" in chosen_set:
            try:
                w = whois.whois(entry)
                out_lines.append(f"WHOIS: {w.domain_name}, Registrador: {w.registrar}")
            except Exception as e:
                out_lines.append(f"Fallo en Consulta WHOIS: {str(e)}")
        if "3" in chosen_set and validate_domain_input(entry):
            try:
                out_lines.append("Enumeración Subdominios: Consultar consola/logs para ver detalles.")
            except Exception as e:
                out_lines.append(f"Error en Subdominios: {str(e)}")
        if "4" in chosen_set:
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', entry):
                details = get_ip_details(entry)
                if details:
                    out_lines.append(f"Info IP: Ciudad={details.get('city','N/A')} Región={details.get('region','N/A')} Proveedor={details.get('org','N/A')}")
                else:
                    out_lines.append("Info de IP no disponible.")
            else:
                out_lines.append("No es una IP pública estructural, omitiendo paso.")
        if "5" in chosen_set and validate_domain_input(entry):
            try:
                context = ssl.create_default_context()
                with socket.create_connection((entry, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=entry) as ssock:
                        cert = ssock.getpeercert()
                subject = dict(x[0] for x in cert['subject'])
                issuer = dict(x[0] for x in cert['issuer'])
                out_lines.append(f"SSL Emitido A: {subject.get('commonName','N/A')}, Por: {issuer.get('commonName','N/A')}")
            except Exception as e:
                out_lines.append(f"Error en enlace SSL: {str(e)}")

        results[entry] = "\n".join(out_lines)

    for entry, data in results.items():
        Write.Print("\n" + data + "\n", Colors.white, interval=0)

    print("[?] ¿Exportar este escaneo masivo por lote en JSON? (S/N): ", end="")
    if input().strip().upper() in ["S", "Y"]:
        export_json(results, filename_prefix="bulk_domain")
    restart()

def ssl_labs_deep_scan(domain: str):
    clear()
    if not validate_domain_input(domain):
        Write.Print("[!] > Formato de nombre de dominio inválido.\n", Colors.red, interval=0); restart(); return
    Write.Print(f"[!] > Solicitando escaneo profundo en SSL Labs para {domain} (esto puede tomar varios minutos)…\n", Colors.white, interval=0)
    base_url = "https://api.ssllabs.com/api/v3/analyze"
    params = {"host": domain, "publish": "off", "all": "done", "ignoreMismatch": "on"}
    try:
        requests.get(base_url, params=params, timeout=60)
        while True:
            time.sleep(15)
            resp = requests.get(base_url, params=params, timeout=60)
            data = resp.json()
            status = data.get("status", "")
            if status == "READY":
                break
            if status == "ERROR":
                Write.Print("[!] > SSL Labs reportó un estado de ERROR crítico.\n", Colors.red, interval=0); restart(); return
            Write.Print(".", Colors.white, interval=0)
        ep = data["endpoints"][0]
        grade = ep.get("grade", "N/A")
        details = ep.get("details", {})
        suites = [c.get("name", "") for s in details.get("suites", {}).get("list", []) for c in s.get("cipherSuite", [])]
        vuln_flags = {k: v for k, v in details.items() if k.startswith("vuln") or k in ("heartbleed", "poodleTls", "logjam")}
        report = (
            f"\n╭─{' '*78}─╮\n|{' '*29}Escaneo Completo SSL Labs{' '*28}|\n|{'='*80}|\n"
            f"| [+] > Dominio: {domain:<60}|\n| [+] > Calificación: {grade:<56}|\n|{'-'*80}|\n| Cifrados Disponibles (Cipher Suites)                                   |\n|{'='*80}|\n"
        )
        for c in suites:
            report += f"| {c:<78}|\n"
        report += f"|{'-'*80}|\n| Vulnerabilidades Detectadas                                           |\n|{'='*80}|\n"
        for k, v in vuln_flags.items():
            report += f"| {k:<25}: {str(v):<49}|\n"
        report += f"╰─{' '*78}─╯"
        Write.Print(report, Colors.white, interval=0)
        log_option(report)
        print("[?] ¿Exportar el informe SSL Labs en JSON? (S/N): ", end="")
        if input().strip().upper() in ["S", "Y"]:
            export_json(data, filename_prefix="ssllabs_scan")
    except Exception as e:
        Write.Print(f"[!] > Error al conectar con SSL Labs: {str(e)}\n", Colors.red, interval=0)
    restart()

def security_header_checker(url: str):
    clear()
    if not url.lower().startswith(("http://", "https://")):
        url = "https://" + url
    try:
        r = requests.get(url, timeout=60)
        hdrs = r.headers
        sec_hdrs = [
            "Strict-Transport-Security","Content-Security-Policy","X-Content-Type-Options",
            "X-Frame-Options","Referrer-Policy","Permissions-Policy",
            "Cross-Origin-Resource-Policy","Cross-Origin-Opener-Policy"
        ]
        report = (
            f"\n╭─{' '*78}─╮\n|{' '*28}Cabeceras de Seguridad HTTP{' '*27}|\n|{'='*80}|\n"
            f"| [+] > URL: {url:<64}|\n|{'-'*80}|\n"
        )
        for h in sec_hdrs:
            report += f"| {h:<32}: {hdrs.get(h,'No Presente (Ausente)')[:44]:<44}|\n"
        domain = urlparse(url).netloc
        sec_txt_url = f"https://{domain}/.well-known/security.txt"
        try:
            txt_r = requests.get(sec_txt_url, timeout=30)
            if txt_r.status_code == 200:
                first_lines = "\n".join(txt_r.text.splitlines()[:10])
                report += f"|{'-'*80}|\n| Archivo security.txt (Primeras 10 líneas detectadas)                  |\n|{'='*80}|\n"
                for ln in first_lines.splitlines():
                    report += f"| {ln[:78]:<78}|\n"
            else:
                report += f"| security.txt: No Encontrado en el servidor (HTTP {txt_r.status_code}) | \n"
        except Exception:
            report += "| security.txt: Error al intentar leer el recurso en la ruta          |\n"
        report += f"╰─{' '*78}─╯"
        Write.Print(report, Colors.white, interval=0)
        log_option(report)
        print("[?] ¿Exportar estas cabeceras de seguridad en JSON? (S/N): ", end="")
        if input().strip().upper() in ["S", "Y"]:
            export_json({"url": url, "headers": dict(hdrs)}, filename_prefix="header_check")
    except Exception as e:
        Write.Print(f"[!] > Error de Red / Conexión: {str(e)}\n", Colors.red, interval=0)
    restart()

def file_hash_calculator(file_path: str):
    clear()
    if not os.path.isfile(file_path):
        Write.Print("[!] > El archivo indicado no existe o la ruta está mal.\n", Colors.red, interval=0); restart(); return
    try:
        with open(file_path, "rb") as fp:
            data = fp.read()
        md5  = hashlib.md5(data).hexdigest()
        sha1 = hashlib.sha1(data).hexdigest()
        sha2 = hashlib.sha256(data).hexdigest()
        sha5 = hashlib.sha512(data).hexdigest()
        report = (
            f"\n╭─{' '*78}─╮\n|{' '*33}Hashes del Archivo{' '*33}|\n|{'='*80}|\n"
            f"| Archivo: {file_path:<68}|\n| MD5:    {md5:<64}|\n| SHA1:   {sha1:<64}|\n| SHA256: {sha2:<64}|\n| SHA512: {sha5:<64}|\n╰─{' '*78}─╯"
        )
        Write.Print(report, Colors.white, interval=0)
        log_option(report)
        print("[?] ¿Exportar hashes calculados en JSON? (S/N): ", end="")
        if input().strip().upper() in ["S", "Y"]:
            export_json({"file":file_path,"md5":md5,"sha1":sha1,"sha256":sha2,"sha512":sha5}, filename_prefix="file_hash")
    except Exception as e:
        Write.Print(f"[!] > Error de procesamiento: {str(e)}\n", Colors.red, interval=0)
    restart()

def favicon_mmh3_hash(site_url: str):
    clear()
    if not site_url.lower().startswith(("http://", "https://")):
        site_url = "https://" + site_url
    favicon_url = site_url.rstrip("/") + "/favicon.ico"
    try:
        r = requests.get(favicon_url, timeout=60); r.raise_for_status()
        b64 = base64.b64encode(r.content)
        if mmh3 is None:
            Write.Print("[!] > Librería 'mmh3' ausente. No se puede computar el algoritmo.\n", Colors.red, interval=0)
        else:
            fav_hash = mmh3.hash(b64)
            report = (
                f"\n╭─{' '*78}─╮\n|{' '*29}Hash MurmurHash3 de Favicon{' '*28}|\n|{'='*80}|\n"
                f"| Enlace Icono: {favicon_url:<64}|\n| Hash Shodan:  {fav_hash:<64}|\n╰─{' '*78}─╯"
            )
            Write.Print(report, Colors.white, interval=0)
            log_option(report)
            print("[?] ¿Exportar hash del favicon en JSON? (S/N): ", end="")
            if input().strip().upper() in ["S", "Y"]:
                export_json({"url":favicon_url,"murmurhash3":fav_hash}, filename_prefix="favicon_hash")
    except Exception as e:
        Write.Print(f"[!] > Error al interceptar el Favicon: {str(e)}\n", Colors.red, interval=0)
    restart()

def wayback_diff(target_url: str):
    clear()
    api = "http://web.archive.org/cdx/search/cdx"
    params = {"url": target_url,"output":"json","filter":"statuscode:200","collapse":"digest","limit":2,"fl":"timestamp,original"}
    try:
        j = requests.get(api, params=params, timeout=60).json()
        if len(j) <= 1:
            Write.Print("[!] > No existen capturas suficientes almacenadas para comparar diferencias.\n", Colors.red, interval=0); restart(); return
        ts1, orig1 = j[-1]; ts2, orig2 = j[0]
        url1 = f"https://web.archive.org/web/{ts1}/{orig1}"
        url2 = f"https://web.archive.org/web/{ts2}/{orig2}"
        html1 = requests.get(url1, timeout=60).text.splitlines()
        html2 = requests.get(url2, timeout=60).text.splitlines()
        diff = list(difflib.unified_diff(html1, html2, fromfile=url1, tofile=url2, lineterm=""))
        header = (
            f"\n╭─{' '*78}─╮\n|{' '*32}Comparación Wayback Diffs{' '*28}|\n|{'='*80}|\n"
            f"| Captura Antigua: {url1:<62}|\n| Captura Reciente:{url2:<62}|\n|{'-'*80}|\n"
        )
        Write.Print(header, Colors.white, interval=0)
        for ln in diff[:500]:
            Write.Print(ln[:78] + "\n", Colors.white, interval=0)
        if len(diff) > 500:
            Write.Print("[...] Archivo de diferencias truncado (Se muestran los primeros 500 cambios)\n", Colors.white, interval=0)
        log_option("Comparación temporal de Wayback desplegada arriba.")
        print("[?] ¿Exportar el reporte unificado de diferencias en un txt? (S/N): ", end="")
        if input().strip().upper() in ["S", "Y"]:
            fn = f"wayback_diff_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(fn, "w", encoding="utf-8") as fp:
                fp.write("\n".join(diff))
            Write.Print(f"[!] > Archivo de diferencias guardado: {fn}\n", Colors.green, interval=0)
    except Exception as e:
        Write.Print(f"[!] > Error al procesar diffs: {str(e)}\n", Colors.red, interval=0)
    restart()    

def main():
    while True:
        try:
            clear()
            print("\033[1;31m ██████╗██╗      █████╗ ████████╗███████╗ ██████╗ ██████╗ ██████╗ ███████╗")
            print("██╔════╝██║     ██╔══██╗╚══██╔══╝██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝")
            print("██║     ██║     ███████║   ██║   ███████╗██║     ██║   ██║██████╔╝█████╗  ")
            print("██║     ██║     ██╔══██║   ██║   ╚════██║██║     ██║   ██║██╔═══╝ ██╔══╝  ")
            print("╚██████╗███████╗██║  ██║   ██║   ███████║╚██████╗╚██████╔╝██║     ███████╗")
            print(" ╚═════╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝\033[0m")
            print("\033[1;31m                        ███╗   ███╗██╗███╗   ██╗██╗                        ")
            print("                        ████╗ ████║██║████╗  ██║██║                        ")
            print("                        ██╔████╔██║██║██╔██╗ ██║██║                        ")
            print("                        ██║╚██╔╝██║██║██║╚██╗██║██║                        ")
            print("                        ██║ ╚═╝ ██║██║██║ ╚████║██║                        ")
            print("                        ╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═╝                       \033[0m")
            print("\033[1;34mC L A T S C O P E   I N F O       T O O L    M I N I\033[0m   \033[1;31m(Versión 1.01)\033[0m")
            author = "🛡️ Traducido al Español - Autor Original: Joshua M Clatney (Clats97) 🛡️"
            Write.Print(author + "\n[OSINT]\nFuentes Abiertas. Conclusiones Claras.\n", Colors.white, interval=0)
            menu = (
                "==============================================================================================================|\n"
                "|  №   ||         Función           ||                          Descripción                                   |\n"
                "|======||===========================||========================================================================|\n"
                "| [1]  || Búsqueda Dirección IP     || Obtiene información geográfica y del ISP de una IP                     |\n"
                "| [2]  || Búsqueda Profunda Cuentas || Escanea perfiles en más de 150 redes sociales y foros                  |\n"
                "| [3]  || Búsqueda de Teléfono      || Valida la estructura, país y operador de un número telefónico          |\n"
                "| [4]  || Búsqueda Registros DNS    || Extrae mapeos de DNS esenciales (A, CNAME, MX, NS)                     |\n"
                "| [5]  || Comprobación Correo MX    || Verifica si un dominio cuenta con servidores de correo (MX) activos   |\n"
                "| [6]  || DNS Inverso (PTR) Search  || Resuelve el nombre de host asociado a una dirección IP                 |\n"
                "| [7]  || Análisis Cabeceras Email  || Desglosa la ruta de servidores e IPs de una cabecera de correo         |\n"
                "| [8]  || Consulta Registro WHOIS   || Obtiene datos legales de registro del dominio (fechas, nombres, etc.)  |\n"
                "| [9]  || Analizador Contraseñas    || Evalúa la robustez de una clave y si figura en listas comunes          |\n"
                "| [10] || Rastreador por Username   || Realiza búsquedas cruzadas de un alias mediante WhatsMyName             |\n"
                "| [11] || Verificación Certif. SSL  || Lee el estado de validez y entidad emisora del cifrado SSL             |\n"
                "| [12] || Rastreo Robots / Sitemap  || Intenta localizar los archivos de indexación web robots.txt/sitemap.xml|\n"
                "| [13] || Consulta Listas Negras    || Revisa reputación de una IP en 4 de las principales DNSBL mundiales    |\n"
                "| [14] || Extractor MetaTags Web    || Recopila títulos, descripciones y palabras clave de un sitio indexado  |\n"
                "| [15] || Metadatos en Archivos     || Analiza metadatos e historial de imágenes, PDF, Office, Audio, etc.    |\n"
                "| [16] || Búsqueda de Subdominios   || Descubre subdominios indexados públicamente a través de crt.sh         |\n"
                "| [17] || Historial Wayback Machine || Localiza copias de seguridad de páginas web en Internet Archive        |\n"
                "| [18] || Escaneo de Puertos Básico || Comprueba la disponibilidad de los 30 puertos de red más comunes       |\n"
                "| [19] || Proceso Masivo por CSV    || Audita una lista masiva de dominios/IPs importados desde un archivo CSV|\n"
                "| [20] || Rastreo Marítimo por MMSI || Localiza la telemetría e información de un buque mediante su ID MMSI    |\n"
                "| [21] || Barcos en Radio Geográfico|| Detecta barcos activos alrededor de coordenadas en un radio dado       |\n"
                "| [22] || Vuelos en vivo por Radio   || Monitorea el espacio aéreo en tiempo real alrededor de una ubicación   |\n"
                "| [23] || Vuelos por Indicativo     || Obtiene los detalles de un vuelo activo buscando por su 'Callsign'     |\n"
                "| [24] || Escaneo Profundo SSL Labs || Realiza una auditoría exhaustiva en SSL Labs (grados, fallos, ciphers) |\n"
                "| [25] || Cabeceras de Seguridad    || Examina políticas CSP, HSTS y la existencia de archivo security.txt    |\n"
                "| [26] || Calculadora Hash Archivos || Genera las firmas criptográficas MD5, SHA1 y SHA256/512 de un archivo  |\n"
                "| [27] || Hash Favicon para Shodan  || Calcula el MurmurHash3 del icono web para buscarlo en Shodan           |\n"
                "| [28] || Diferencias en Wayback    || Compara el código HTML de las dos capturas más viejas del archivo web  |\n"
                "| [0]  || Salir de la Herramienta   || Cierra ClatScope Info Tool Mini                                        |\n"
                "╰─    ─╯╰─                         ─╯╰─                                                                      ─╯\n"
            )

            Write.Print(menu, Colors.white, interval=0)
            choice = Write.Input("[?] >  ", default_color, interval=0).strip()
            if choice == "1":
                clear()
                ip = Write.Input("[?] > Dirección IP: ", default_color, interval=0)
                if not ip:
                    clear()
                    Write.Print("[!] > Debes introducir una Dirección IP para continuar.\n", default_color, interval=0)
                    continue
                ip_info(ip)
            elif choice == "2":
                clear()
                nickname = Write.Input("[?] > Nombre de Usuario (Alias): ", default_color, interval=0)
                if not nickname:
                    clear()
                    Write.Print("[!] > Introduce un nombre de usuario válido.\n", default_color, interval=0)
                    continue
                deep_account_search(nickname)
            elif choice == "3":
                clear()
                phone_number = Write.Input("[?] > Número telefónico (+País...): ", default_color, interval=0)
                if not phone_number:
                    clear()
                    Write.Print("[!] > Introduce un número de teléfono.\n", default_color, interval=0)
                    continue
                phone_info(phone_number)
            elif choice == "4":
                clear()
                domain = Write.Input("[?] > Dominio / URL: ", default_color, interval=0)
                if not domain:
                    clear()
                    Write.Print("[!] > Introduce un dominio o URL para resolver.\n", default_color, interval=0)
                    continue
                dns_lookup(domain)
            elif choice == "5":
                clear()
                email = Write.Input("[?] > Correo Electrónico: ", default_color, interval=0)
                if not email:
                    clear()
                    Write.Print("[!] > Introduce un correo electrónico.\n", default_color, interval=0)
                    continue
                email_lookup(email)
            elif choice == "6":
                clear()
                ip = Write.Input("[?] > Introduce una Dirección IP para búsqueda DNS Inversa: ", default_color, interval=0)
                if not ip:
                    clear()
                    Write.Print("[!] > Introduce una IP válida.\n", default_color, interval=0)
                    continue
                reverse_dns(ip)
            elif choice == "7":
                clear()
                Write.Print("[!] > Pega las cabeceras RAW del email abajo en una sola línea (presiona doble Enter al terminar):\n", default_color, interval=0)
                lines = []
                while True:
                    line = input()
                    if not line.strip():
                        break
                    lines.append(line)
                raw_headers = "\n".join(lines)
                if not raw_headers.strip():
                    clear()
                    Write.Print("[!] > No se proporcionó ninguna cabecera válida.\n", default_color, interval=0)
                    continue
                analyze_email_header(raw_headers)
            elif choice == "8":
                clear()
                domain = Write.Input("[?] > Introduce el dominio / URL para consulta WHOIS: ", default_color, interval=0)
                if not domain:
                    clear()
                    Write.Print("[!] > Introduce un dominio o dirección URL.\n", default_color, interval=0)
                    continue
                whois_lookup(domain)
            elif choice == "9":
                clear()
                password_strength_tool()
            elif choice == "10":
                clear()
                username_check()
            elif choice == "11":
                clear()
                domain = Write.Input("[?] > Introduce el dominio / URL para verificar certificado SSL: ", default_color, interval=0)
                if not domain:
                    clear()
                    Write.Print("[!] > Introduce un dominio o URL.\n", default_color, interval=0)
                    continue
                check_ssl_cert(domain)
            elif choice == "12":
                clear()
                domain = Write.Input("[?] > Introduce el dominio para buscar Robots.txt & Sitemap.xml: ", default_color, interval=0)
                if not domain:
                    clear()
                    Write.Print("[!] > Introduce un dominio.\n", default_color, interval=0)
                    continue
                check_robots_and_sitemap(domain)
            elif choice == "13":
                clear()
                ip_address = Write.Input("[?] > Introduce la dirección IP para cruzar con DNSBL: ", default_color, interval=0)
                if not ip_address:
                    clear()
                    Write.Print("[!] > Introduce una IP.\n", default_color, interval=0)
                    continue
                check_dnsbl(ip_address)
            elif choice == "14":
                clear()
                url = Write.Input("[?] > Introduce la URL para extraer sus metadatos web: ", Colors.white, interval=0)
                if not url:
                    clear()
                    Write.Print("[!] > Introduce una URL.\n", default_color, interval=0)
                    continue
                fetch_webpage_metadata(url)
            elif choice == "15":
                clear()
                file_path = Write.Input("  Introduce la ruta al archivo local que quieres analizar: ", default_color, interval=0)
                read_file_metadata(file_path)
            elif choice == "16":
                clear()
                domain = Write.Input("[?] > Introduce el dominio raíz para enumerar subdominios: ", default_color, interval=0)
                subdomain_enumeration(domain)
            elif choice == "17":
                clear()
                domain = Write.Input("[?] > Introduce el dominio para buscar en la Wayback Machine: ", default_color, interval=0)
                wayback_lookup(domain)
            elif choice == "18":
                clear()
                target = Write.Input("[?] > Introduce la IP o dominio para el escaneo de puertos: ", default_color, interval=0)
                basic_port_scan(target)
            elif choice == "19":
                clear()
                csv_path = Write.Input("[?] > Introduce la ruta local al archivo CSV: ", Colors.white, interval=0)
                bulk_domain_processing(csv_path)
            elif choice == "20":
                clear()
                mmsi = Write.Input("[?] > Introduce el código marítimo MMSI del barco: ", default_color, interval=0).strip()
                if not mmsi:
                    clear()
                    Write.Print("[!] > El código MMSI no puede estar en blanco.\n", default_color, interval=0)
                    continue
                ship_info(mmsi)
            elif choice == "21":
                clear()
                latitude = Write.Input("[?] > Introduce la latitud: ", default_color, interval=0).strip()
                longitude = Write.Input("[?] > Introduce la longitud: ", default_color, interval=0).strip()
                radius = Write.Input("[?] > Introduce el radio de búsqueda (en KM): ", default_color, interval=0).strip()
                if not latitude or not longitude or not radius:
                    clear()
                    Write.Print("[!] > Faltan parámetros indispensables (latitud, longitud o radio).\n", default_color, interval=0)
                    continue
                ship_radius(latitude, longitude, radius)
            elif choice == "22":
                clear()
                lat = Write.Input("[?] > Introduce la latitud de origen: ", default_color, interval=0).strip()
                lon = Write.Input("[?] > Introduce la longitud de origen: ", default_color, interval=0).strip()
                range_value = Write.Input("[?] > Introduce el rango de búsqueda: ", default_color, interval=0).strip()
                if not lat or not lon or not range_value:
                    clear()
                    Write.Print("[!] > Todos los campos de ubicación aérea son mandatorios.\n", default_color, interval=0)
                    continue
                aircraft_live_range(lat, lon, range_value)
            elif choice == "23":
                clear()
                callsign = Write.Input("[?] > Introduce el indicativo de vuelo (Callsign): ", default_color, interval=0).strip()
                if not callsign:
                    clear()
                    Write.Print("[!] > Debes proveer un indicativo de llamada.\n", default_color, interval=0)
                    continue
                aircraft_live_callsign(callsign)
            elif choice == "24":
                clear(); domain = Write.Input("[?] > Introduce el dominio para escaneo SSL Labs: ", default_color, interval=0)
                ssl_labs_deep_scan(domain)
            elif choice == "25":
                clear(); u = Write.Input("[?] > Introduce la URL para verificar cabeceras HTTP: ", default_color, interval=0)
                security_header_checker(u)
            elif choice == "26":
                clear(); fp = Write.Input("[?] > Introduce la ruta local del archivo para calcular hashes: ", default_color, interval=0)
                file_hash_calculator(fp)
            elif choice == "27":
                clear(); u = Write.Input("[?] > Introduce la URL del sitio web (para leer su favicon): ", default_color, interval=0)
                favicon_mmh3_hash(u)
            elif choice == "28":
                clear(); u = Write.Input("[?] > Introduce la URL para inspección de cambios (Wayback Diff): ", default_color, interval=0)
                wayback_diff(u)
            elif choice == "0":
                clear()
                Write.Print("[!] > Saliendo de ClatScope Info Tool Mini. ¡Buenas investigaciones! 🛡️\n", Colors.white, interval=0)
                break
            else:
                clear()
                Write.Print("[!] > Opción inválida del menú. Intenta de nuevo.\n", Colors.white, interval=0)
        except KeyboardInterrupt:
            clear()
            Write.Print("[!] > Ejecución interrumpida por el usuario. Saliendo de la consola...\n", Colors.white, interval=0)
            break

if __name__ == "__main__":
    main()