#!/usr/bin/env python3
"""
Security Automation Toolkit
مجموعة أدوات أمنية متكاملة للتحليل واكتشاف الثغرات

المؤلف: فريق الأمن السيبراني
الإصدار: 2.0 (نسخة محسّنة)
"""

import os
import sys
import socket
import hashlib
import threading
import re
from datetime import datetime
from collections import defaultdict
from urllib.parse import urljoin

try:
    import requests
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    print("خطأ: المكتبات المطلوبة غير مثبتة")
    print("الرجاء التثبيت: pip install requests colorama")
    sys.exit(1)


# ============================================================================
# الدوال المساعدة (Utility Functions)
# ============================================================================

def print_header(text):
    """طباعة عنوان منسق"""
    print(f"\n{Fore.CYAN}{'='*70}\n{text.center(70)}\n{'='*70}{Style.RESET_ALL}\n")

def print_success(text):
    """رسالة نجاح"""
    print(f"{Fore.GREEN}[✓] {text}{Style.RESET_ALL}")

def print_error(text):
    """رسالة خطأ"""
    print(f"{Fore.RED}[✗] {text}{Style.RESET_ALL}")

def print_warning(text):
    """رسالة تحذير"""
    print(f"{Fore.YELLOW}[!] {text}{Style.RESET_ALL}")

def print_info(text):
    """رسالة معلومات"""
    print(f"{Fore.BLUE}[i] {text}{Style.RESET_ALL}")

def get_timestamp():
    """الحصول على الطابع الزمني"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def save_report(filename, content):
    """حفظ التقرير في ملف"""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(content)
        print_success(f"تم حفظ التقرير: {filename}")
        return True
    except Exception as e:
        print_error(f"خطأ في الحفظ: {e}")
        return False


# ============================================================================
# الأداة الأولى: ماسح المنافذ (Port Scanner)
# ============================================================================

class PortScanner:
    """فحص المنافذ المفتوحة على الأجهزة المستهدفة"""
    
    def __init__(self, target, start=1, end=1024, timeout=1):
        self.target = target
        self.start = start
        self.end = end
        self.timeout = timeout
        self.open_ports = []
        self.lock = threading.Lock()
    
    def scan_port(self, port):
        """فحص منفذ واحد"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                if sock.connect_ex((self.target, port)) == 0:
                    with self.lock:
                        self.open_ports.append(port)
                        try:
                            service = socket.getservbyport(port)
                        except:
                            service = "Unknown"
                        print_success(f"المنفذ {port} مفتوح - الخدمة: {service}")
        except:
            pass
    
    def scan(self, threads=50):
        """بدء عملية الفحص"""
        print_header(f"فحص المنافذ للهدف: {self.target}")
        print_info(f"نطاق الفحص: {self.start}-{self.end}")
        print_info(f"وقت البدء: {get_timestamp()}")
        
        thread_list = []
        for port in range(self.start, self.end + 1):
            t = threading.Thread(target=self.scan_port, args=(port,))
            thread_list.append(t)
            t.start()
            if len(thread_list) >= threads:
                for th in thread_list:
                    th.join()
                thread_list = []
        
        for th in thread_list:
            th.join()
        
        print_info(f"وقت الانتهاء: {get_timestamp()}")
        print_success(f"تم العثور على {len(self.open_ports)} منفذ مفتوح")
    
    def generate_report(self):
        """إنشاء تقرير الفحص"""
        report = f"""
{'='*70}
تقرير فحص المنافذ (Port Scan Report)
{'='*70}

الهدف: {self.target}
نطاق الفحص: {self.start}-{self.end}
التاريخ: {get_timestamp()}

المنافذ المفتوحة ({len(self.open_ports)}):
{'-'*70}
"""
        if self.open_ports:
            for port in sorted(self.open_ports):
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "غير معروف"
                report += f"المنفذ {port:5d} - الخدمة: {service}\n"
        else:
            report += "لم يتم العثور على منافذ مفتوحة\n"
        
        report += f"\n{'='*70}\n"
        return report


# ============================================================================
# الأداة الثانية: فاحص التجزئة (File Hash Checker)
# ============================================================================

class FileHashChecker:
    """حساب والتحقق من تجزئة الملفات"""
    
    def __init__(self):
        self.results = []
    
    def calculate_hash(self, filepath, algorithm='sha256'):
        """حساب التجزئة للملف"""
        try:
            hash_obj = hashlib.new(algorithm)
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except Exception as e:
            print_error(f"خطأ في حساب التجزئة: {e}")
            return None
    
    def check_file(self, filepath):
        """فحص ملف وحساب التجزئة"""
        if not os.path.isfile(filepath):
            print_error(f"الملف غير موجود: {filepath}")
            return None
        
        try:
            size = os.path.getsize(filepath)
            md5 = self.calculate_hash(filepath, 'md5')
            sha256 = self.calculate_hash(filepath, 'sha256')
            
            result = {
                'path': filepath,
                'name': os.path.basename(filepath),
                'size': size,
                'md5': md5,
                'sha256': sha256,
                'time': get_timestamp()
            }
            
            self.results.append(result)
            print_success(f"تم فحص الملف: {result['name']}")
            print_info(f"MD5: {md5}")
            print_info(f"SHA256: {sha256}")
            return result
        except Exception as e:
            print_error(f"خطأ في معالجة الملف: {e}")
            return None
    
    def verify_hash(self, filepath, expected, algorithm='sha256'):
        """التحقق من التجزئة"""
        calculated = self.calculate_hash(filepath, algorithm)
        if calculated == expected.lower():
            print_success("✓ التحقق ناجح - التجزئة متطابقة")
            return True
        else:
            print_error("✗ فشل التحقق - التجزئة غير متطابقة")
            print_info(f"المتوقع: {expected}")
            print_info(f"المحسوب: {calculated}")
            return False
    
    def generate_report(self):
        """إنشاء تقرير التجزئة"""
        report = f"""
{'='*70}
تقرير فحص التجزئة (File Hash Report)
{'='*70}

التاريخ: {get_timestamp()}
عدد الملفات: {len(self.results)}

تفاصيل الملفات:
{'-'*70}
"""
        for r in self.results:
            report += f"""
الملف: {r['name']}
المسار: {r['path']}
الحجم: {r['size']:,} بايت
MD5: {r['md5']}
SHA256: {r['sha256']}
{'-'*70}
"""
        return report


# ============================================================================
# الأداة الثالثة: كاسر الدليل (Directory Brute-Forcer)
# ============================================================================

class DirectoryBruteForcer:
    """اكتشاف المجلدات والملفات المخفية"""
    
    WORDLIST = [
        'admin', 'administrator', 'api', 'backup', 'config', 'console',
        'dashboard', 'data', 'database', 'debug', 'dev', 'docs',
        'download', 'files', 'images', 'includes', 'install', 'login',
        'logs', 'panel', 'private', 'public', 'root', 'scripts',
        'secure', 'server', 'settings', 'setup', 'static', 'test',
        'tmp', 'upload', 'uploads', 'user', 'users', 'wp-admin'
    ]
    
    def __init__(self, target_url, timeout=5):
        self.target = target_url.rstrip('/')
        self.timeout = timeout
        self.found = []
        self.lock = threading.Lock()
    
    def check_dir(self, directory):
        """فحص وجود مجلد"""
        url = urljoin(self.target, f"/{directory}/")
        try:
            r = requests.head(url, timeout=self.timeout, allow_redirects=False)
            if r.status_code in [200, 301, 302, 403]:
                with self.lock:
                    self.found.append({'dir': directory, 'url': url, 'status': r.status_code})
                    print_success(f"تم العثور: {url} (الحالة: {r.status_code})")
        except:
            pass
    
    def brute_force(self, wordlist=None, threads=10):
        """بدء عملية الكسر"""
        print_header(f"كسر الدليل للهدف: {self.target}")
        words = wordlist if wordlist else self.WORDLIST
        print_info(f"عدد الكلمات: {len(words)}")
        
        thread_list = []
        for word in words:
            t = threading.Thread(target=self.check_dir, args=(word,))
            thread_list.append(t)
            t.start()
            if len(thread_list) >= threads:
                for th in thread_list:
                    th.join()
                thread_list = []
        
        for th in thread_list:
            th.join()
        
        print_success(f"اكتمل الفحص - تم العثور على {len(self.found)} مجلد")
    
    def generate_report(self):
        """إنشاء تقرير الكسر"""
        report = f"""
{'='*70}
تقرير كسر الدليل (Directory Brute-Force Report)
{'='*70}

الهدف: {self.target}
التاريخ: {get_timestamp()}
المجلدات المكتشفة: {len(self.found)}

النتائج:
{'-'*70}
"""
        if self.found:
            for item in self.found:
                report += f"الرابط: {item['url']}\nالحالة: {item['status']}\n{'-'*70}\n"
        else:
            report += "لم يتم العثور على مجلدات\n"
        
        return report


# ============================================================================
# الأداة الرابعة: محلل السجلات (Log Parser)
# ============================================================================

class LogParser:
    """تحليل سجلات الخادم واكتشاف الأنشطة المشبوهة"""
    
    PATTERNS = {
        'sql_injection': r"('|\")\s*(or|and)\s*('|\")|union\s+select|drop\s+table",
        'xss_attack': r"<script|javascript:|onerror|onload",
        'path_traversal': r"\.\./|\.\.\\",
        'command_injection': r";\s*(cat|ls|rm|wget|curl)",
        'suspicious_agent': r"sqlmap|nikto|nmap|masscan"
    }
    
    def __init__(self):
        self.logs = []
        self.suspicious = defaultdict(list)
    
    def parse_log(self, filepath):
        """تحليل ملف السجل"""
        if not os.path.isfile(filepath):
            print_error(f"الملف غير موجود: {filepath}")
            return False
        
        try:
            pattern = r'(\S+) - - \[(.*?)\] "(\S+) (\S+) (\S+)" (\d+) (\S+)'
            with open(filepath, 'r') as f:
                for line in f:
                    match = re.match(pattern, line)
                    if match:
                        self.logs.append({
                            'ip': match.group(1),
                            'time': match.group(2),
                            'method': match.group(3),
                            'path': match.group(4),
                            'status': match.group(6),
                            'raw': line.strip()
                        })
            print_success(f"تم تحليل {len(self.logs)} سجل")
            return True
        except Exception as e:
            print_error(f"خطأ في التحليل: {e}")
            return False
    
    def detect_attacks(self):
        """اكتشاف الهجمات"""
        print_info("جاري فحص الأنشطة المشبوهة...")
        for log in self.logs:
            for attack, pattern in self.PATTERNS.items():
                if re.search(pattern, log['raw'], re.IGNORECASE):
                    self.suspicious[attack].append(log)
                    print_warning(f"تم اكتشاف {attack}: {log['ip']} - {log['path']}")
        
        total = sum(len(v) for v in self.suspicious.values())
        print_success(f"اكتمل الفحص - تم العثور على {total} نشاط مشبوه")
    
    def get_top_ips(self, limit=10):
        """الحصول على أكثر العناوين نشاطاً"""
        ip_count = defaultdict(int)
        for log in self.logs:
            ip_count[log['ip']] += 1
        return sorted(ip_count.items(), key=lambda x: x[1], reverse=True)[:limit]
    
    def generate_report(self):
        """إنشاء تقرير التحليل"""
        report = f"""
{'='*70}
تقرير تحليل السجلات (Log Analysis Report)
{'='*70}

التاريخ: {get_timestamp()}
عدد السجلات: {len(self.logs)}

الأنشطة المشبوهة:
{'-'*70}
"""
        for attack, logs in self.suspicious.items():
            report += f"\n{attack.upper()}: {len(logs)} حالة\n"
            for log in logs[:3]:
                report += f"  - {log['ip']} | {log['path']}\n"
        
        report += f"\nأكثر 10 عناوين IP نشاطاً:\n{'-'*70}\n"
        for ip, count in self.get_top_ips():
            report += f"{ip:20s} - {count:5d} طلب\n"
        
        return report


# ============================================================================
# الأداة الخامسة: الماسح (Packet Sniffer)
# ============================================================================

class PacketSniffer:
    """التقاط وتحليل حزم الشبكة"""
    
    def __init__(self):
        self.packets = []
    
    def generate_sample_packets(self, count=10):
        """توليد حزم تجريبية"""
        protocols = ['TCP', 'UDP', 'ICMP', 'DNS', 'HTTP']
        ips = ['192.168.1.100', '8.8.8.8', '172.16.0.1', '10.0.0.1']
        
        for i in range(count):
            packet = {
                'num': i + 1,
                'src': ips[i % len(ips)],
                'dst': ips[(i + 1) % len(ips)],
                'proto': protocols[i % len(protocols)],
                'size': (i + 1) * 64,
                'time': get_timestamp()
            }
            self.packets.append(packet)
            print_success(f"الحزمة #{i+1}: {packet['src']} → {packet['dst']} ({packet['proto']})")
    
    def sniff(self, count=10):
        """التقاط الحزم"""
        print_header("التقاط حزم الشبكة")
        print_info(f"عدد الحزم: {count}")
        print_warning("ملاحظة: يتم توليد بيانات تجريبية للعرض")
        self.generate_sample_packets(count)
        print_success(f"تم التقاط {len(self.packets)} حزمة")
    
    def generate_report(self):
        """إنشاء تقرير الحزم"""
        report = f"""
{'='*70}
تقرير التقاط الحزم (Packet Sniffer Report)
{'='*70}

التاريخ: {get_timestamp()}
عدد الحزم: {len(self.packets)}

تفاصيل الحزم:
{'-'*70}
"""
        for p in self.packets:
            report += f"""
الحزمة #{p['num']}
المصدر: {p['src']} | الوجهة: {p['dst']}
البروتوكول: {p['proto']} | الحجم: {p['size']} بايت
{'-'*70}
"""
        
        proto_count = defaultdict(int)
        for p in self.packets:
            proto_count[p['proto']] += 1
        
        report += "\nإحصائيات البروتوكولات:\n"
        for proto, count in sorted(proto_count.items(), key=lambda x: x[1], reverse=True):
            report += f"{proto:10s} - {count:3d} حزمة\n"
        
        return report


# ============================================================================
# الأداة السادسة: مدقق رؤوس HTTP (HTTP Header Auditor)
# ============================================================================

class HTTPHeaderAuditor:
    """تدقيق رؤوس الأمان في HTTP"""
    
    SECURITY_HEADERS = {
        'Strict-Transport-Security': 'فرض اتصال HTTPS',
        'X-Content-Type-Options': 'منع استنشاق MIME',
        'X-Frame-Options': 'الحماية من Clickjacking',
        'X-XSS-Protection': 'الحماية من XSS',
        'Content-Security-Policy': 'سياسة أمان المحتوى',
        'Referrer-Policy': 'سياسة المُحيل',
        'Permissions-Policy': 'سياسة الأذونات'
    }
    
    def __init__(self, target_url):
        self.target = target_url
        self.headers = {}
        self.findings = []
    
    def audit(self):
        """تدقيق الرؤوس"""
        print_header(f"تدقيق رؤوس HTTP للهدف: {self.target}")
        
        try:
            r = requests.get(self.target, timeout=10, allow_redirects=True)
            self.headers = dict(r.headers)
            print_success(f"حالة الاستجابة: {r.status_code}")
            print_info(f"عدد الرؤوس: {len(self.headers)}")
            
            self.check_security_headers()
            self.check_info_disclosure()
            return True
        except Exception as e:
            print_error(f"خطأ في الاتصال: {e}")
            return False
    
    def check_security_headers(self):
        """فحص رؤوس الأمان"""
        print_info("\nفحص رؤوس الأمان:")
        for header, desc in self.SECURITY_HEADERS.items():
            if header in self.headers:
                print_success(f"✓ {header}: موجود")
            else:
                print_warning(f"✗ {header}: مفقود - {desc}")
                self.findings.append({
                    'type': 'رأس مفقود',
                    'header': header,
                    'severity': 'متوسط'
                })
    
    def check_info_disclosure(self):
        """فحص الإفصاح عن المعلومات"""
        print_info("\nفحص الإفصاح عن المعلومات:")
        risky = ['Server', 'X-Powered-By', 'X-AspNet-Version']
        for header in risky:
            if header in self.headers:
                print_warning(f"⚠ {header}: {self.headers[header]} (إفصاح عن معلومات)")
                self.findings.append({
                    'type': 'إفصاح عن معلومات',
                    'header': header,
                    'value': self.headers[header],
                    'severity': 'منخفض'
                })
    
    def get_security_score(self):
        """حساب درجة الأمان"""
        total = len(self.SECURITY_HEADERS)
        present = sum(1 for h in self.SECURITY_HEADERS if h in self.headers)
        return int((present / total) * 100)
    
    def generate_report(self):
        """إنشاء تقرير التدقيق"""
        score = self.get_security_score()
        report = f"""
{'='*70}
تقرير تدقيق رؤوس HTTP (HTTP Header Audit Report)
{'='*70}

الهدف: {self.target}
التاريخ: {get_timestamp()}
درجة الأمان: {score}/100

الرؤوس المستلمة:
{'-'*70}
"""
        for h, v in sorted(self.headers.items()):
            report += f"{h:40s}: {v[:30]}\n"
        
        report += f"\nالنتائج الأمنية ({len(self.findings)} مشكلة):\n{'-'*70}\n"
        for f in self.findings:
            report += f"النوع: {f['type']}\nالرأس: {f['header']}\nالخطورة: {f['severity']}\n{'-'*70}\n"
        
        return report


# ============================================================================
# الفئة الرئيسية (Main Toolkit Class)
# ============================================================================

class SecurityToolkit:
    """مجموعة الأدوات الأمنية الرئيسية"""
    
    def __init__(self):
        self.tools = {
            '1': ('ماسح المنافذ', 'فحص المنافذ المفتوحة', self.run_port_scanner),
            '2': ('فاحص التجزئة', 'حساب والتحقق من تجزئة الملفات', self.run_hash_checker),
            '3': ('كاسر الدليل', 'اكتشاف المجلدات المخفية', self.run_brute_forcer),
            '4': ('محلل السجلات', 'تحليل السجلات واكتشاف الهجمات', self.run_log_parser),
            '5': ('الماسح', 'التقاط وتحليل حزم الشبكة', self.run_packet_sniffer),
            '6': ('مدقق رؤوس HTTP', 'تدقيق رؤوس الأمان', self.run_header_auditor)
        }
    
    def display_banner(self):
        """عرض شعار البرنامج"""
        banner = f"""
{Fore.CYAN}╔════════════════════════════════════════════════════════════════════╗
║                                                                    ║
║          🛡️  مجموعة أدوات الأمن السيبراني المتقدمة  🛡️           ║
║                                                                    ║
║              Security Automation Toolkit v2.0                     ║
║                                                                    ║
║      أدوات احترافية لتحليل التهديدات واكتشاف الثغرات الأمنية      ║
║                                                                    ║
╚════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(banner)
    
    def display_menu(self):
        """عرض القائمة الرئيسية"""
        print_header("القائمة الرئيسية")
        print("\nالأدوات المتاحة:\n")
        for key, (name, desc, _) in self.tools.items():
            print(f"  {key}. {name:<20} - {desc}")
        print("\n  0. خروج")
        print(f"\n{'='*70}")
    
    def run_port_scanner(self):
        """تشغيل ماسح المنافذ"""
        target = input("أدخل عنوان IP المستهدف: ").strip()
        if not target:
            print_error("العنوان فارغ")
            return
        
        try:
            start = int(input("المنفذ الأول (افتراضي 1): ") or "1")
            end = int(input("المنفذ الأخير (افتراضي 1024): ") or "1024")
        except:
            print_error("منافذ غير صالحة")
            return
        
        scanner = PortScanner(target, start, end)
        scanner.scan()
        report = scanner.generate_report()
        print(report)
        
        if input("حفظ التقرير؟ (y/n): ").lower() == 'y':
            filename = f"port_scan_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            save_report(filename, report)
    
    def run_hash_checker(self):
        """تشغيل فاحص التجزئة"""
        checker = FileHashChecker()
        while True:
            print("\n1. فحص ملف\n2. التحقق من التجزئة\n3. عرض التقرير\n4. حفظ التقرير\n5. رجوع")
            choice = input("اختر: ").strip()
            
            if choice == '1':
                filepath = input("مسار الملف: ").strip()
                checker.check_file(filepath)
            elif choice == '2':
                filepath = input("مسار الملف: ").strip()
                expected = input("التجزئة المتوقعة: ").strip()
                algo = input("الخوارزمية (md5/sha256): ").strip().lower() or 'sha256'
                checker.verify_hash(filepath, expected, algo)
            elif choice == '3':
                print(checker.generate_report())
            elif choice == '4':
                filename = f"hash_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                save_report(filename, checker.generate_report())
            elif choice == '5':
                break
    
    def run_brute_forcer(self):
        """تشغيل كاسر الدليل"""
        target = input("أدخل رابط الموقع (مثال: http://example.com): ").strip()
        if not target:
            print_error("الرابط فارغ")
            return
        
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"
        
        forcer = DirectoryBruteForcer(target)
        forcer.brute_force()
        report = forcer.generate_report()
        print(report)
        
        if input("حفظ التقرير؟ (y/n): ").lower() == 'y':
            filename = f"brute_force_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            save_report(filename, report)
    
    def run_log_parser(self):
        """تشغيل محلل السجلات"""
        parser = LogParser()
        while True:
            print("\n1. تحليل ملف سجل\n2. اكتشاف الهجمات\n3. عرض التقرير\n4. حفظ التقرير\n5. رجوع")
            choice = input("اختر: ").strip()
            
            if choice == '1':
                filepath = input("مسار ملف السجل: ").strip()
                parser.parse_log(filepath)
            elif choice == '2':
                parser.detect_attacks()
            elif choice == '3':
                print(parser.generate_report())
            elif choice == '4':
                filename = f"log_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                save_report(filename, parser.generate_report())
            elif choice == '5':
                break
    
    def run_packet_sniffer(self):
        """تشغيل الماسح"""
        try:
            count = int(input("عدد الحزم (افتراضي 10): ") or "10")
        except:
            count = 10
        
        sniffer = PacketSniffer()
        sniffer.sniff(count)
        report = sniffer.generate_report()
        print(report)
        
        if input("حفظ التقرير؟ (y/n): ").lower() == 'y':
            filename = f"packet_sniffer_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            save_report(filename, report)
    
    def run_header_auditor(self):
        """تشغيل مدقق رؤوس HTTP"""
        target = input("أدخل رابط الموقع (مثال: https://example.com): ").strip()
        if not target:
            print_error("الرابط فارغ")
            return
        
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        
        auditor = HTTPHeaderAuditor(target)
        if auditor.audit():
            report = auditor.generate_report()
            print(report)
            print_info(f"درجة الأمان: {auditor.get_security_score()}/100")
            
            if input("حفظ التقرير؟ (y/n): ").lower() == 'y':
                filename = f"header_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                save_report(filename, report)
    
    def run(self):
        """تشغيل البرنامج الرئيسي"""
        self.display_banner()
        
        while True:
            self.display_menu()
            choice = input("\nاختر أداة (0-6): ").strip()
            
            if choice == '0':
                print_success("\nشكراً لاستخدام مجموعة الأدوات الأمنية!")
                print_info("ابق آمناً! 🔒\n")
                break
            
            elif choice in self.tools:
                os.system('clear' if os.name != 'nt' else 'cls')
                try:
                    self.tools[choice][2]()
                except KeyboardInterrupt:
                    print_error("\nتم الإلغاء من قبل المستخدم")
                except Exception as e:
                    print_error(f"خطأ: {e}")
                input("\nاضغط Enter للعودة للقائمة...")
                os.system('clear' if os.name != 'nt' else 'cls')
            
            else:
                print_error("خيار غير صحيح")


# ============================================================================
# نقطة الدخول الرئيسية (Main Entry Point)
# ============================================================================

def main():
    """الدالة الرئيسية"""
    try:
        toolkit = SecurityToolkit()
        toolkit.run()
    except KeyboardInterrupt:
        print_error("\n\nتم إيقاف البرنامج من قبل المستخدم")
        sys.exit(0)
    except Exception as e:
        print_error(f"خطأ فادح: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
