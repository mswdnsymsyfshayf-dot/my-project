#!/usr/bin/env python3
"""
ملف اختبار للتحقق من عمل جميع الأدوات
"""

import sys
import os

# إضافة المسار الحالي
sys.path.insert(0, os.path.dirname(__file__))

from security_toolkit import (
    PortScanner,
    FileHashChecker,
    DirectoryBruteForcer,
    LogParser,
    PacketSniffer,
    HTTPHeaderAuditor,
    print_header,
    print_success,
    print_error
)

def test_port_scanner():
    """اختبار ماسح المنافذ"""
    print_header("اختبار ماسح المنافذ")
    try:
        scanner = PortScanner("127.0.0.1", 80, 82, timeout=0.5)
        scanner.scan(threads=3)
        report = scanner.generate_report()
        assert "تقرير فحص المنافذ" in report
        print_success("✓ اختبار ماسح المنافذ نجح")
        return True
    except Exception as e:
        print_error(f"✗ فشل اختبار ماسح المنافذ: {e}")
        return False

def test_file_hash_checker():
    """اختبار فاحص التجزئة"""
    print_header("اختبار فاحص التجزئة")
    try:
        # إنشاء ملف تجريبي
        test_file = "/tmp/test_file.txt"
        with open(test_file, 'w') as f:
            f.write("test content")
        
        checker = FileHashChecker()
        result = checker.check_file(test_file)
        assert result is not None
        assert result['md5'] is not None
        assert result['sha256'] is not None
        
        report = checker.generate_report()
        assert "تقرير فحص التجزئة" in report
        
        # حذف الملف التجريبي
        os.remove(test_file)
        
        print_success("✓ اختبار فاحص التجزئة نجح")
        return True
    except Exception as e:
        print_error(f"✗ فشل اختبار فاحص التجزئة: {e}")
        return False

def test_directory_brute_forcer():
    """اختبار كاسر الدليل"""
    print_header("اختبار كاسر الدليل")
    try:
        forcer = DirectoryBruteForcer("http://example.com", timeout=2)
        # اختبار مع قائمة صغيرة
        forcer.brute_force(wordlist=['test', 'admin'], threads=2)
        report = forcer.generate_report()
        assert "تقرير كسر الدليل" in report
        print_success("✓ اختبار كاسر الدليل نجح")
        return True
    except Exception as e:
        print_error(f"✗ فشل اختبار كاسر الدليل: {e}")
        return False

def test_log_parser():
    """اختبار محلل السجلات"""
    print_header("اختبار محلل السجلات")
    try:
        # إنشاء ملف سجل تجريبي
        test_log = "/tmp/test_access.log"
        with open(test_log, 'w') as f:
            f.write('192.168.1.1 - - [01/Jan/2024:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234\n')
            f.write('192.168.1.2 - - [01/Jan/2024:12:00:01 +0000] "GET /admin HTTP/1.1" 403 567\n')
        
        parser = LogParser()
        result = parser.parse_log(test_log)
        assert result is True
        assert len(parser.logs) == 2
        
        parser.detect_attacks()
        report = parser.generate_report()
        assert "تقرير تحليل السجلات" in report
        
        # حذف الملف التجريبي
        os.remove(test_log)
        
        print_success("✓ اختبار محلل السجلات نجح")
        return True
    except Exception as e:
        print_error(f"✗ فشل اختبار محلل السجلات: {e}")
        return False

def test_packet_sniffer():
    """اختبار الماسح"""
    print_header("اختبار الماسح")
    try:
        sniffer = PacketSniffer()
        sniffer.sniff(count=5)
        assert len(sniffer.packets) == 5
        
        report = sniffer.generate_report()
        assert "تقرير التقاط الحزم" in report
        
        print_success("✓ اختبار الماسح نجح")
        return True
    except Exception as e:
        print_error(f"✗ فشل اختبار الماسح: {e}")
        return False

def test_http_header_auditor():
    """اختبار مدقق رؤوس HTTP"""
    print_header("اختبار مدقق رؤوس HTTP")
    try:
        auditor = HTTPHeaderAuditor("https://www.google.com")
        result = auditor.audit()
        
        if result:
            report = auditor.generate_report()
            assert "تقرير تدقيق رؤوس HTTP" in report
            
            score = auditor.get_security_score()
            assert 0 <= score <= 100
            
            print_success("✓ اختبار مدقق رؤوس HTTP نجح")
            return True
        else:
            print_error("✗ فشل الاتصال بالموقع")
            return False
    except Exception as e:
        print_error(f"✗ فشل اختبار مدقق رؤوس HTTP: {e}")
        return False

def main():
    """تشغيل جميع الاختبارات"""
    print("\n" + "="*70)
    print("بدء اختبار جميع الأدوات".center(70))
    print("="*70 + "\n")
    
    tests = [
        ("ماسح المنافذ", test_port_scanner),
        ("فاحص التجزئة", test_file_hash_checker),
        ("كاسر الدليل", test_directory_brute_forcer),
        ("محلل السجلات", test_log_parser),
        ("الماسح", test_packet_sniffer),
        ("مدقق رؤوس HTTP", test_http_header_auditor)
    ]
    
    results = []
    for name, test_func in tests:
        try:
            result = test_func()
            results.append((name, result))
        except Exception as e:
            print_error(f"خطأ في اختبار {name}: {e}")
            results.append((name, False))
        print()
    
    # عرض النتائج النهائية
    print("="*70)
    print("ملخص نتائج الاختبار".center(70))
    print("="*70)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✓ نجح" if result else "✗ فشل"
        print(f"{name:30s} : {status}")
    
    print("="*70)
    print(f"النتيجة النهائية: {passed}/{total} اختبار نجح")
    print("="*70 + "\n")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
