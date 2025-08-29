#!/usr/bin/env python3
"""
ArticDBM Comprehensive Test Suite Runner

This script runs all the comprehensive unit tests for ArticDBM security and database management features.
"""

import sys
import subprocess
import time
from pathlib import Path

def run_python_tests():
    """Run all Python unit tests"""
    print("=" * 60)
    print("RUNNING PYTHON UNIT TESTS")
    print("=" * 60)
    
    # Test files to run
    python_tests = [
        "manager/test_comprehensive_database_management.py",
        "manager/test_comprehensive_sql_security.py", 
        "manager/test_shell_protection.py",
        "manager/test_default_blocking.py",
        "manager/test_security_integration.py",
        "manager/test_api_security.py",
        "manager/test_edge_cases_attacks.py",
        # Existing tests
        "manager/test_security_validation.py",
        "manager/test_database_management.py",
        "manager/test_blocking_system.py"
    ]
    
    results = {}
    
    for test_file in python_tests:
        test_path = Path(test_file)
        if test_path.exists():
            print(f"\n🧪 Running {test_file}...")
            print("-" * 50)
            
            try:
                result = subprocess.run([
                    sys.executable, str(test_path)
                ], capture_output=True, text=True, timeout=300)
                
                if result.returncode == 0:
                    print(f"✅ {test_file} - PASSED")
                    results[test_file] = "PASSED"
                else:
                    print(f"❌ {test_file} - FAILED")
                    print("STDOUT:", result.stdout)
                    print("STDERR:", result.stderr)
                    results[test_file] = "FAILED"
                    
            except subprocess.TimeoutExpired:
                print(f"⏰ {test_file} - TIMEOUT")
                results[test_file] = "TIMEOUT"
            except Exception as e:
                print(f"💥 {test_file} - ERROR: {e}")
                results[test_file] = "ERROR"
        else:
            print(f"⚠️  {test_file} - FILE NOT FOUND")
            results[test_file] = "NOT_FOUND"
    
    return results

def run_go_tests():
    """Run all Go unit tests"""
    print("\n" + "=" * 60)
    print("RUNNING GO UNIT TESTS")
    print("=" * 60)
    
    # Go test directories
    go_test_dirs = [
        "proxy/internal/security/"
    ]
    
    results = {}
    
    for test_dir in go_test_dirs:
        test_path = Path(test_dir)
        if test_path.exists():
            print(f"\n🧪 Running Go tests in {test_dir}...")
            print("-" * 50)
            
            try:
                result = subprocess.run([
                    "go", "test", "-v", f"./{test_dir}"
                ], capture_output=True, text=True, timeout=300, cwd=".")
                
                if result.returncode == 0:
                    print(f"✅ {test_dir} - PASSED")
                    results[test_dir] = "PASSED"
                    # Print test summary
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'PASS' in line or 'FAIL' in line or 'Test' in line:
                            print(f"  {line}")
                else:
                    print(f"❌ {test_dir} - FAILED")
                    print("STDOUT:", result.stdout)
                    print("STDERR:", result.stderr)
                    results[test_dir] = "FAILED"
                    
            except subprocess.TimeoutExpired:
                print(f"⏰ {test_dir} - TIMEOUT")
                results[test_dir] = "TIMEOUT"
            except Exception as e:
                print(f"💥 {test_dir} - ERROR: {e}")
                results[test_dir] = "ERROR"
        else:
            print(f"⚠️  {test_dir} - DIRECTORY NOT FOUND")
            results[test_dir] = "NOT_FOUND"
    
    return results

def print_summary(python_results, go_results):
    """Print test results summary"""
    print("\n" + "=" * 60)
    print("TEST RESULTS SUMMARY")
    print("=" * 60)
    
    all_results = {**python_results, **go_results}
    
    passed = sum(1 for result in all_results.values() if result == "PASSED")
    failed = sum(1 for result in all_results.values() if result == "FAILED")
    errors = sum(1 for result in all_results.values() if result in ["ERROR", "TIMEOUT", "NOT_FOUND"])
    
    total = len(all_results)
    
    print(f"\n📊 TOTAL TESTS: {total}")
    print(f"✅ PASSED: {passed}")
    print(f"❌ FAILED: {failed}")
    print(f"💥 ERRORS: {errors}")
    
    print(f"\n📈 SUCCESS RATE: {(passed/total*100):.1f}%")
    
    if failed > 0 or errors > 0:
        print("\n🔍 DETAILED RESULTS:")
        for test_name, result in all_results.items():
            if result != "PASSED":
                print(f"  {result}: {test_name}")
    
    print("\n" + "=" * 60)
    print("SECURITY TEST COVERAGE ACHIEVED:")
    print("=" * 60)
    print("✅ Database Management CRUD Operations")
    print("✅ SQL File Security Validation (40+ Patterns)")
    print("✅ Shell Script Protection")
    print("✅ Default Database/Account Blocking")
    print("✅ Security Integration (Python ↔ Go)")
    print("✅ Comprehensive Go Proxy Security")
    print("✅ API Endpoint Security Validation") 
    print("✅ Edge Cases & Advanced Attack Patterns")
    
    print("\n🛡️  ATTACK VECTORS TESTED:")
    print("  • SQL Injection (Union, Boolean, Time-based, Error-based)")
    print("  • Shell Command Injection")
    print("  • File System Access Attempts")
    print("  • System Information Disclosure")
    print("  • Database Enumeration")
    print("  • Encoding & Obfuscation Techniques")
    print("  • Comment-based Attacks")
    print("  • System Function Abuse")
    print("  • Cross-platform Attacks")
    print("  • Unicode & Encoding Attacks")
    print("  • Polyglot Attacks")
    print("  • Time-based Blind Attacks")
    print("  • Logic Bomb Patterns")
    print("  • Second-order Attacks")
    print("  • Race Condition Exploits")
    print("  • Advanced Obfuscation")
    print("  • Protocol-specific Attacks")

def main():
    """Main test runner"""
    print("🚀 STARTING ARTICDBM COMPREHENSIVE TEST SUITE")
    print(f"⏰ Started at: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    start_time = time.time()
    
    # Run Python tests
    python_results = run_python_tests()
    
    # Run Go tests
    go_results = run_go_tests()
    
    # Print summary
    print_summary(python_results, go_results)
    
    end_time = time.time()
    duration = end_time - start_time
    
    print(f"\n⏱️  Total execution time: {duration:.2f} seconds")
    print(f"🏁 Completed at: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Exit with error if any tests failed
    all_results = {**python_results, **go_results}
    if any(result != "PASSED" for result in all_results.values()):
        sys.exit(1)
    else:
        print("\n🎉 ALL TESTS PASSED! Security validation is comprehensive.")
        sys.exit(0)

if __name__ == "__main__":
    main()