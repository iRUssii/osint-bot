#!/usr/bin/env python3
"""
Test script to verify the improvements made to address issue #21
"""

import os
import sys
import tempfile
import json
from pathlib import Path

def test_health_check_imports():
    """Test that health check script can be imported and run"""
    print("Testing health check script...")
    
    # Try to import the health check script
    sys.path.insert(0, '.')
    try:
        import health_check
        print("✅ Health check script imports successfully")
        return True
    except Exception as e:
        print(f"❌ Health check script import failed: {e}")
        return False

def test_issue_templates_exist():
    """Test that all issue templates exist and have required content"""
    print("Testing issue templates...")
    
    templates_dir = Path(".github/ISSUE_TEMPLATE")
    required_templates = [
        "bug_report.md",
        "feature_request.md", 
        "osint_command_issue.md",
        "config.yml"
    ]
    
    all_exist = True
    for template in required_templates:
        template_path = templates_dir / template
        if template_path.exists():
            content = template_path.read_text()
            if len(content) > 100:  # Basic content check
                print(f"✅ {template}: Exists and has content")
            else:
                print(f"⚠️  {template}: Exists but may be empty")
                all_exist = False
        else:
            print(f"❌ {template}: Missing")
            all_exist = False
    
    return all_exist

def test_workflow_exists():
    """Test that the issue validation workflow exists"""
    print("Testing issue validation workflow...")
    
    workflow_path = Path(".github/workflows/issue-validation.yml")
    if workflow_path.exists():
        content = workflow_path.read_text()
        if "Issue Validation" in content and "placeholder" in content:
            print("✅ Issue validation workflow exists and has placeholder detection")
            return True
        else:
            print("⚠️  Issue validation workflow exists but may be incomplete")
            return False
    else:
        print("❌ Issue validation workflow missing")
        return False

def test_readme_improvements():
    """Test that README has been improved with troubleshooting info"""
    print("Testing README improvements...")
    
    readme_path = Path("README.md")
    if readme_path.exists():
        content = readme_path.read_text()
        required_sections = [
            "Health Check Tool",
            "python health_check.py",
            "Reporting Issues",
            "Bug Report",
            "OSINT Command Issue",
            "Feature Request"
        ]
        
        all_present = True
        for section in required_sections:
            if section in content:
                print(f"✅ README contains: {section}")
            else:
                print(f"❌ README missing: {section}")
                all_present = False
        
        return all_present
    else:
        print("❌ README.md not found")
        return False

def test_requirements_fix():
    """Test that requirements.txt has been fixed"""
    print("Testing requirements.txt fix...")
    
    requirements_path = Path("requirements.txt")
    if requirements_path.exists():
        content = requirements_path.read_text()
        if "pyTelegramBotAPI" in content and "python-telegram-bot" not in content:
            print("✅ requirements.txt has correct telegram bot dependency")
            return True
        else:
            print("❌ requirements.txt has incorrect telegram bot dependency")
            return False
    else:
        print("❌ requirements.txt not found")
        return False

def main():
    """Run all tests"""
    print("🔍 Testing Issue #21 Improvements")
    print("=" * 50)
    
    tests = [
        test_health_check_imports,
        test_issue_templates_exist,
        test_workflow_exists,
        test_readme_improvements,
        test_requirements_fix
    ]
    
    results = []
    for test in tests:
        try:
            result = test()
            results.append(result)
            print()
        except Exception as e:
            print(f"❌ Test failed with exception: {e}")
            results.append(False)
            print()
    
    # Summary
    print("📊 Test Results")
    print("=" * 50)
    passed = sum(results)
    total = len(results)
    
    print(f"Overall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! The improvements look good.")
        return 0
    else:
        print("⚠️  Some tests failed. Please review the issues above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())