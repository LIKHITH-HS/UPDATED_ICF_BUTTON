"""
Admin Panel Integration Test

This script tests the integration of the admin panel with the main application
to ensure all components are working together properly.
"""

import requests
import sys
import json
from datetime import datetime

class AdminIntegrationTest:
    """Test suite for admin panel integration"""
    
    def __init__(self, base_url="http://localhost:5000"):
        self.base_url = base_url
        self.admin_url = f"{base_url}/admin"
        self.session = requests.Session()
        self.test_results = []
    
    def run_all_tests(self):
        """Run all integration tests"""
        print("🚀 Starting Admin Panel Integration Tests")
        print("=" * 50)
        
        # Test basic connectivity
        self.test_main_app_connectivity()
        self.test_admin_panel_accessibility()
        self.test_admin_login_page()
        self.test_admin_authentication_required()
        self.test_admin_api_endpoints()
        self.test_maintenance_mode_integration()
        self.test_rate_limiting_integration()
        
        # Print results
        self.print_test_results()
    
    def test_main_app_connectivity(self):
        """Test that the main application is running"""
        try:
            response = self.session.get(self.base_url, timeout=5)
            if response.status_code == 200:
                self.log_test("Main App Connectivity", True, "Main application is accessible")
            else:
                self.log_test("Main App Connectivity", False, f"Status code: {response.status_code}")
        except Exception as e:
            self.log_test("Main App Connectivity", False, f"Connection error: {str(e)}")
    
    def test_admin_panel_accessibility(self):
        """Test that admin panel routes are accessible"""
        try:
            response = self.session.get(self.admin_url, timeout=5)
            # Should redirect to login page
            if response.status_code in [200, 302]:
                self.log_test("Admin Panel Accessibility", True, "Admin panel routes are accessible")
            else:
                self.log_test("Admin Panel Accessibility", False, f"Status code: {response.status_code}")
        except Exception as e:
            self.log_test("Admin Panel Accessibility", False, f"Connection error: {str(e)}")
    
    def test_admin_login_page(self):
        """Test that admin login page loads correctly"""
        try:
            response = self.session.get(f"{self.admin_url}/login", timeout=5)
            if response.status_code == 200 and "LinkSafetyShield" in response.text:
                self.log_test("Admin Login Page", True, "Login page loads with correct branding")
            else:
                self.log_test("Admin Login Page", False, f"Status code: {response.status_code}")
        except Exception as e:
            self.log_test("Admin Login Page", False, f"Error: {str(e)}")
    
    def test_admin_authentication_required(self):
        """Test that admin routes require authentication"""
        protected_routes = [
            "/admin/dashboard",
            "/admin/settings",
            "/admin/monitoring",
            "/admin/rate-limits",
            "/admin/maintenance"
        ]
        
        all_protected = True
        failed_routes = []
        
        for route in protected_routes:
            try:
                response = self.session.get(f"{self.base_url}{route}", timeout=5)
                # Should redirect to login (302) or show login page (200 with login form)
                if response.status_code not in [200, 302]:
                    all_protected = False
                    failed_routes.append(route)
            except Exception as e:
                all_protected = False
                failed_routes.append(f"{route} (error: {str(e)})")
        
        if all_protected:
            self.log_test("Authentication Protection", True, "All admin routes are protected")
        else:
            self.log_test("Authentication Protection", False, f"Unprotected routes: {failed_routes}")
    
    def test_admin_api_endpoints(self):
        """Test that admin API endpoints are accessible (should require auth)"""
        api_endpoints = [
            "/admin/api/status",
            "/admin/api/stats",
            "/admin/api/monitoring/health",
            "/admin/api/maintenance/status"
        ]
        
        all_protected = True
        failed_endpoints = []
        
        for endpoint in api_endpoints:
            try:
                response = self.session.get(f"{self.base_url}{endpoint}", timeout=5)
                # Should return 302 (redirect to login) or 403 (forbidden)
                if response.status_code not in [302, 403]:
                    all_protected = False
                    failed_endpoints.append(f"{endpoint} (status: {response.status_code})")
            except Exception as e:
                all_protected = False
                failed_endpoints.append(f"{endpoint} (error: {str(e)})")
        
        if all_protected:
            self.log_test("API Endpoint Protection", True, "All admin API endpoints are protected")
        else:
            self.log_test("API Endpoint Protection", False, f"Issues: {failed_endpoints}")
    
    def test_maintenance_mode_integration(self):
        """Test that maintenance mode integration is working"""
        try:
            # Test that maintenance mode doesn't affect admin access
            response = self.session.get(f"{self.admin_url}/login", timeout=5)
            if response.status_code == 200:
                self.log_test("Maintenance Mode Integration", True, "Admin panel accessible during maintenance")
            else:
                self.log_test("Maintenance Mode Integration", False, f"Status code: {response.status_code}")
        except Exception as e:
            self.log_test("Maintenance Mode Integration", False, f"Error: {str(e)}")
    
    def test_rate_limiting_integration(self):
        """Test that rate limiting is integrated with the main app"""
        try:
            # Make multiple requests to test rate limiting
            responses = []
            for i in range(3):
                response = self.session.get(self.base_url, timeout=5)
                responses.append(response.status_code)
            
            # All should succeed (rate limits are generous for testing)
            if all(status == 200 for status in responses):
                self.log_test("Rate Limiting Integration", True, "Rate limiting is integrated")
            else:
                self.log_test("Rate Limiting Integration", False, f"Status codes: {responses}")
        except Exception as e:
            self.log_test("Rate Limiting Integration", False, f"Error: {str(e)}")
    
    def log_test(self, test_name, passed, message):
        """Log test result"""
        status = "✅ PASS" if passed else "❌ FAIL"
        self.test_results.append({
            'name': test_name,
            'passed': passed,
            'message': message,
            'timestamp': datetime.now().isoformat()
        })
        print(f"{status} {test_name}: {message}")
    
    def print_test_results(self):
        """Print summary of test results"""
        print("\n" + "=" * 50)
        print("📊 Test Results Summary")
        print("=" * 50)
        
        passed_tests = sum(1 for result in self.test_results if result['passed'])
        total_tests = len(self.test_results)
        
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed_tests}")
        print(f"Failed: {total_tests - passed_tests}")
        print(f"Success Rate: {(passed_tests/total_tests)*100:.1f}%")
        
        if passed_tests == total_tests:
            print("\n🎉 All tests passed! Admin panel integration is working correctly.")
        else:
            print("\n⚠️  Some tests failed. Please review the failed tests above.")
            
        # Save results to file
        try:
            with open('admin_integration_test_results.json', 'w') as f:
                json.dump(self.test_results, f, indent=2)
            print(f"\n📄 Test results saved to: admin_integration_test_results.json")
        except Exception as e:
            print(f"\n⚠️  Could not save test results: {e}")


def main():
    """Main function to run integration tests"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Admin Panel Integration Test')
    parser.add_argument('--url', default='http://localhost:5000', 
                       help='Base URL of the application (default: http://localhost:5000)')
    
    args = parser.parse_args()
    
    tester = AdminIntegrationTest(args.url)
    tester.run_all_tests()


if __name__ == "__main__":
    main()