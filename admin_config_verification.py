"""
Admin Panel Configuration Verification

This script verifies that all admin panel components are properly configured
and integrated with the main application.
"""

import os
import sys
import importlib
from pathlib import Path

class AdminConfigVerification:
    """Verify admin panel configuration and integration"""
    
    def __init__(self):
        self.checks = []
        self.workspace_root = Path.cwd()
    
    def run_all_checks(self):
        """Run all configuration checks"""
        print("🔍 Admin Panel Configuration Verification")
        print("=" * 50)
        
        self.check_required_files()
        self.check_imports()
        self.check_blueprint_registration()
        self.check_middleware_initialization()
        self.check_template_structure()
        self.check_environment_variables()
        self.check_dependencies()
        
        self.print_results()
    
    def check_required_files(self):
        """Check that all required admin panel files exist"""
        required_files = [
            'admin_panel.py',
            'admin_auth.py',
            'admin_middleware.py',
            'admin_error_handler.py',
            'maintenance_mode.py',
            'monitoring_service.py',
            'config_manager.py',
            'rate_limiter.py',
            'templates/admin/base.html',
            'templates/admin/login.html',
            'templates/admin/dashboard.html',
            'templates/admin/settings.html',
            'templates/admin/monitoring.html',
            'templates/admin/maintenance.html',
            'templates/maintenance.html'
        ]
        
        missing_files = []
        for file_path in required_files:
            if not (self.workspace_root / file_path).exists():
                missing_files.append(file_path)
        
        if not missing_files:
            self.log_check("Required Files", True, "All required admin panel files exist")
        else:
            self.log_check("Required Files", False, f"Missing files: {missing_files}")
    
    def check_imports(self):
        """Check that admin panel modules can be imported"""
        modules_to_check = [
            'admin_panel',
            'admin_auth',
            'admin_middleware',
            'admin_error_handler',
            'maintenance_mode',
            'monitoring_service'
        ]
        
        import_errors = []
        for module_name in modules_to_check:
            try:
                importlib.import_module(module_name)
            except ImportError as e:
                import_errors.append(f"{module_name}: {str(e)}")
        
        if not import_errors:
            self.log_check("Module Imports", True, "All admin modules can be imported")
        else:
            self.log_check("Module Imports", False, f"Import errors: {import_errors}")
    
    def check_blueprint_registration(self):
        """Check that admin blueprint is registered in app.py"""
        try:
            app_py_path = self.workspace_root / 'app.py'
            if app_py_path.exists():
                content = app_py_path.read_text()
                
                has_import = 'from admin_panel import admin_panel' in content
                has_registration = 'app.register_blueprint(admin_panel)' in content
                
                if has_import and has_registration:
                    self.log_check("Blueprint Registration", True, "Admin blueprint is properly registered")
                else:
                    issues = []
                    if not has_import:
                        issues.append("missing import")
                    if not has_registration:
                        issues.append("missing registration")
                    self.log_check("Blueprint Registration", False, f"Issues: {issues}")
            else:
                self.log_check("Blueprint Registration", False, "app.py file not found")
        except Exception as e:
            self.log_check("Blueprint Registration", False, f"Error checking: {str(e)}")
    
    def check_middleware_initialization(self):
        """Check that admin middleware is initialized"""
        try:
            app_py_path = self.workspace_root / 'app.py'
            if app_py_path.exists():
                content = app_py_path.read_text()
                
                required_initializations = [
                    'AdminMiddleware(app)',
                    'setup_admin_session_config(app)',
                    'init_rate_limiting(app)',
                    'init_monitoring(app)',
                    'init_maintenance_mode(app)',
                    'init_admin_error_handling(app)'
                ]
                
                missing_inits = []
                for init_call in required_initializations:
                    if init_call not in content:
                        missing_inits.append(init_call)
                
                if not missing_inits:
                    self.log_check("Middleware Initialization", True, "All middleware components are initialized")
                else:
                    self.log_check("Middleware Initialization", False, f"Missing: {missing_inits}")
            else:
                self.log_check("Middleware Initialization", False, "app.py file not found")
        except Exception as e:
            self.log_check("Middleware Initialization", False, f"Error checking: {str(e)}")
    
    def check_template_structure(self):
        """Check admin template structure"""
        template_checks = [
            ('templates/admin/base.html', ['{% block content %}', 'csrf_token']),
            ('templates/admin/login.html', ['csrf_token', 'username', 'password']),
            ('templates/admin/dashboard.html', ['{% extends "admin/base.html" %}', 'system_stats']),
            ('templates/maintenance.html', ['maintenance_status', 'countdown'])
        ]
        
        template_issues = []
        for template_path, required_content in template_checks:
            try:
                template_file = self.workspace_root / template_path
                if template_file.exists():
                    content = template_file.read_text()
                    missing_content = [item for item in required_content if item not in content]
                    if missing_content:
                        template_issues.append(f"{template_path}: missing {missing_content}")
                else:
                    template_issues.append(f"{template_path}: file not found")
            except Exception as e:
                template_issues.append(f"{template_path}: error reading file")
        
        if not template_issues:
            self.log_check("Template Structure", True, "All templates have required structure")
        else:
            self.log_check("Template Structure", False, f"Issues: {template_issues}")
    
    def check_environment_variables(self):
        """Check for required environment variables"""
        env_file_path = self.workspace_root / '.env.example'
        
        if env_file_path.exists():
            try:
                content = env_file_path.read_text()
                required_vars = [
                    'ADMIN_USERNAME',
                    'ADMIN_PASSWORD',
                    'ADMIN_SESSION_TIMEOUT',
                    'SECRET_KEY'
                ]
                
                missing_vars = []
                for var in required_vars:
                    if var not in content:
                        missing_vars.append(var)
                
                if not missing_vars:
                    self.log_check("Environment Variables", True, "All required env vars documented")
                else:
                    self.log_check("Environment Variables", False, f"Missing from .env.example: {missing_vars}")
            except Exception as e:
                self.log_check("Environment Variables", False, f"Error reading .env.example: {str(e)}")
        else:
            self.log_check("Environment Variables", False, ".env.example file not found")
    
    def check_dependencies(self):
        """Check that required dependencies are available"""
        required_packages = [
            'flask',
            'flask-limiter',
            'redis',
            'psutil'
        ]
        
        missing_packages = []
        for package in required_packages:
            try:
                importlib.import_module(package.replace('-', '_'))
            except ImportError:
                missing_packages.append(package)
        
        if not missing_packages:
            self.log_check("Dependencies", True, "All required packages are available")
        else:
            self.log_check("Dependencies", False, f"Missing packages: {missing_packages}")
    
    def log_check(self, check_name, passed, message):
        """Log check result"""
        status = "✅ PASS" if passed else "❌ FAIL"
        self.checks.append({
            'name': check_name,
            'passed': passed,
            'message': message
        })
        print(f"{status} {check_name}: {message}")
    
    def print_results(self):
        """Print summary of check results"""
        print("\n" + "=" * 50)
        print("📊 Configuration Check Summary")
        print("=" * 50)
        
        passed_checks = sum(1 for check in self.checks if check['passed'])
        total_checks = len(self.checks)
        
        print(f"Total Checks: {total_checks}")
        print(f"Passed: {passed_checks}")
        print(f"Failed: {total_checks - passed_checks}")
        print(f"Success Rate: {(passed_checks/total_checks)*100:.1f}%")
        
        if passed_checks == total_checks:
            print("\n🎉 All configuration checks passed! Admin panel is properly configured.")
        else:
            print("\n⚠️  Some checks failed. Please review the failed checks above.")
            print("\n🔧 Recommended Actions:")
            for check in self.checks:
                if not check['passed']:
                    print(f"   • Fix {check['name']}: {check['message']}")


def main():
    """Main function to run configuration verification"""
    verifier = AdminConfigVerification()
    verifier.run_all_checks()


if __name__ == "__main__":
    main()