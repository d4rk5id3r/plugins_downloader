import os
import re

# Patterns to detect entry points
AJAX_HANDLER = re.compile(r"add_action\(\s*['\"]wp_ajax(?:_nopriv)?_.*?['\"],\s*['\"](\w+)['\"]")
REST_ROUTE = re.compile(r"register_rest_route\([^)]+['\"]permission_callback['\"]\s*=>\s*([^\s,]+)")
ADMIN_MENU = re.compile(r"add_(?:menu|submenu)_page\([^)]*['\"](\w+)['\"]\s*\)")

# Check if function contains a capability check
CAP_CHECK = re.compile(r"current_user_can\s*\(")

def find_php_files(base_dir):
    php_files = []
    for root, _, files in os.walk(base_dir):
        for f in files:
            if f.endswith('.php'):
                php_files.append(os.path.join(root, f))
    return php_files

def extract_functions(file_content):
    # Map function names to their contents
    func_blocks = {}
    pattern = re.compile(r"function\s+(\w+)\s*\((.*?)\)\s*{", re.DOTALL)
    matches = list(pattern.finditer(file_content))
    for i, match in enumerate(matches):
        start = match.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(file_content)
        func_name = match.group(1)
        func_body = file_content[start:end]
        func_blocks[func_name] = func_body
    return func_blocks

def scan_php_file(file_path):
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    results = []
    functions = extract_functions(content)

    # Check AJAX handlers
    for match in AJAX_HANDLER.finditer(content):
        func_name = match.group(1)
        if func_name in functions and not CAP_CHECK.search(functions[func_name]):
            results.append((file_path, func_name, "AJAX handler"))

    # Check REST routes
    for match in REST_ROUTE.finditer(content):
        permission_cb = match.group(1).strip()
        if permission_cb in ["__return_true", "true"]:
            results.append((file_path, permission_cb, "REST API insecure permission_callback"))

    return results

def scan_plugin(plugin_dir):
    print(f"Scanning plugin directory: {plugin_dir}\n")
    php_files = find_php_files(plugin_dir)
    all_issues = []

    for php_file in php_files:
        issues = scan_php_file(php_file)
        all_issues.extend(issues)

    if not all_issues:
        print("No missing capability checks found (based on this static scan).")
    else:
        print("Potential issues found:")
        for path, func, issue_type in all_issues:
            print(f"[{issue_type}] Missing or weak cap check in '{func}' in file: {path}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python check_capability_issues.py /path/to/plugin")
    else:
        scan_plugin(sys.argv[1])
