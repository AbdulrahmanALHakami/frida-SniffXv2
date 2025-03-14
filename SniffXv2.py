import frida
import sys

def show_help():
    """Display available command options and their descriptions."""
    print("\n[+] SniffX - iOS API Traffic Interceptor")
    print("\nUsage:")
    print("  python3 sniffx.py <App or PID> [Options]")
    print("\nOptions:")
    print("  --help                 this help message and exit.")
    print("  --api <endpoint>       Intercept traffic for a specific API endpoint (e.g., /login).")
    print("  --ssl-bypass-only      Enabling SSL Pinning bypass without intercepting traffic.")
    print("  --list-endpoints       Extract & list all of the APIs endpoints used by the application.")
    print("\nExamples:")
    print("  python3 sniffx.py <App>              # Attach to Your app and bypass SSL Pinning")
    print("  python3 sniffx.py <App> --api /login # Intercept only /login API requests")
    print("  python3 sniffx.py <App> --ssl-bypass-only # Bypass SSL pinning only")
    print("  python3 sniffx.py <App> --list-endpoints # List all API endpoints used by the app")
    print(" by : Abdulrahman AL-Hakami")
    sys.exit(0)

def get_pid(target_app):
    """Find and return the PID of the target iOS application."""
    device = frida.get_usb_device()
    processes = device.enumerate_processes()
    
    for process in processes:
        if target_app.lower() in process.name.lower():
            print(f"[+] Founding {target_app}: PID {process.pid}")
            return process.pid
    
    print(f"[-] Process {target_app} not found.")
    sys.exit(1)

if len(sys.argv) < 2 or "--help" in sys.argv:
    show_help()

target = sys.argv[1]
api_filter = None
ssl_bypass_only = False
list_endpoints = False

if "--api" in sys.argv:
    api_index = sys.argv.index("--api") + 1
    if api_index < len(sys.argv):
        api_filter = sys.argv[api_index]
    else:
        print("[-] Error: Missing endpoint for --api option.")
        show_help()
elif "--ssl-bypass-only" in sys.argv:
    ssl_bypass_only = True
elif "--list-endpoints" in sys.argv:
    list_endpoints = True

try:
    if target.isdigit(): 
        pid = int(target)
    else:  
        pid = get_pid(target)
    
    device = frida.get_usb_device()
    session = device.attach(pid)
    print(f"[+] Attached to PID {pid}")

except Exception as e:
    print(f"[-] Error attaching to process: {e}")
    sys.exit(1)

script_code = """
// SSL Pinning Bypass
try {
    Interceptor.attach(Module.findExportByName(null, 'SecTrustEvaluate'), {
        onEnter: function(args) {
            console.log("[+] Bypassing SSL Pinning...");
        },
        onLeave: function(retval) {
            retval.replace(0);
        }
    });
    console.log("[+] SSL pinning disabled");
} catch (err) {
    console.log("[-] Error disabling SSL pinning: " + err);
}
"""

# Add API filtering if specified
if api_filter:
    script_code += f"""
    var classNSURLSession = ObjC.classes.NSURLSession;
    if (classNSURLSession) {{
        console.log("[+] Hooking NSURLSession");

        Interceptor.attach(classNSURLSession["- dataTaskWithRequest:completionHandler:"].implementation, {{
            onEnter: function(args) {{
                var request = new ObjC.Object(args[2]);
                var url = request.URL().absoluteString().toString();

                if (url.includes("{api_filter}")) {{  // Filtering by API Endpoint
                    console.log("\\n[+] Intercepted Target API Request: " + url);
                    console.log("Method: " + request.HTTPMethod().toString());
                    console.log("Headers: " + request.allHTTPHeaderFields().toString());

                    var body = request.HTTPBody();
                    if (body) {{
                        console.log("Body: " + body.bytes().toString());
                    }}
                }}
            }}
        }});
    }}
    """

if list_endpoints:
    script_code += """
    var classNSURLSession = ObjC.classes.NSURLSession;
    if (classNSURLSession) {
        console.log("[+] Extracting all API endpoints...");

        Interceptor.attach(classNSURLSession["- dataTaskWithRequest:completionHandler:"].implementation, {
            onEnter: function(args) {
                var request = new ObjC.Object(args[2]);
                var url = request.URL().absoluteString().toString();

                console.log("[+] API Call Detected: " + url);
            }
        });
    }
    """

try:
    script = session.create_script(script_code)
    script.load()
    print("[+] Script loaded successfully.")
    if api_filter:
        print(f"[+] Waiting for requests to {api_filter}")
    elif ssl_bypass_only:
        print("[+] SSL Pinning Bypass Only Mode Enabled.")
    elif list_endpoints:
        print("[+] Extracting API Endpoints in real-time...")
    sys.stdin.read() 
except Exception as e:
    print(f"[-] Error loading script: {e}")

