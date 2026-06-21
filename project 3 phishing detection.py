import re
from urllib.parse import urlparse

class PhishingTriageEngine:
    def __init__(self):
        # Configuration for authorized environments
        self.internal_domain = "decodelabs.com"
        
        # High-risk file extensions specified in requirements
        self.dangerous_extensions = ['.iso', '.js', '.scr', '.exe', '.vbs', '.bat']
        
        # Keywords tied to psychological cognitive triggers
        self.cognitive_triggers = {
            "Urgency": ["immediate", "urgent", "30 minutes", "expires", "act now", "action required"],
            "Authority": ["ceo", "president", "administrator", "it support", "legal", "hr compliance"],
            "Fear/Greed": ["lawsuit", "termination", "suspended", "unauthorized", "refund", "bonus", "prize"],
            "Curiosity": ["confidential", "secret", "review details", "invoice attached", "delivery update"]
        }

    def analyze_email_headers(self, display_name, from_address, return_path):
        """Checks for Sender Domain Mismatch and Spoofing."""
        flags = []
        is_spoofed = False

        # Check for Display Name Spoofing vs True Routing
        # If display name looks like internal personnel but address is public/external
        if ("decodelabs" in display_name.lower() or "ceo" in display_name.lower()) and self.internal_domain not in from_address:
            flags.append("[!] Display Name Spoofing: External address masquerading as internal authority.")
            is_spoofed = True
            
        # Check if Return-Path matches From address (Mismatch indicates routing redirection)
        if from_address.lower() != return_path.lower():
            flags.append(f"[!] Header Mismatch: 'From' ({from_address}) does not match 'Return-Path' ({return_path}).")
            is_spoofed = True

        return flags, is_spoofed

    def analyze_url(self, url):
        """Dissects URLs from right-to-left to identify subdomain traps and lookalike structures."""
        flags = []
        try:
            parsed_url = urlparse(url)
            hostname = parsed_url.hostname if parsed_url.hostname else parsed_url.path
            hostname = hostname.lower()

            # 1. Check for Subdomain Traps (Nesting trusted names far to the left)
            if "decodelabs" in hostname and not hostname.endswith(self.internal_domain):
                flags.append(f"[!] Subdomain Trap: Legitimate brand name used as a subdomain on rogue root domain.")

            # 2. Check for Combosquatting (Paired with security words or hyphens)
            security_keywords = ["secure", "login", "update", "verify", "portal", "auth"]
            if any(keyword in hostname for keyword in security_keywords) and "-" in hostname:
                flags.append("[!] Combosquatting Indicator: Hyphenated security keywords mixed into the domain structure.")

            # 3. Check for Typosquatting (Common lookalikes/homoglyphs manually simulated here)
            if "dec0de" in hostname or "decodelabs" in hostname.replace("l", "1").replace("o", "0"):
                flags.append("[!] Typosquatting/Homoglyph Alert: Visual manipulation detected (e.g., swapping letters for numbers).")

            return flags, hostname
        except Exception:
            return ["[!] Invalid or unparseable URL format."], "Unknown"

    def analyze_content(self, subject, body, attachment_name):
        """Scans for psychological behavioral triggers and high-risk attachments."""
        flags = []
        detected_triggers = []
        combined_text = f"{subject} {body}".lower()

        # Check for cognitive psychological triggers
        for trigger_type, keywords in self.cognitive_triggers.items():
            for keyword in keywords:
                if keyword in combined_text:
                    detected_triggers.append(f"{trigger_type} ('{keyword}')")
                    break # Trigger family found, move to next

        if detected_triggers:
            flags.append(f"[!] Behavioral Triggers Detected: {', '.join(detected_triggers)}")

        # Check for Fake Forwarded Chain artifacts
        if subject.lower().startswith("fw:") or "original message" in combined_text:
            flags.append("[!] Fake Forwarded Chain: Subject uses 'FW:' with no historic system logs to verify conversation.")

        # Check for High-Risk Attachments
        if attachment_name:
            if any(attachment_name.lower().endswith(ext) for ext in self.dangerous_extensions):
                flags.append(f"[!] Dangerous Attachment: File '{attachment_name}' utilizes an unsafe executable/script extension.")

        return flags

    def process_triage(self, email_data):
        """Main evaluation logic turning findings into a definitive operational action."""
        print("=" * 65)
        print("🔍 DECODELABS PHISHING TRIAGE RECONNAISSANCE REPORT")
        print("=" * 65)

        header_flags, spoofed = self.analyze_email_headers(
            email_data.get('display_name', ''), 
            email_data.get('from_address', ''), 
            email_data.get('return_path', '')
        )
        
        url_flags, true_root = self.analyze_url(email_data.get('embedded_url', ''))
        content_flags = self.analyze_content(
            email_data.get('subject', ''), 
            email_data.get('body', ''), 
            email_data.get('attachment', '')
        )

        all_flags = header_flags + url_flags + content_flags

        # Compile Evidence Metrics
        print(f"SENDER      : \"{email_data['display_name']}\" <{email_data['from_address']}>")
        print(f"TRUE ROOT   : {true_root}")
        print(f"ATTACHMENT  : {email_data['attachment'] if email_data['attachment'] else 'None'}")
        print("-" * 65)
        
        if all_flags:
            print(f"⚠️ DETECTED ANOMALIES ({len(all_flags)}):")
            for flag in all_flags:
                print(f" {flag}")
        else:
            print("✅ No automated technical anomalies flagged.")
        print("-" * 65)

        # Mandatory Action Logic Engine
        # Rules: Spoofing, dangerous links, or high-risk attachments trigger Immediate Malicious Action.
        if spoofed or len(url_flags) > 0 or any(".iso" in f or ".js" in f or ".scr" in f for f in content_flags):
            verdict = "🚨 MALICIOUS 🚨"
            actions = [
                "1. Block sender root domain gateway-wide.",
                "2. Purge this message completely from all enterprise inboxes.",
                "3. Escalate case logs immediately to the SOC / Incident Response Team."
            ]
        elif len(all_flags) > 0:
            verdict = "⚠️ SUSPICIOUS ⚠️"
            actions = [
                "1. Inject an active caution warning banner into the user interface.",
                "2. Flag account monitoring logs for unusual session traffic.",
                "3. Enqueue for deep secondary tier-2 evaluation."
            ]
        else:
            verdict = "🛡️ SAFE 🛡️"
            actions = [
                "1. Close out the triage support ticket.",
                "2. Move message to safe standard archive storage."
            ]

        print(f"FINAL DECISION VERDICT: {verdict}")
        print("\nMANDATORY INCIDENT RESPONSE ACTIONS:")
        for action in actions:
            print(f" {action}")
        print("=" * 65 + "\n")


# --- RUNNING REAL-WORLD TEST CASES ---
if __name__ == "__main__":
    triage_tool = PhishingTriageEngine()

    # Case 1: Malicious Phishing Campaign impersonating internal executive
    phishing_email = {
        "display_name": "DecodeLabs IT Administration",
        "from_address": "security-alert@decodelabs-secure-login.com",
        "return_path": "hacker-relay@gmail.com",
        "subject": "URGENT: Corporate Account Deactivation in 30 minutes",
        "body": "Your access is suspended due to an unauthorized attempt. Click here: http://www.decodelabs.tech.login-update.com/auth",
        "attachment": "vpn_configuration_patch.iso"
    }

    # Case 2: Clean/Safe Corporate Traffic
    legitimate_email = {
        "display_name": "HR Portal Operations",
        "from_address": "noreply@decodelabs.com",
        "return_path": "noreply@decodelabs.com",
        "subject": "Monthly Benefits Guide Overview",
        "body": "Team, please review the updated corporate benefits guide posted inside our internal intranet site.",
        "attachment": "benefits_guide.pdf"
    }

    # Execute Triage
    triage_tool.process_triage(phishing_email)
    triage_tool.process_triage(legitimate_email)