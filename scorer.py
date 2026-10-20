import difflib
import re
import csv
import os
from datetime import datetime

def safe_get_text(data_dict, key):
    val = data_dict.get(key, "")
    return val.lower() if isinstance(val, str) else ""

def contains_whole_word(text, word):
    pattern = rf'\b{re.escape(word)}\b'
    return bool(re.search(pattern, text))

# Rules

def check_domain_spoofing(sender_name, domain, protected_domain):
    # מוודא ששם השולח לא מתחזה לתפקיד רגיש בארגון מכתובת חיצונית 
    sensitive_roles = ["ceo", "cfo", "hr", "admin", "support", "it", "security", "upwind"]
    is_sensitive_sender = any(contains_whole_word(sender_name, role) for role in sensitive_roles)
    if is_sensitive_sender and domain != protected_domain:
        return 8, 9, "Sender Spoofing: Display name contains a privileged role, but the email address is external."
    return 0, 0, None

def check_financial_urgency(subject, body):
    # מחפש שילוב של מילות דחיפות ובקשות פיננסיות בתוכן המייל
    urgency_words = ["urgent", "action required", "immediate", "asap", "דחוף"]
    financial_words = ["invoice", "wire transfer", "payment", "account", "חשבונית"]
    
    has_urgency = any(contains_whole_word(subject, w) or contains_whole_word(body, w) for w in urgency_words)
    has_financial = any(contains_whole_word(subject, w) or contains_whole_word(body, w) for w in financial_words)
    
    if not has_financial and re.search(r'[$€₪]', subject + body):
        has_financial = True
        
    if has_urgency and has_financial:
        return 6, 7, "Financial Urgency: Email combines urgent language with financial requests."
    elif has_urgency or has_financial:
        return 4, 5, "Suspicious Language: Email contains urgency or financial keywords."
    return 0, 0, None

def check_suspicious_links(links):
    # סורק קישורים לאיתור מילות פישינג, מקצרי כתובות או כתובות IP ישירות
    if not isinstance(links, list):
        return 0, 0, None
    suspicious_url_keywords = ["login", "verify", "reset", "secure", "bit.ly", "tinyurl"]
    for link in links:
        if not isinstance(link, str):
            continue
        link_lower = link.lower()
        if any(keyword in link_lower for keyword in suspicious_url_keywords) or re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', link_lower):
            return 8, 6, "Suspicious Link: Found a link to a login page, URL shortener, or direct IP address."
    return 0, 0, None

def check_spam_tlds(domain):
    # מזהה סיומות דומיין זולות, נפוצות בספאם, או שייכות למדינות שאינן שגרתיות לעסקים
    spam_tlds = [".xyz", ".top", ".tk", ".cc", ".biz", ".info"]
    geo_tlds = [".ru", ".ir", ".kp", ".cn", ".sy"]
    
    domain_lower = domain.lower()
    
    if any(domain_lower.endswith(tld) for tld in spam_tlds):
        return 4, 7, "Spam TLDs: Domain uses a low-cost or often-abused top-level domain."
        
    if any(domain_lower.endswith(tld) for tld in geo_tlds):
        return 4, 7, "Suspicious Geo-TLD: Domain originates from a country code not typical for routine business."
        
    return 0, 0, None

def check_reply_to_mismatch(sender_email, reply_to):
    # משווה בין כתובת השולח לכתובת ההשבה לאיתור ניסיונות ניתוב מחדש של התקשורת
    if reply_to and sender_email:
        if sender_email.lower() != reply_to.lower():
            return 8, 9, "Reply-To Mismatch: The 'Reply-To' address differs from the 'From' address."
    return 0, 0, None

def check_dangerous_attachments(attachments):
    # מתריע על קבצים מצורפים מסוכנים או קבצים המוסווים בעזרת סיומת כפולה
    if not isinstance(attachments, list):
        return 0, 0, None
    dangerous_exts = [".exe", ".js", ".vbs", ".bat", ".scr", ".ps1", ".lnk", ".iso", ".hta"]
    document_exts = [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".docm", ".xlsm"]
    
    for att in attachments:
        if not isinstance(att, str):
            continue
        parts = att.lower().split('.')
        if len(parts) > 1:
            last_ext = "." + parts[-1]
            if last_ext in dangerous_exts:
                if len(parts) > 2 and ("." + parts[-2]) in document_exts:
                    return 10, 8, "Disguised Executable: Attachment masquerades as a document but is an executable file."
                return 9, 6, "Dangerous Attachment: Executable file attached."
    return 0, 0, None

def check_first_time_sender(is_first_time):
    # מוודא האם מדובר בשולח שמעולם לא התקיימה איתו תקשורת קודמת (מומש כדגל לבדיקה)
    if is_first_time is True:
        return 3, 3, "First-Time Sender: No prior communication history with this address."
    return 0, 0, None

def check_typosquatting(domain, protected_domain):
    # בודק אם הדומיין של השולח דומה ויזואלית לדומיין המוגן כדי לזהות שגיאות כתיב מכוונות
    if domain and domain != protected_domain:
        similarity = difflib.SequenceMatcher(None, domain, protected_domain).ratio()
        if similarity > 0.8:
            return 9, 9, f"Typosquatting: Domain '{domain}' is visually similar to the protected domain but not identical."
    return 0, 0, None

def check_punycode(domain):
    # מזהה שימוש בתווים בינלאומיים מוסווים (IDN) בדומיין
    if domain.startswith("xn--"):
        return 8, 7, "Punycode Attack: Domain contains internationalized characters often used for evasion."
    return 0, 0, None




# Orchestrator

def analyze_email(email_data):
    sender_email = safe_get_text(email_data, "sender_email")
    sender_name = safe_get_text(email_data, "sender_name")
    reply_to = safe_get_text(email_data, "reply_to")
    subject = safe_get_text(email_data, "subject")
    body = safe_get_text(email_data, "body")
    links = email_data.get("links", [])
    attachments = email_data.get("attachments", [])
    is_first_time = email_data.get("is_first_time_sender", False)
    
    
    domain = sender_email.split('@')[-1] if '@' in sender_email else ""
    protected_domain = "upwind.com"
    
    total_score = 0
    reasons = []
    triggered_rules = []
    
    rules = {
        "domain_spoofing": lambda: check_domain_spoofing(sender_name, domain, protected_domain),
        "typosquatting": lambda: check_typosquatting(domain, protected_domain),
        "punycode": lambda: check_punycode(domain),
        "financial_urgency": lambda: check_financial_urgency(subject, body),
        "suspicious_links": lambda: check_suspicious_links(links),
        "dangerous_attachments": lambda: check_dangerous_attachments(attachments),
        "first_time_sender": lambda: check_first_time_sender(is_first_time),
        "spam_tlds": lambda: check_spam_tlds(domain),
        "reply_to_mismatch": lambda: check_reply_to_mismatch(sender_email, reply_to)
    }

    for rule_name, rule_func in rules.items():
        try:
            impact, confidence, reason = rule_func()
            if impact > 0:
                rule_score = impact * confidence
                total_score += rule_score
                reasons.append(f"{reason} (Impact: {impact}/10, Confidence: {confidence}/10)")
                triggered_rules.append(rule_name)
        except Exception:
            continue

    if "financial_urgency" in triggered_rules and "first_time_sender" in triggered_rules:
        reasons.insert(0, "🚨 Contextual Alert: Sender requests urgent financial action, but has no prior communication history.")

    capped_score = min(total_score, 100)
    
    if capped_score >= 60:
        verdict = "Malicious"
    elif capped_score >= 30:
        verdict = "Suspicious"
    else:
        verdict = "Safe"

    return {
        "score": capped_score,
        "verdict": verdict,
        "reasons": reasons
    }

def log_alert_to_csv(email_data, result, target_email):
    """שומר התראות לטבלת CSV יומית"""
    if result["score"] < 30:
        return 
        
    # יצירת שם קובץ דינמי לפי התאריך של היום
    current_date = datetime.now().strftime("%Y-%m-%d")
    file_path = f"alerts_telemetry_{current_date}.csv"
    
    file_exists = os.path.isfile(file_path)
    
    with open(file_path, mode="a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        if not file_exists:
            writer.writerow(["Timestamp", "Target_Email", "Sender_Email", "Score", "Verdict", "Alert_Reasons"])
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        sender = safe_get_text(email_data, "sender_email")
        score = result["score"]
        verdict = result["verdict"]
        reasons = " | ".join(result["reasons"])
        
        writer.writerow([timestamp, target_email, sender, score, verdict, reasons])