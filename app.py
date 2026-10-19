from flask import Flask, request, jsonify
from scorer import analyze_email, log_alert_to_csv

app = Flask(__name__)
API_TOKEN = "upwind-sec-token-2026" # סוד האותנטיקציה שלנו

@app.route('/analyze', methods=['POST'])
def analyze():
    # 1. בדיקת אותנטיקציה (Security Awareness)
    auth_header = request.headers.get('X-Upwind-Auth')
    if auth_header != API_TOKEN:
        return jsonify({"error": "Unauthorized. Invalid API Token."}), 401
    
    # 2. קבלת הנתונים מהתוסף
    email_data = request.json
    target_email = email_data.get("target_email", "unknown_user@upwind.com")
    
    # 3. הרצת מנוע הניקוד
    result = analyze_email(email_data)
    
    # 4. כתיבת טלמטריה ל-CSV (רק עבור התראות)
    log_alert_to_csv(email_data, result, target_email)
    
    return jsonify(result)

if __name__ == '__main__':
    app.run(port=5000)