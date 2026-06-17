"""
Stars and Stripes Pool Service — Flask Web Application
======================================================
Secure, single-file Flask website for a pool service business.

Requirements:
    pip install flask gunicorn requests

Run locally:
    python clearwater_pools.py

Deploy on Render:
    Build command:  pip install -r requirements.txt
    Start command:  gunicorn clearwater_pools:app --bind 0.0.0.0:$PORT

IMPORTANT — Set these in Render's Environment Variables dashboard:
    SECRET_KEY    →  generate with: python -c "import secrets; print(secrets.token_hex(32))"
                     Without this, every app restart invalidates all sessions and breaks CSRF.
    BREVO_API_KEY →  your Brevo API key (found in Brevo → Settings → API Keys)
    DEBUG         →  false
"""

import os
import re
import time
import secrets
import requests
from collections import defaultdict
from flask import Flask, render_template_string, request, redirect, flash, url_for, session

# ╔══════════════════════════════════════════════════════════════════╗
# ║                    APP & SECURITY CONFIG                         ║
# ╚══════════════════════════════════════════════════════════════════╝

app = Flask(__name__)

# CRITICAL: Set SECRET_KEY as an environment variable on Render.
# Without it, a new random key is generated on every restart/deploy,
# which invalidates all sessions and causes every form submission to fail
# with a CSRF error until the user refreshes the page.
app.config["SECRET_KEY"]              = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# app.config["SESSION_COOKIE_SECURE"] = True  # Uncomment once live on HTTPS


# ╔══════════════════════════════════════════════════════════════════╗
# ║                        BUSINESS DATA                             ║
# ╚══════════════════════════════════════════════════════════════════╝

SERVICES = [
    {
        "icon": "📅",
        "name": "Monthly Service",
        "price": "$125",
        "desc": "Includes wall sweeping, chemical balance, sweeper cleaning, "
                "plumbing assessment, and surface cleaning to ensure your pool "
                "is always in top condition.",
    },
    {
        "icon": "💧",
        "name": "Filter Cleaning",
        "price": "$95",
        "desc": "Includes the removal, cleaning, and reinstallation of your pool filter.",
    },
    {
        "icon": "🔧",
        "name": "Miscellaneous Repairs",
        "price": "Upon Request",
        "desc": "Includes minor repairs, major repairs, or any fixes you need — "
                "no matter the complexity.",
    },
]

CONTACT_INFO = {
    "phone":     "(559) 281-8167",
    "email":     "starsandstripespoolservice@gmail.com",
    "instagram": "@StarsAndStripesPoolService",
    "location":  "Fresno, CA and surrounding areas",
}

WHY_US = [
    {
        "icon": "🎖️",
        "title": "Veteran Owned",
        "desc": "Proudly veteran-owned and operated, with the discipline and "
                "dedication you'd expect from those who served.",
    },
    {
        "icon": "📍",
        "title": "Local",
        "desc": "Proudly serving Fresno and the Central Valley — "
                "your neighbors, not a franchise.",
    },
    {
        "icon": "🕐",
        "title": "Consistent Schedule",
        "desc": "We work around your schedule. Weekly visits, thorough "
                "communication, no surprises.",
    },
]


# ╔══════════════════════════════════════════════════════════════════╗
# ║                  RATE LIMITER (In-Memory)                        ║
# ╚══════════════════════════════════════════════════════════════════╝

_rate_store: dict = defaultdict(list)
RATE_MAX    = 5
RATE_WINDOW = 3600


def is_rate_limited(ip: str) -> bool:
    """Returns True if this IP has exceeded 5 submissions per hour."""
    now    = time.time()
    cutoff = now - RATE_WINDOW
    _rate_store[ip] = [t for t in _rate_store[ip] if t > cutoff]
    if len(_rate_store[ip]) >= RATE_MAX:
        return True
    _rate_store[ip].append(now)
    return False


# ╔══════════════════════════════════════════════════════════════════╗
# ║                      CSRF PROTECTION                             ║
# ╚══════════════════════════════════════════════════════════════════╝

def get_csrf_token() -> str:
    """Generates (or retrieves) a per-session CSRF token."""
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(32)
    return session["_csrf"]

def validate_csrf(submitted: str) -> bool:
    """Constant-time comparison prevents timing side-channel attacks."""
    stored = session.get("_csrf", "")
    return secrets.compare_digest(submitted or "", stored)

@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=get_csrf_token)


# ╔══════════════════════════════════════════════════════════════════╗
# ║                    SECURITY HEADERS                              ║
# ╚══════════════════════════════════════════════════════════════════╝

@app.after_request
def add_security_headers(response):
    h = response.headers
    h["X-Content-Type-Options"] = "nosniff"
    h["X-Frame-Options"]         = "DENY"
    h["Referrer-Policy"]         = "strict-origin-when-cross-origin"
    h["Permissions-Policy"]      = "camera=(), microphone=(), geolocation=()"
    h["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline' 'unsafe-eval'; "
        "style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; "
        "font-src https://fonts.gstatic.com; "
        "img-src 'self' data: https:; "
        "connect-src 'self';"
    )
    return response


# ╔══════════════════════════════════════════════════════════════════╗
# ║                    INPUT VALIDATION                              ║
# ╚══════════════════════════════════════════════════════════════════╝

EMAIL_RE  = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
MAX_NAME  = 100
MAX_EMAIL = 254
MAX_MSG   = 2000

def validate_contact(name: str, email: str, message: str) -> list:
    errors = []
    if not name or len(name) > MAX_NAME:
        errors.append(f"Please enter a valid name (max {MAX_NAME} characters).")
    if not email or not EMAIL_RE.match(email) or len(email) > MAX_EMAIL:
        errors.append("Please enter a valid email address.")
    if not message or len(message) > MAX_MSG:
        errors.append(f"Message must be between 1 and {MAX_MSG} characters.")
    return errors


# ╔══════════════════════════════════════════════════════════════════╗
# ║                  EMAIL DELIVERY                                  ║
# ╚══════════════════════════════════════════════════════════════════╝

BREVO_SEND_URL   = "https://api.brevo.com/v3/smtp/email"
BUSINESS_EMAIL   = "starsandstripespoolservice@gmail.com"
BUSINESS_NAME    = "Stars & Stripes Pool Service"


def send_notification(name: str, email: str, message: str) -> None:
    """
    Sends contact form submissions via Brevo's transactional email API.
    Falls back to console logging (visible in Render's log dashboard) when
    BREVO_API_KEY is not set.
    """
    safe_name  = re.sub(r"[\r\n]", "", name)
    safe_email = re.sub(r"[\r\n]", "", email)

    api_key = os.environ.get("BREVO_API_KEY")
    if not api_key:
        print("\n--- [Stars & Stripes] New Contact Submission ---")
        print(f"  Name:    {safe_name}")
        print(f"  Email:   {safe_email}")
        print(f"  Message: {message[:100]}{'...' if len(message) > 100 else ''}\n")
        return

    try:
        payload = {
            "sender":      {"name": BUSINESS_NAME, "email": BUSINESS_EMAIL},
            "to":          [{"email": BUSINESS_EMAIL, "name": BUSINESS_NAME}],
            "replyTo":     {"email": safe_email, "name": safe_name},
            "subject":     f"Stars & Stripes — Inquiry from {safe_name}",
            "textContent": (
                f"New inquiry via the Stars & Stripes website:\n\n"
                f"Name:    {safe_name}\n"
                f"Email:   {safe_email}\n\n"
                f"Message:\n{message}"
            ),
        }
        resp = requests.post(
            BREVO_SEND_URL,
            json=payload,
            headers={"api-key": api_key, "Content-Type": "application/json"},
            timeout=10,
        )
        resp.raise_for_status()
        print(f"[Email OK] Notification sent for inquiry from {safe_name}")

    except Exception as exc:
        print(f"[Email Error] {type(exc).__name__}: {exc}")


# ╔══════════════════════════════════════════════════════════════════╗
# ║                      HTML TEMPLATE                               ║
# ╚══════════════════════════════════════════════════════════════════╝

HTML = """
<!DOCTYPE html>
<html lang="en" class="scroll-smooth">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="description"
        content="Professional pool cleaning and maintenance in Fresno, CA.
                 Veteran-owned, transparent pricing, reliable weekly service.">
  <title>Stars &amp; Stripes Pool Service — Fresno, CA</title>

  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;500;600;700;800;900&display=swap"
        rel="stylesheet">

  <script src="https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4"></script>

  <style>
    body { font-family: 'Outfit', sans-serif; }

    .hero-wave {
      clip-path: ellipse(110% 100% at 50% 0%);
      padding-bottom: 5rem;
    }

    .service-card {
      transition: transform 0.3s ease, box-shadow 0.3s ease;
    }
    .service-card:hover {
      transform: translateY(-6px);
      box-shadow: 0 16px 40px -12px rgba(15, 23, 42, 0.15);
    }

    .reveal {
      opacity: 0;
      transform: translateY(20px);
      transition: opacity 0.55s ease, transform 0.55s ease;
    }
    .reveal.visible {
      opacity: 1;
      transform: translateY(0);
    }
  </style>
</head>

<body class="bg-slate-50 text-slate-800">

  <!-- STICKY HEADER -->
  <header class="sticky top-0 z-50 bg-blue-950/96 backdrop-blur-sm shadow-lg">
    <div class="max-w-6xl mx-auto px-6 py-4 flex justify-between items-center">
      <a href="#" class="text-white text-xl font-extrabold tracking-tight hover:text-slate-200 transition">
        ⭐ Stars &amp; Stripes Pools
      </a>
      <nav class="flex items-center gap-6 text-sm font-semibold">
        <a href="#services" class="text-slate-300 hover:text-white transition hidden sm:inline">Services</a>
        <a href="#why-us"   class="text-slate-300 hover:text-white transition hidden sm:inline">Why Us</a>
        <a href="#contact"
           class="bg-red-600 hover:bg-red-500 active:bg-red-700 text-white px-5 py-2 rounded-lg transition shadow font-bold">
          Get a Quote
        </a>
      </nav>
    </div>
  </header>

  <!-- HERO -->
  <section class="hero-wave bg-gradient-to-br from-blue-900 via-blue-950 to-slate-900 text-white pt-20">
    <div class="max-w-6xl mx-auto px-6 text-center">
      <p class="text-blue-300 uppercase tracking-[0.2em] text-xs font-bold mb-5">
        Fresno's Trusted Pool Pros
      </p>
      <h1 class="text-5xl md:text-7xl font-black leading-[1.05] mb-6 tracking-tight">
        Stars &amp; Stripes Pool Service.<br>
        <span class="text-red-500">American Made Quality.</span>
      </h1>

      <!-- Logo: place logo.png inside a /static folder next to SASPS.py -->
      <img src="/static/logo.png"
           alt="Stars and Stripes Pool Service Logo"
           class="ml-2 mt-6 h-32 w-auto object-contain drop-shadow-lg translate-y-10 scale-225"
           onerror="this.style.display='none'">

      <p class="text-slate-300 text-lg md:text-xl mb-10 max-w-xl mx-auto leading-relaxed mt-6">
        Professional pool maintenance, chemical balancing, and deep cleaning —
        so you can just enjoy the swim.
      </p>
      <div class="flex flex-col sm:flex-row gap-4 justify-center pb-4">
        <a href="#contact"
           class="bg-white text-blue-950 font-black px-8 py-3.5 rounded-xl shadow-xl hover:bg-slate-100 transition text-base">
          Book a Free Quote →
        </a>
        <a href="#services"
           class="border border-white/40 text-white font-semibold px-8 py-3.5 rounded-xl hover:bg-white/10 transition text-base">
          View Services
        </a>
      </div>
    </div>
  </section>

  <!-- FLASH MESSAGES -->
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      <div class="max-w-6xl mx-auto px-6 mt-8 space-y-3">
        {% for category, message in messages %}
          <div class="flex items-center gap-3 px-5 py-4 rounded-xl border font-medium
            {% if category == 'error' %}bg-red-50 border-red-200 text-red-700
            {% else %}bg-emerald-50 border-emerald-200 text-emerald-700{% endif %}">
            <span class="text-lg">{{ '⚠️' if category == 'error' else '✅' }}</span>
            <span>{{ message }}</span>
          </div>
        {% endfor %}
      </div>
    {% endif %}
  {% endwith %}

  <!-- SERVICES -->
  <section id="services" class="max-w-6xl mx-auto px-6 py-20">
    <div class="text-center mb-14">
      <p class="text-blue-900 uppercase tracking-[0.18em] text-xs font-bold mb-3">What We Offer</p>
      <h2 class="text-4xl md:text-5xl font-black text-slate-900 tracking-tight">Services &amp; Pricing</h2>
      <p class="text-slate-500 mt-4 max-w-lg mx-auto">
        Transparent pricing, no hidden fees. Pick the plan that fits your pool.
      </p>
    </div>
    <div class="grid md:grid-cols-3 gap-7">
      {% for service in services %}
      <div class="service-card reveal bg-white rounded-2xl border border-slate-200 shadow-sm p-8">
        <div class="text-5xl mb-5">{{ service.icon }}</div>
        <h3 class="text-xl font-bold text-slate-900 mb-1">{{ service.name }}</h3>
        <p class="text-3xl font-black text-red-600 mb-4">{{ service.price }}</p>
        <p class="text-slate-500 leading-relaxed text-sm">{{ service.desc }}</p>
      </div>
      {% endfor %}
    </div>
  </section>

  <!-- WHY US -->
  <section id="why-us" class="bg-slate-100 border-y border-slate-200 py-20">
    <div class="max-w-6xl mx-auto px-6">
      <div class="text-center mb-14">
        <p class="text-blue-900 uppercase tracking-[0.18em] text-xs font-bold mb-3">The Stars &amp; Stripes Difference</p>
        <h2 class="text-4xl md:text-5xl font-black text-slate-900 tracking-tight">Why Choose Us?</h2>
      </div>
      <div class="grid sm:grid-cols-3 gap-6">
        {% for item in why_us %}
        <div class="reveal bg-white rounded-2xl p-7 shadow-sm border border-slate-200 text-center hover:shadow-md transition">
          <div class="text-4xl mb-3">{{ item.icon }}</div>
          <h4 class="font-bold text-slate-900 mb-2">{{ item.title }}</h4>
          <p class="text-slate-500 text-sm leading-relaxed">{{ item.desc }}</p>
        </div>
        {% endfor %}
      </div>
    </div>
  </section>

  <!-- CONTACT -->
  <section id="contact" class="bg-blue-950 text-white py-20">
    <div class="max-w-6xl mx-auto px-6 grid md:grid-cols-2 gap-16">

      <!-- Info column -->
      <div class="reveal">
        <p class="text-red-400 uppercase tracking-[0.18em] text-xs font-bold mb-3">Let's Talk</p>
        <h2 class="text-4xl md:text-5xl font-black tracking-tight mb-5">Get In Touch</h2>
        <p class="text-slate-400 mb-10 leading-relaxed max-w-sm">
          Ready for a cleaner pool? Have questions about pricing?
          We typically respond within a few hours.
        </p>

        <div class="space-y-4">
          <!-- FIX: tel link now matches the actual phone number (559) 281-8167 -->
          <a href="tel:+15592818167" class="flex items-center gap-4 group">
            <div class="w-12 h-12 rounded-xl bg-red-600 group-hover:bg-red-500 transition flex items-center justify-center text-xl shrink-0">📞</div>
            <div>
              <p class="text-xs text-slate-400 uppercase tracking-wide font-semibold">Phone</p>
              <p class="font-semibold group-hover:text-red-400 transition">{{ contact.phone }}</p>
            </div>
          </a>
          <a href="mailto:{{ contact.email }}" class="flex items-center gap-4 group">
            <div class="w-12 h-12 rounded-xl bg-red-600 group-hover:bg-red-500 transition flex items-center justify-center text-xl shrink-0">✉️</div>
            <div>
              <p class="text-xs text-slate-400 uppercase tracking-wide font-semibold">Email</p>
              <p class="font-semibold group-hover:text-red-400 transition">{{ contact.email }}</p>
            </div>
          </a>
          <!-- FIX: Instagram URL now matches the handle @StarsAndStripesPoolService -->
          <a href="https://instagram.com/StarsAndStripesPoolService" target="_blank" rel="noopener noreferrer"
             class="flex items-center gap-4 group">
            <div class="w-12 h-12 rounded-xl bg-red-600 group-hover:bg-red-500 transition flex items-center justify-center text-xl shrink-0">📸</div>
            <div>
              <p class="text-xs text-slate-400 uppercase tracking-wide font-semibold">Instagram</p>
              <p class="font-semibold group-hover:text-red-400 transition">{{ contact.instagram }}</p>
            </div>
          </a>
          <div class="flex items-center gap-4">
            <div class="w-12 h-12 rounded-xl bg-red-600 flex items-center justify-center text-xl shrink-0">📍</div>
            <div>
              <p class="text-xs text-slate-400 uppercase tracking-wide font-semibold">Location</p>
              <p class="font-semibold">{{ contact.location }}</p>
            </div>
          </div>
        </div>
      </div>

      <!-- Form column -->
      <div class="reveal bg-blue-900 p-8 rounded-2xl border border-blue-800 shadow-2xl">
        <h3 class="text-2xl font-black mb-6">Send a Message</h3>
        <form action="/submit-contact" method="POST" class="space-y-5">
          <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">

          <div>
            <label class="block text-sm font-semibold text-slate-300 mb-1.5">Your Name</label>
            <input type="text" name="name" required maxlength="100" autocomplete="name"
                   placeholder="John Smith"
                   class="w-full bg-blue-950 border border-blue-800 rounded-lg px-4 py-2.5 text-white
                          placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-red-500
                          focus:border-transparent transition text-sm">
          </div>

          <div>
            <label class="block text-sm font-semibold text-slate-300 mb-1.5">Email Address</label>
            <input type="email" name="email" required maxlength="254" autocomplete="email"
                   placeholder="john@example.com"
                   class="w-full bg-blue-950 border border-blue-800 rounded-lg px-4 py-2.5 text-white
                          placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-red-500
                          focus:border-transparent transition text-sm">
          </div>

          <div>
            <label class="block text-sm font-semibold text-slate-300 mb-1.5">
              Message
              <span class="text-slate-400 font-normal">(max 2,000 chars)</span>
            </label>
            <textarea name="message" rows="4" required maxlength="2000"
                      placeholder="Tell us about your pool and what service you need..."
                      class="w-full bg-blue-950 border border-blue-800 rounded-lg px-4 py-2.5 text-white
                             placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-red-500
                             focus:border-transparent transition resize-none text-sm"></textarea>
          </div>

          <button type="submit"
                  class="w-full bg-red-600 hover:bg-red-500 active:bg-red-700 transition text-white
                         font-black py-3 rounded-xl shadow-lg text-base">
            Send Message →
          </button>

          <p class="text-xs text-slate-400 text-center">
            🔒 Your information is never shared or sold.
          </p>
        </form>
      </div>

    </div>
  </section>

  <!-- FOOTER -->
  <footer class="bg-blue-950 text-slate-400 border-t border-blue-900 py-8">
    <div class="max-w-6xl mx-auto px-6 flex flex-col sm:flex-row justify-between items-center gap-4 text-sm">
      <p class="font-bold text-white">⭐ Stars &amp; Stripes Pool Service</p>
      <p>© 2026 Stars &amp; Stripes. All rights reserved.</p>
      <nav class="flex gap-5">
        <a href="#services" class="hover:text-slate-300 transition">Services</a>
        <a href="#why-us"   class="hover:text-slate-300 transition">Why Us</a>
        <a href="#contact"  class="hover:text-slate-300 transition">Contact</a>
      </nav>
    </div>
  </footer>

  <script>
    const observer = new IntersectionObserver(
      (entries) => entries.forEach(e => { if (e.isIntersecting) e.target.classList.add('visible'); }),
      { threshold: 0.12 }
    );
    document.querySelectorAll('.reveal').forEach(el => observer.observe(el));
  </script>

</body>
</html>
"""


# ╔══════════════════════════════════════════════════════════════════╗
# ║                          ROUTES                                  ║
# ╚══════════════════════════════════════════════════════════════════╝

@app.route("/")
def home():
    return render_template_string(HTML, services=SERVICES, contact=CONTACT_INFO, why_us=WHY_US)

@app.route("/submit-contact", methods=["POST"])
def submit_contact():
    # Step 1: CSRF validation
    if not validate_csrf(request.form.get("csrf_token", "")):
        flash("Invalid request token. Please refresh the page and try again.", "error")
        return redirect(url_for("home"))

    # Step 2: Rate limiting
    client_ip = (
        request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")
        .split(",")[0]
        .strip()
    )
    if is_rate_limited(client_ip):
        flash("Too many submissions. Please wait before trying again.", "error")
        return redirect(url_for("home"))

    # Step 3: Sanitize & validate
    name    = request.form.get("name",    "").strip()
    email   = request.form.get("email",   "").strip().lower()
    message = request.form.get("message", "").strip()

    errors = validate_contact(name, email, message)
    if errors:
        flash(errors[0], "error")
        return redirect(url_for("home"))

    # Step 4: Deliver notification
    send_notification(name, email, message)

    flash("Thanks! Your message was sent — we'll be in touch shortly. 🎉", "success")
    return redirect(url_for("home"))


# ╔══════════════════════════════════════════════════════════════════╗
# ║                        ENTRY POINT                               ║
# ╚══════════════════════════════════════════════════════════════════╝

if __name__ == "__main__":
    debug_mode = os.environ.get("DEBUG", "true").lower() == "true"
    app.run(debug=debug_mode)
