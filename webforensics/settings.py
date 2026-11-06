import os
import secrets
from pathlib import Path
from .auth import load_auth_config

BASE_DIR = Path(__file__).resolve().parent.parent
SECRET_KEY = os.environ.get("WF_SECRET_KEY") or secrets.token_urlsafe(48)
DEBUG = False
WF_AUTH_ENABLED, WF_AUTH_USERNAME, WF_AUTH_PASSWORD = load_auth_config(os.environ)
ALLOWED_HOSTS = [h.strip() for h in os.environ.get("WF_ALLOWED_HOSTS", "localhost,127.0.0.1,[::1]").split(",") if h.strip()]
ROOT_URLCONF = "webforensics.urls"
WSGI_APPLICATION = "webforensics.wsgi.application"
INSTALLED_APPS = ["django.contrib.staticfiles"]
MIDDLEWARE = [
    "webforensics.middleware.PrivacyMiddleware",
    "webforensics.middleware.DeploymentMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "webforensics.auth.BasicAuthMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]
DATABASES = {}
CACHES = {"default": {"BACKEND": "django.core.cache.backends.dummy.DummyCache"}}
TEMPLATES = [{"BACKEND": "django.template.backends.django.DjangoTemplates", "DIRS": [BASE_DIR / "templates"]}]
STATIC_URL = "/static/"
STATICFILES_DIRS = [BASE_DIR / "static"]
WHITENOISE_USE_FINDERS = True
WHITENOISE_AUTOREFRESH = False
WHITENOISE_MAX_AGE = 0
LANGUAGE_CODE = "de"
TIME_ZONE = "UTC"
USE_TZ = True
DATA_UPLOAD_MAX_MEMORY_SIZE = 2 * 1024 * 1024
DATA_UPLOAD_MAX_NUMBER_FIELDS = 20
FILE_UPLOAD_MAX_MEMORY_SIZE = 0
FILE_UPLOAD_HANDLERS = []
CSRF_FAILURE_VIEW = "webforensics.views.csrf_failure"
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = "Strict"
CSRF_COOKIE_NAME = "wf_csrftoken"
# Public browser scheme, including HTTPS terminated by a reverse proxy.
PUBLIC_HTTPS = os.environ.get("WF_HTTPS", "0") == "1"
CSRF_COOKIE_SECURE = PUBLIC_HTTPS
CSRF_TRUSTED_ORIGINS = [o.strip() for o in os.environ.get("WF_TRUSTED_ORIGINS", "").split(",") if o.strip()]
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "no-referrer"
X_FRAME_OPTIONS = "DENY"
# No handlers, request/access/error logging, or exception payloads.
LOGGING_CONFIG = None
import logging
logging.disable(logging.CRITICAL)
