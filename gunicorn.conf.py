import os

bind = "0.0.0.0:8000"
workers = int(os.environ.get("WF_WORKERS", "2"))
worker_class = "gthread"
threads = 2
timeout = 150
graceful_timeout = 15
preload_app = True  # One ephemeral report-signing key shared by all workers.
worker_tmp_dir = "/dev/shm"
accesslog = None
errorlog = "/dev/null"
capture_output = False
limit_request_line = 4094
limit_request_fields = 50
limit_request_field_size = 8190
