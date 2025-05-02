import time

_metrics = []

def record(event: str, duration_ms: float):
    _metrics.append({"event": event, "duration_ms": duration_ms, "ts": time.time()})

def get_metrics():
    return list(_metrics)
