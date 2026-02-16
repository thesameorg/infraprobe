import asyncio
import hashlib
import hmac
import ipaddress
import logging
import socket
from datetime import UTC, datetime
from urllib.parse import urlparse

import httpx

from infraprobe.blocklist import BlockedTargetError, _is_blocked_ip
from infraprobe.models import Job

logger = logging.getLogger("infraprobe.webhook")


def _validate_webhook_url(url: str) -> str:
    """Validate webhook URL scheme and hostname against SSRF blocklist."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Webhook URL must use http or https scheme, got: {parsed.scheme}")
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Webhook URL has no hostname")

    # Check if hostname is a literal IP
    try:
        addr = ipaddress.ip_address(hostname)
        if _is_blocked_ip(addr):
            raise BlockedTargetError(f"Webhook URL points to blocked IP: {hostname}")
        return url
    except ValueError:
        pass

    # Hostname is a domain — resolve and check all IPs
    try:
        addrinfos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"Cannot resolve webhook hostname {hostname}: {exc}") from exc

    for _family, _, _, _, sockaddr in addrinfos:
        ip_str = sockaddr[0]
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if _is_blocked_ip(addr):
            raise BlockedTargetError(f"Webhook hostname {hostname} resolves to blocked IP {ip_str}")

    return url


def _build_payload(job: Job) -> dict:
    """Build the webhook callback payload."""
    event = "scan.completed" if job.status == "completed" else "scan.failed"
    payload: dict = {
        "event": event,
        "job_id": job.job_id,
        "status": str(job.status),
        "created_at": job.created_at.isoformat(),
        "completed_at": job.updated_at.isoformat(),
        "request": job.request.model_dump(mode="json"),
    }
    if job.result is not None:
        payload["result"] = job.result.model_dump(mode="json")
    if job.error is not None:
        payload["error"] = job.error
    return payload


def _sign_payload(body: bytes, secret: str) -> str:
    """Compute HMAC-SHA256 signature for the payload."""
    mac = hmac.new(secret.encode(), body, hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


async def deliver_webhook(
    job: Job,
    url: str,
    *,
    secret: str | None,
    timeout: float,
    max_retries: int,
) -> bool:
    """POST job result to the webhook URL. Returns True if delivered (2xx), False otherwise."""
    payload = _build_payload(job)

    headers = {"Content-Type": "application/json"}

    async with httpx.AsyncClient(timeout=httpx.Timeout(timeout), verify=True) as client:
        # Serialize once for consistent HMAC
        body = httpx.Request("POST", url, json=payload).content
        if secret:
            headers["X-InfraProbe-Signature"] = _sign_payload(body, secret)

        for attempt in range(max_retries):
            try:
                resp = await client.post(url, content=body, headers=headers)
                if 200 <= resp.status_code < 300:
                    logger.info(
                        "webhook delivered",
                        extra={
                            "job_id": job.job_id,
                            "url": url,
                            "status_code": resp.status_code,
                            "attempt": attempt + 1,
                        },
                    )
                    return True
                logger.warning(
                    "webhook non-2xx response",
                    extra={"job_id": job.job_id, "url": url, "status_code": resp.status_code, "attempt": attempt + 1},
                )
            except (httpx.HTTPError, OSError) as exc:
                logger.warning(
                    "webhook delivery error",
                    extra={"job_id": job.job_id, "url": url, "error": str(exc), "attempt": attempt + 1},
                )

            if attempt < max_retries - 1:
                delay = 2**attempt  # 1s, 2s, 4s
                await asyncio.sleep(delay)

    logger.error("webhook delivery failed after all retries", extra={"job_id": job.job_id, "url": url})
    return False


async def maybe_deliver_webhook(
    job: Job,
    url: str | None,
    secret: str | None,
    *,
    store,
    timeout: float,
    max_retries: int,
) -> None:
    """Deliver webhook if url is provided, and update job webhook status."""
    if not url:
        return

    delivered = await deliver_webhook(job, url, secret=secret, timeout=timeout, max_retries=max_retries)
    now = datetime.now(UTC) if delivered else None
    status = "delivered" if delivered else "failed"
    await store.update_webhook_status(job.job_id, status, now)
