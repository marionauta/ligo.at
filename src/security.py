from urllib.parse import urlparse
import httpx


# this is a crude/partial filter that looks at HTTPS URLs and checks if they seem "safe" for server-side requests (SSRF). This is only a partial mitigation, the actual HTTP client also needs to prevent other attacks and behaviors.
# this isn't a fully complete or secure implementation
def is_safe_url(url: str) -> bool:
    parts = urlparse(url)
    if not (
        parts.scheme == "https"
        and parts.hostname is not None
        and parts.hostname == parts.netloc
        and parts.username is None
        and parts.password is None
        and parts.port is None
    ):
        return False

    segments = parts.hostname.split(".")
    if not (
        len(segments) >= 2
        and segments[-1] not in ["local", "arpa", "internal", "localhost"]
    ):
        return False

    if segments[-1].isdigit():
        return False

    return True


class HardenedHttp:
    def get_session(self) -> httpx.Client:
        return httpx.Client(
            timeout=httpx.Timeout(20, connect=5),
            follow_redirects=False,
            headers={
                "User-Agent": "ligo.at/0",
            },
        )


hardened_http = HardenedHttp()
