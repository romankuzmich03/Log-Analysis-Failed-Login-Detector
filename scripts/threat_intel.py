KNOWN_BAD_IPS = {
    "192.168.1.55",
    "10.0.0.25"
}


def check_ip_reputation(ip_address):

    if ip_address in KNOWN_BAD_IPS:

        return {
            "status": "malicious",
            "source": "local threat database"
        }


    return {
        "status": "unknown",
        "source": "local threat database"
    }