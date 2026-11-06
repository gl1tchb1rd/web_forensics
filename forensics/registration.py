import tldextract

from .network import normalize_domain

# Packaged PSL snapshot only: no network requests and no filesystem cache.
_extract = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=(),
                                fallback_to_snapshot=True, include_psl_private_domains=False)


def registration_domain(value):
    domain = normalize_domain(value)
    result = _extract(domain)
    if not result.suffix:
        return domain, "Die Endung ist im mitgelieferten Public-Suffix-Snapshot nicht bekannt; für Registrierungsabfragen wird die vollständige Eingabe verwendet."
    if not result.domain:
        raise ValueError("Bitte eine registrierte Domain eingeben, nicht nur eine öffentliche Domainendung.")
    return result.top_domain_under_public_suffix, ""
