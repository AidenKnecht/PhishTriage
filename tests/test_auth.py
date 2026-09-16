from phishtriage.auth import analyze_auth, parse_authentication_results, spf_check
from phishtriage.models import AuthStatus
from phishtriage.parser import parse_bytes, parse_file
from phishtriage.rulesdata import Brand, organizational_domain, same_org

BRANDS = (
    Brand("microsoft", ("microsoft.com", "office.com")),
    Brand("paypal", ("paypal.com",)),
    Brand("ups", ("ups.com",)),
    Brand(
        "acme",
    ),
)


def _auth(raw: str, **kw):
    return analyze_auth(parse_bytes(raw.encode()), brands=BRANDS, **kw)


def test_parse_rfc8601_with_comments_and_props():
    header = (
        "mx.example.com; spf=pass (sender IP is 192.0.2.10) smtp.mailfrom=bounce@example.net; "
        "dkim=pass (2048-bit key) header.d=example.net header.s=sel1; "
        'dmarc=pass (p=REJECT sp=NONE) header.from="example.net"; compauth=pass reason=100'
    )
    results = {r.mechanism: r for r in parse_authentication_results(header)}

    assert results["spf"].status is AuthStatus.PASS
    assert results["spf"].domain == "example.net"
    assert results["dkim"].domain == "example.net"
    assert results["dmarc"].domain == "example.net"
    assert "compauth" not in results


def test_parse_unknown_and_hardfail_values():
    results = {r.mechanism: r for r in parse_authentication_results("x; spf=hardfail; dkim=weird")}

    assert results["spf"].status is AuthStatus.FAIL
    assert results["dkim"].status is AuthStatus.NONE
    assert "unrecognised" in results["dkim"].detail


def test_fully_aligned_pass(fixtures):
    a = analyze_auth(parse_file(fixtures / "simple.eml"), brands=BRANDS)

    assert a.spf.status is AuthStatus.PASS
    assert a.dkim.status is AuthStatus.PASS
    assert a.dmarc.status is AuthStatus.PASS
    assert a.spf_aligned is True
    assert a.dkim_aligned is True
    assert a.reply_to_mismatch is False
    assert a.display_name_spoof is False
    assert a.no_auth_headers is False
    assert a.flags == []


def test_dkim_pass_on_unrelated_domain_is_not_aligned():
    a = _auth(
        "From: Support <support@bank.example>\n"
        "Return-Path: <x@attacker.example>\n"
        "DKIM-Signature: v=1; a=rsa-sha256; d=attacker.example; s=k1; h=from; b=abc\n"
        "Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=attacker.example; "
        "dkim=pass header.d=attacker.example; dmarc=fail header.from=bank.example\n\nx"
    )

    assert a.spf.status is AuthStatus.PASS
    assert a.dkim.status is AuthStatus.PASS
    assert a.dmarc.status is AuthStatus.FAIL
    assert a.spf_aligned is False
    assert a.dkim_aligned is False
    assert a.dkim_signature_domains == ["attacker.example"]
    assert any("does not align" in f for f in a.flags)
    assert "DMARC fail" in a.flags


def test_relaxed_alignment_uses_org_domain():
    a = _auth(
        "From: a@example.net\nReturn-Path: <b@bounce.mail.example.net>\n"
        "Authentication-Results: mx; spf=pass smtp.mailfrom=bounce.mail.example.net; "
        "dkim=pass header.d=mail.example.net; dmarc=pass header.from=example.net\n\nx"
    )

    assert a.spf_aligned is True
    assert a.dkim_aligned is True


def test_no_auth_headers_at_all():
    a = _auth("From: it@corp.example\nTo: me@corp.example\n\nx")

    assert a.no_auth_headers is True
    assert a.spf.status is AuthStatus.MISSING
    assert a.dkim.status is AuthStatus.MISSING
    assert a.dmarc.status is AuthStatus.MISSING
    assert a.spf_aligned is None
    assert a.dkim_aligned is None
    assert a.flags[0].startswith("No Authentication-Results")


def test_results_header_silent_on_mechanism_means_none():
    a = _auth(
        "From: a@example.net\nAuthentication-Results: mx; spf=pass smtp.mailfrom=example.net\n\nx"
    )

    assert a.spf.status is AuthStatus.PASS
    assert a.dkim.status is AuthStatus.NONE
    assert a.dmarc.status is AuthStatus.NONE
    assert a.no_auth_headers is False


def test_unverified_dkim_signature_recorded():
    a = _auth(
        "From: a@example.net\nDKIM-Signature: v=1; d=example.net; s=x; b=y\n"
        "Authentication-Results: mx; spf=pass smtp.mailfrom=example.net\n\nx"
    )

    assert a.dkim.status is AuthStatus.NONE
    assert "not verified" in a.dkim.detail
    assert a.dkim.domain == "example.net"
    assert a.dkim_aligned is True


def test_received_spf_fallback():
    a = _auth(
        "From: a@example.net\n"
        "Received-SPF: Softfail (mx.example.com: domain of transitioning bounce@example.net "
        "does not designate 203.0.113.5 as permitted sender) client-ip=203.0.113.5; "
        "envelope-from=bounce@example.net;\n\nx"
    )

    assert a.spf.status is AuthStatus.SOFTFAIL
    assert a.spf.domain == "example.net"
    assert a.spf.source_header == "Received-SPF"
    assert a.no_auth_headers is False


def test_arc_results_fallback_for_forwarded_mail():
    a = _auth(
        "From: a@example.net\n"
        "ARC-Authentication-Results: i=1; mx.google.com; spf=pass smtp.mailfrom=example.net; "
        "dkim=pass header.i=@example.net; dmarc=pass header.from=example.net\n\nx"
    )

    assert a.spf.status is AuthStatus.PASS
    assert a.dkim.domain == "example.net"
    assert a.dmarc.source_header == "ARC-Authentication-Results"


def test_multiple_dkim_prefers_pass():
    a = _auth(
        "From: a@example.net\nAuthentication-Results: mx; dkim=fail header.d=other.example; "
        "dkim=pass header.d=example.net\n\nx"
    )

    assert a.dkim.status is AuthStatus.PASS
    assert a.dkim.domain == "example.net"


def test_reply_to_mismatch():
    a = _auth("From: ceo@corp.example\nReply-To: ceo.corp@freemail.example\n\nx")

    assert a.reply_to_mismatch is True
    assert any("Reply-To" in f for f in a.flags)


def test_reply_to_same_org_is_fine():
    a = _auth("From: ceo@corp.example\nReply-To: replies@mail.corp.example\n\nx")

    assert a.reply_to_mismatch is False


def test_display_name_brand_spoof():
    a = _auth('From: "Microsoft Account Team" <alerts@example.net>\n\nx')

    assert a.display_name_spoof is True
    assert "microsoft" in a.display_name_spoof_reason


def test_display_name_brand_from_legit_domain_ok():
    a = _auth('From: "Microsoft Account Team" <alerts@account.microsoft.com>\n\nx')
    assert a.display_name_spoof is False

    a = _auth('From: "ACME Payroll" <hr@acme.example>\n\nx')  # bare brand, name in domain
    assert a.display_name_spoof is False


def test_display_name_brand_word_boundary():
    a = _auth('From: "Groups digest" <noreply@example.net>\n\nx')  # "ups" inside "Groups"
    assert a.display_name_spoof is False


def test_display_name_embedded_address_spoof():
    a = _auth('From: "ceo@corp.example" <random123@freemail.example>\n\nx')

    assert a.display_name_spoof is True
    assert "@corp.example" in a.display_name_spoof_reason


def test_display_name_embedded_address_same_org_ok():
    a = _auth('From: "ceo@corp.example" <ceo@corp.example>\n\nx')
    assert a.display_name_spoof is False


def test_double_address_from_is_spoof():
    a = _auth('From: "PayPal" <service@paypal.com> <attacker@example.net>\n\nx')

    assert a.display_name_spoof is True
    assert "more than one address" in a.display_name_spoof_reason


def test_org_domain_helpers():
    assert organizational_domain("mail.eu.example.co.uk") == "example.co.uk"
    assert organizational_domain("a.b.example.com") == "example.com"
    assert organizational_domain("example.com.") == "example.com"
    assert organizational_domain("localhost") == "localhost"
    assert same_org("A.example.COM", "example.com")
    assert not same_org("", "example.com")


# --------------------------------------------------------------------------- live SPF


def _resolver(records):
    def resolve(name, rtype):
        return records.get((name.lower(), rtype), [])

    return resolve


def test_spf_check_ip4_include_redirect_and_all():
    res = _resolver(
        {
            ("example.net", "TXT"): ["v=spf1 ip4:192.0.2.0/24 include:_spf.relay.example -all"],
            ("_spf.relay.example", "TXT"): ["v=spf1 ip4:198.51.100.7 ~all"],
            ("soft.example", "TXT"): ["v=spf1 ~all"],
            ("redir.example", "TXT"): ["v=spf1 redirect=example.net"],
            ("mx.example", "TXT"): ["v=spf1 mx a:web.example -all"],
            ("mx.example", "MX"): ["in.mx.example"],
            ("in.mx.example", "A"): ["203.0.113.1"],
            ("web.example", "A"): ["203.0.113.2"],
            ("nospf.example", "TXT"): ["some other txt"],
        }
    )

    assert spf_check("example.net", "192.0.2.55", res) == "pass"
    assert spf_check("example.net", "198.51.100.7", res) == "pass"  # via include
    assert spf_check("example.net", "203.0.113.9", res) == "fail"
    assert spf_check("soft.example", "203.0.113.9", res) == "softfail"
    assert spf_check("redir.example", "192.0.2.1", res) == "pass"
    assert spf_check("mx.example", "203.0.113.1", res) == "pass"
    assert spf_check("mx.example", "203.0.113.2", res) == "pass"
    assert spf_check("mx.example", "203.0.113.3", res) == "fail"
    assert spf_check("nospf.example", "192.0.2.1", res) == "none"
    assert spf_check("example.net", "not-an-ip", res) == "error"


def test_spf_check_recursion_limit():
    res = _resolver({("loop.example", "TXT"): ["v=spf1 include:loop.example -all"]})
    assert spf_check("loop.example", "192.0.2.1", res) in ("error", "fail")


def test_live_dns_flags_unauthorised_origin():
    res = _resolver({("example.net", "TXT"): ["v=spf1 ip4:192.0.2.0/24 -all"]})
    a = _auth(
        "From: a@example.net\nReturn-Path: <b@example.net>\n\nx",
        live_dns=True,
        origin_ip="203.0.113.5",
        resolver=res,
    )

    assert a.live_dns_spf_authorized is False
    assert any("not an authorised sender" in f for f in a.flags)

    a = _auth(
        "From: a@example.net\nReturn-Path: <b@example.net>\n\nx",
        live_dns=True,
        origin_ip="192.0.2.5",
        resolver=res,
    )
    assert a.live_dns_spf_authorized is True


def test_live_dns_without_origin_ip():
    a = _auth("From: a@example.net\n\nx", live_dns=True, resolver=_resolver({}))

    assert a.live_dns_spf_authorized is None
    assert "no sending domain or origin IP" in a.live_dns_detail
