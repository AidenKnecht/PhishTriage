from datetime import UTC, datetime

from phishtriage.hops import analyze_hops, is_private_ip, parse_received
from phishtriage.parser import parse_bytes, parse_file


def test_parse_standard_received():
    hop = parse_received(
        "from mail.example.net (mail.example.net [192.0.2.10]) by mx.example.com (Postfix) "
        "with ESMTPS id ABC123 for <analyst@example.com>; Mon, 02 Sep 2024 10:15:22 +0000"
    )

    assert hop.from_host == "mail.example.net"
    assert hop.from_ip == "192.0.2.10"
    assert hop.by_host == "mx.example.com"
    assert hop.with_protocol == "ESMTPS"
    assert hop.timestamp == datetime(2024, 9, 2, 10, 15, 22, tzinfo=UTC)


def test_parse_bracket_only_from():
    hop = parse_received(
        "from [10.0.0.5] (unknown [10.0.0.5]) by mail.example.net with ESMTPA; "
        "Mon, 02 Sep 2024 10:15:20 +0000"
    )

    assert hop.from_host == ""
    assert hop.from_ip == "10.0.0.5"
    assert hop.by_host == "mail.example.net"


def test_parse_helo_differs_from_rdns():
    hop = parse_received(
        "from friendly.example (evil.example [203.0.113.7]) by mx.example.com with ESMTP; "
        "Mon, 02 Sep 2024 10:15:20 +0000"
    )

    assert hop.from_host == "friendly.example"
    assert hop.from_ip == "203.0.113.7"


def test_parse_ipv6():
    hop = parse_received(
        "from mail.example.net (mail.example.net [IPv6:2001:db8::25]) by mx.example.com; "
        "Mon, 02 Sep 2024 10:15:20 +0000"
    )

    assert hop.from_ip == "2001:db8::25"


def test_parse_no_date_and_garbage():
    hop = parse_received("(qmail 1234 invoked from network)")
    assert hop.timestamp is None
    assert hop.from_host == ""

    hop = parse_received("from a.example by b.example; not a date")
    assert hop.from_host == "a.example"
    assert hop.by_host == "b.example"
    assert hop.timestamp is None

    hop = parse_received("")
    assert hop.raw == ""


def test_parse_by_with_parenthesised_software():
    hop = parse_received(
        "from a.example (a.example [192.0.2.1]) by b.example (8.15.2/8.15.2) with ESMTP id x; "
        "Mon, 02 Sep 2024 10:15:20 +0000"
    )

    assert hop.by_host == "b.example"
    assert hop.with_protocol == "ESMTP"


def test_is_private_ip():
    assert is_private_ip("10.1.2.3")
    assert is_private_ip("172.16.5.5")
    assert is_private_ip("192.168.0.1")
    assert is_private_ip("127.0.0.1")
    assert is_private_ip("169.254.1.1")
    assert is_private_ip("100.64.0.1")
    assert is_private_ip("::1")
    assert is_private_ip("fe80::1")
    assert is_private_ip("fd00::1")
    assert is_private_ip("::ffff:10.0.0.1")
    # RFC 5737 documentation ranges stand in for public space in the samples.
    assert not is_private_ip("192.0.2.1")
    assert not is_private_ip("198.51.100.1")
    assert not is_private_ip("203.0.113.1")
    assert not is_private_ip("8.8.8.8")
    assert not is_private_ip("2001:db8::1")
    assert not is_private_ip("garbage")


def test_chain_reversed_origin_first(fixtures):
    a = analyze_hops(parse_file(fixtures / "simple.eml"))

    assert [h.from_ip for h in a.hops] == ["10.0.0.5", "192.0.2.10"]
    assert a.first_external_ip == "192.0.2.10"
    assert a.first_external_host == "mail.example.net"
    assert a.private_ip_origin is False
    assert a.timestamp_anomaly is False
    # Sender-side internal relay is informational only.
    assert a.hops[0].flags == ["private IP (internal relay)"]
    assert a.flags == []


def test_private_ip_at_boundary_flagged():
    rec = parse_bytes(
        b"Received: from mailer.example.net (unknown [192.168.1.50]) by mx.example.com "
        b"with ESMTP; Mon, 02 Sep 2024 10:15:22 +0000\n"
        b"To: analyst@example.com\nFrom: x@example.net\n\nx"
    )
    a = analyze_hops(rec)

    assert a.private_ip_origin is True
    assert a.first_external_ip == "192.168.1.50"
    assert any("private/reserved" in f for f in a.flags)


def test_boundary_found_by_recipient_org():
    rec = parse_bytes(
        b"Received: from internal.example.com (internal.example.com [10.9.9.9]) by "
        b"exchange.example.com; Mon, 02 Sep 2024 10:15:25 +0000\n"
        b"Received: from out.sender.example (out.sender.example [203.0.113.40]) by "
        b"mx.example.com; Mon, 02 Sep 2024 10:15:22 +0000\n"
        b"Received: from [10.0.0.5] by out.sender.example; Mon, 02 Sep 2024 10:15:20 +0000\n"
        b"To: analyst@example.com\nFrom: x@sender.example\n\nx"
    )
    a = analyze_hops(rec)

    assert a.first_external_ip == "203.0.113.40"
    assert a.private_ip_origin is False  # recipient's internal relay is not the origin


def test_boundary_from_for_clause_when_no_to():
    rec = parse_bytes(
        b"Received: from a.example (a.example [203.0.113.1]) by mx.example.com for "
        b"<someone@example.com>; Mon, 02 Sep 2024 10:15:22 +0000\nFrom: x@a.example\n\nx"
    )
    a = analyze_hops(rec)

    assert a.first_external_ip == "203.0.113.1"


def test_timestamp_backwards_flagged():
    rec = parse_bytes(
        b"Received: from b.example (b.example [203.0.113.2]) by mx.example.com; "
        b"Mon, 02 Sep 2024 10:00:00 +0000\n"
        b"Received: from a.example (a.example [203.0.113.1]) by b.example; "
        b"Mon, 02 Sep 2024 11:30:00 +0000\n"
        b"To: analyst@example.com\n\nx"
    )
    a = analyze_hops(rec)

    assert a.timestamp_anomaly is True
    assert any("backwards" in f for f in a.hops[1].flags)


def test_timestamp_small_skew_tolerated():
    rec = parse_bytes(
        b"Received: from b.example (b.example [203.0.113.2]) by mx.example.com; "
        b"Mon, 02 Sep 2024 10:00:00 +0000\n"
        b"Received: from a.example (a.example [203.0.113.1]) by b.example; "
        b"Mon, 02 Sep 2024 10:02:00 +0000\n"
        b"To: analyst@example.com\n\nx"
    )
    a = analyze_hops(rec)

    assert a.timestamp_anomaly is False


def test_timestamp_large_forward_jump_flagged():
    rec = parse_bytes(
        b"Received: from b.example (b.example [203.0.113.2]) by mx.example.com; "
        b"Thu, 05 Sep 2024 10:00:00 +0000\n"
        b"Received: from a.example (a.example [203.0.113.1]) by b.example; "
        b"Mon, 02 Sep 2024 10:00:00 +0000\n"
        b"To: analyst@example.com\n\nx"
    )
    a = analyze_hops(rec)

    assert a.timestamp_anomaly is True
    assert any("jumps forward" in f for f in a.hops[1].flags)


def test_no_received_headers():
    a = analyze_hops(parse_bytes(b"From: a@example.net\n\nx"))

    assert a.hops == []
    assert a.flags == ["No Received headers"]


def test_reverse_dns_mismatch_with_mocked_resolver():
    rec = parse_bytes(
        b"Received: from mail.bank.example (mail.bank.example [203.0.113.5]) by mx.example.com; "
        b"Mon, 02 Sep 2024 10:00:00 +0000\nTo: analyst@example.com\n\nx"
    )
    ptr = {"203.0.113.5": ["vps-1234.cheaphost.example"]}
    a = analyze_hops(rec, live_dns=True, ptr_resolver=lambda ip: ptr.get(ip, []))

    assert a.reverse_dns_mismatch is True
    assert any("reverse-resolves" in f for f in a.hops[0].flags)

    ok = analyze_hops(rec, live_dns=True, ptr_resolver=lambda ip: ["mail.bank.example"])
    assert ok.reverse_dns_mismatch is False

    none = analyze_hops(rec, live_dns=True, ptr_resolver=lambda ip: [])
    assert any("no PTR" in f for f in none.hops[0].flags)
