"""Received-chain shapes taken from real Gmail and Microsoft 365 deliveries."""

from phishtriage.hops import analyze_hops, infra_family
from phishtriage.parser import parse_bytes


def test_gmail_chain_finds_boundary_at_mx_google():
    rec = parse_bytes(
        b"Received: by 2002:a05:6124:1ea1:b0:448:b4c5:5917 with SMTP id x; "
        b"Mon, 02 Sep 2024 10:00:03 +0000\n"
        b"Received: from mta.sender.example (mta.sender.example [203.0.113.64]) by "
        b"mx.google.com with ESMTPS id y; Mon, 02 Sep 2024 10:00:02 +0000\n"
        b"Received: by mta.sender.example id z; Mon, 02 Sep 2024 10:00:00 +0000\n"
        b"To: someone@gmail.com\nFrom: news@sender.example\n\nx"
    )
    a = analyze_hops(rec)

    assert a.first_external_ip == "203.0.113.64"
    assert a.first_external_host == "mta.sender.example"
    assert a.private_ip_origin is False


def test_m365_chain_loopback_hop_is_not_external_origin():
    rec = parse_bytes(
        b"Received: from XX1.prod.exchangelabs.com (::1) by YY1.prod.exchangelabs.com with "
        b"HTTPS; Mon, 02 Sep 2024 10:00:05 +0000\n"
        b"Received: from ca0004.namprd18.prod.outlook.com (2603:10b6:208:23c::9) by "
        b"XX1.prod.exchangelabs.com with Microsoft SMTP Server; Mon, 02 Sep 2024 10:00:04 +0000\n"
        b"Received: from pepf0001.namprd02.prod.outlook.com (2603:10b6:208:23c:cafe::f0) by "
        b"ca0004.outlook.office365.com; Mon, 02 Sep 2024 10:00:03 +0000\n"
        b"Received: from sender-of-o51.zoho.in (sender-of-o51.zoho.in [203.0.113.51]) by "
        b"pepf0001.mail.protection.outlook.com; Mon, 02 Sep 2024 10:00:02 +0000\n"
        b"Received: from mail.zoho.in by mx.zoho.in; Mon, 02 Sep 2024 10:00:01 +0000\n"
        b"To: student@mail.uni.example\nFrom: recruiter@zoho.in\n\nx"
    )
    a = analyze_hops(rec)

    assert a.first_external_ip == "203.0.113.51"
    assert a.first_external_host == "sender-of-o51.zoho.in"
    assert a.private_ip_origin is False
    assert a.hops[-1].flags == ["private IP (internal relay)"]


def test_intra_tenant_m365_mail_has_no_external_origin():
    rec = parse_bytes(
        b"Received: from CY3.prod.exchangelabs.com (::1) by SN6.prod.exchangelabs.com with "
        b"HTTPS; Wed, 21 May 2025 16:46:53 +0000\n"
        b"Received: from BY3.prod.exchangelabs.com (2603:10b6:a03:357::18) by "
        b"CY3.prod.exchangelabs.com; Wed, 21 May 2025 16:46:50 +0000\n"
        b"Received: from BY3.prod.exchangelabs.com ([fe80::4cf9:eefe:3ea6:13dd]) by "
        b"BY3.prod.exchangelabs.com with mapi; Wed, 21 May 2025 16:46:50 +0000\n"
        b"From: student@mail.uni.example\n\nx"
    )
    a = analyze_hops(rec)

    assert a.first_external_ip == ""
    assert a.private_ip_origin is False
    assert any("never left" in f for f in a.flags)


def test_cross_tenant_m365_falls_back_to_authentication_results_ip():
    rec = parse_bytes(
        b"Received: from IA1.prod.exchangelabs.com (::1) by SJ2.prod.exchangelabs.com; "
        b"Mon, 02 Sep 2024 10:00:04 +0000\n"
        b"Received: from cu005.outbound.protection.outlook.com (2a01:111:f403:c105::5) by "
        b"pepf013d.mail.protection.outlook.com; Mon, 02 Sep 2024 10:00:02 +0000\n"
        b"Received: from PH5.namprd05.prod.outlook.com ([fe80::6eb5:6c7d:281d:7600]) by "
        b"PH5.namprd05.prod.outlook.com with mapi; Mon, 02 Sep 2024 10:00:01 +0000\n"
        b"Authentication-Results: spf=pass (sender IP is 2a01:111:f403:c105::5) "
        b"smtp.mailfrom=tenant.example; dmarc=pass header.from=tenant.example\n"
        b"To: student@mail.uni.example\nFrom: hr@tenant.example\n\nx"
    )
    a = analyze_hops(rec)

    assert a.first_external_ip == "2a01:111:f403:c105::5"
    assert a.private_ip_origin is False
    assert any("Authentication-Results" in f for f in a.flags)


def test_infra_family_mapping():
    assert infra_family("bn3pepf00022bbd.mail.protection.outlook.com") == "microsoft"
    assert infra_family("ds4pr01mb994357.prod.exchangelabs.com") == "microsoft"
    assert infra_family("mx.google.com") == "google"
    assert infra_family("gmail.com") == "google"
    assert infra_family("mail.example.net") == "example.net"
    assert infra_family("2002:a05:6124:1ea1:b0:448:b4c5:5917") == ""
    assert infra_family("[203.0.113.1]") == ""
    assert infra_family("") == ""
