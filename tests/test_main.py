from pretix_oidc.auth import _validated_next_url

def test_next_url_validation():
    fallback = "/control/"

    assert _validated_next_url("/control/") == "/control/"

    assert (
        _validated_next_url("/control/events/?page=2")
        == "/control/events/?page=2"
    )

    assert (
        _validated_next_url("https://attacker.example/")
        == fallback
    )

    assert (
        _validated_next_url("//attacker.example/")
        == fallback
    )

    assert (
        _validated_next_url("javascript:alert(1)")
        == fallback
    )

    assert (
        _validated_next_url("/presale/")
        == fallback
    )

def test_next_url_validation_edge_cases():
    fallback = "/control/"

    assert _validated_next_url(None) == fallback
    assert _validated_next_url("") == fallback
    assert _validated_next_url("control/") == fallback
    assert _validated_next_url("/control") == "/control"
    assert _validated_next_url("/control/anything") == "/control/anything"

    assert _validated_next_url(
        "https://tickets.mito.org.nz/control/"
    ) == fallback

    assert _validated_next_url(
        "\\\\attacker.example\\control"
    ) == fallback

    assert _validated_next_url(
        "/control/\r\nLocation: https://attacker.example/"
    ) == fallback

    assert _validated_next_url(
        "/" + ("a" * 2048)
    ) == fallback
