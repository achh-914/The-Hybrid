from hybrid.drift import compute_drift, fingerprint


def finding(path_id, ref, severity="high", tenant="t1"):
    return {
        "tenant_id": tenant, "id": "f-random", "rule_id": "UNAUTHORIZED_ACCESS_PATH",
        "severity": severity, "requirement_id": "req-1", "attack_path_id": path_id,
        "evidence": [
            {"kind": "clause", "ref": "c-1", "hash": "aa"},
            {"kind": "graph_path", "ref": ref, "hash": "bb"},
        ],
    }


A = finding("path:role:a->s3:x", "role:a -> role:admin -> s3:x")
B = finding("path:role:admin->s3:x", "role:admin -> s3:x")


def empty_diff(d):
    return not (d["new"] or d["resolved"] or d["changed"])


def test_identical_scans_have_empty_diff():
    d = compute_drift([A, B], [B, A])
    assert empty_diff(d) and len(d["persisting"]) == 2


def test_added_path_is_new():
    d = compute_drift([A], [A, B])
    assert [x["attack_path_id"] for x in d["new"]] == [B["attack_path_id"]]
    assert not d["resolved"]


def test_removed_path_is_resolved():
    d = compute_drift([A, B], [A])
    assert [x["attack_path_id"] for x in d["resolved"]] == [B["attack_path_id"]]
    assert not d["new"]


def test_severity_change_is_changed():
    d = compute_drift([A], [finding(A["attack_path_id"], "role:a -> role:admin -> s3:x", "critical")])
    assert len(d["changed"]) == 1 and d["changed"][0]["after"]["severity"] == "critical"


def test_path_shape_change_is_changed_not_new():
    d = compute_drift([A], [finding(A["attack_path_id"], "role:a -> s3:x")])
    assert len(d["changed"]) == 1 and not d["new"] and not d["resolved"]


def test_fingerprint_ignores_ids_and_evidence_hashes():
    x = finding("path:p", "r")
    y = dict(x, id="f-other", evidence=[{"kind": "clause", "ref": "zz", "hash": "cc"}])
    assert fingerprint(x) == fingerprint(y)


def test_fingerprint_differs_per_tenant():
    assert fingerprint(finding("path:p", "r", tenant="t1")) != fingerprint(finding("path:p", "r", tenant="t2"))


def test_resolved_when_the_new_scan_has_no_findings():
    d = compute_drift([A, B], [])
    assert {x["attack_path_id"] for x in d["resolved"]} == {A["attack_path_id"], B["attack_path_id"]}
    assert not d["new"] and not d["persisting"] and not d["changed"]


def test_resolved_item_carries_its_fingerprint():
    (r,) = compute_drift([A], [])["resolved"]
    assert r["fingerprint"] == fingerprint(A)


def test_a_resolved_path_that_comes_back_is_new_again():
    assert compute_drift([A], [])["resolved"]
    again = compute_drift([], [A])
    assert [x["attack_path_id"] for x in again["new"]] == [A["attack_path_id"]]


def test_resolved_and_new_can_happen_in_the_same_diff():
    d = compute_drift([A], [B])
    assert [x["attack_path_id"] for x in d["resolved"]] == [A["attack_path_id"]]
    assert [x["attack_path_id"] for x in d["new"]] == [B["attack_path_id"]]


def test_same_path_in_two_tenants_is_not_the_same_finding():
    other = finding(A["attack_path_id"], "role:a -> role:admin -> s3:x", tenant="t2")
    assert fingerprint(A) != fingerprint(other)
    d = compute_drift([A], [other])
    assert len(d["resolved"]) == 1 and len(d["new"]) == 1
