from threat_intel_analyzer.parser import load_indicators


def test_load_csv(tmp_path):
    path = tmp_path / "sample.csv"
    path.write_text(
        "value,indicator_type,severity,confidence,first_seen,source,tags,mitre_techniques\n"
        "203.0.113.10,ip,high,88,2026-09-25T12:00:00Z,demo,c2|botnet,T1071|T1105\n",
        encoding="utf-8",
    )
    indicators = load_indicators(path)
    assert len(indicators) == 1
    assert indicators[0].indicator_type == "ip"
    assert indicators[0].tags == ("c2", "botnet")
    assert indicators[0].mitre_techniques == ("T1071", "T1105")
