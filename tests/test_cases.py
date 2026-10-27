from pathlib import Path

from core.cases import (
    add_analysis_to_case,
    create_case,
    delete_case,
    export_case,
    get_case_analyses,
    init_db,
    list_cases,
)
from core.investigator import investigate_ip


def test_case_lifecycle(tmp_path: Path):
    db = tmp_path / "cases.db"
    init_db(db)
    case_id = create_case("Caso teste", "Descrição", db)
    bundle = investigate_ip("192.168.1.10", enabled_sources=set())
    analysis_id = add_analysis_to_case(case_id, bundle, db_path=db)
    assert analysis_id > 0
    cases = list_cases(db)
    assert cases[0]["analysis_count"] == 1
    analyses = get_case_analyses(case_id, db)
    assert analyses[0]["bundle"]["query"]["ip"] == "192.168.1.10"
    exported = export_case(case_id, db)
    assert exported["case"]["name"] == "Caso teste"
    assert len(exported["analyses"]) == 1
    delete_case(case_id, db)
    assert list_cases(db) == []
