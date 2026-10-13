from datetime import datetime, timedelta, timezone

from app.models import (
    ExposureScan,
    Identifier,
    ScanStatus,
    User,
)
from app.services.scan_recovery import recover_stale_scans


def test_recovery_marks_only_stale_running_scans_failed(db_session):
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(minutes=15)
    users = [
        User(email=f"recovery-{index}@example.com", password_hash="test")
        for index in range(4)
    ]
    db_session.add_all(users)
    db_session.flush()

    identifiers = [
        Identifier(
            user_id=user.id,
            type="email",
            value_hmac=f"hmac-{index}",
            display_value="encrypted-test-value",
        )
        for index, user in enumerate(users)
    ]
    db_session.add_all(identifiers)
    db_session.flush()

    stale_scan = ExposureScan(
        user_id=users[0].id,
        identifier_id=identifiers[0].id,
        status=ScanStatus.RUNNING,
        is_simulated=True,
        findings=[],
        created_at=now - timedelta(minutes=30),
        started_at=now - timedelta(minutes=30),
    )
    recent_scan = ExposureScan(
        user_id=users[1].id,
        identifier_id=identifiers[1].id,
        status=ScanStatus.RUNNING,
        is_simulated=True,
        findings=[],
        created_at=now - timedelta(minutes=5),
        started_at=now - timedelta(minutes=5),
    )
    completed_scan = ExposureScan(
        user_id=users[2].id,
        identifier_id=identifiers[2].id,
        status=ScanStatus.COMPLETED,
        is_simulated=True,
        findings=[],
        created_at=now - timedelta(minutes=30),
        started_at=now - timedelta(minutes=30),
        completed_at=now - timedelta(minutes=29),
    )
    pending_scan = ExposureScan(
        user_id=users[3].id,
        identifier_id=identifiers[3].id,
        status=ScanStatus.PENDING,
        is_simulated=True,
        findings=[],
        created_at=now - timedelta(minutes=30),
        started_at=None,
    )
    scans = [stale_scan, recent_scan, completed_scan, pending_scan]
    db_session.add_all(scans)
    db_session.commit()

    recovered_count = recover_stale_scans(db_session, cutoff)
    db_session.expire_all()

    assert recovered_count == 1
    assert db_session.get(ExposureScan, stale_scan.id).status == ScanStatus.FAILED
    assert (
        db_session.get(ExposureScan, stale_scan.id).error_code
        == "scan_interrupted"
    )
    assert db_session.get(ExposureScan, stale_scan.id).completed_at is not None
    assert db_session.get(ExposureScan, recent_scan.id).status == ScanStatus.RUNNING
    assert (
        db_session.get(ExposureScan, completed_scan.id).status
        == ScanStatus.COMPLETED
    )
    assert db_session.get(ExposureScan, pending_scan.id).status == ScanStatus.PENDING
