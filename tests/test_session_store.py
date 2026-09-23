from app.waf.session_store import SessionStore


def test_record_tracks_requests_within_window():
    store = SessionStore(window_seconds=60)
    store.record("1.1.1.1", "/a", now=0.0)
    store.record("1.1.1.1", "/b", now=10.0)
    state = store.get("1.1.1.1")
    assert len(state.request_times) == 2
    assert state.endpoints == {"/a", "/b"}


def test_requests_outside_window_are_dropped():
    store = SessionStore(window_seconds=60)
    store.record("1.1.1.1", "/a", now=0.0)
    store.record("1.1.1.1", "/b", now=100.0)  # 100s later, outside the 60s window
    state = store.get("1.1.1.1")
    assert len(state.request_times) == 1


def test_bump_reputation_is_clamped_to_0_1_range():
    store = SessionStore()
    store.bump_reputation("1.1.1.1", 0.5)
    store.bump_reputation("1.1.1.1", 0.8)
    assert store.get("1.1.1.1").reputation_score == 1.0
    store.bump_reputation("1.1.1.1", -5)
    assert store.get("1.1.1.1").reputation_score == 0.0


def test_store_evicts_least_recently_used_client_over_capacity():
    store = SessionStore(max_clients=2)
    store.record("ip-1", "/", now=0.0)
    store.record("ip-2", "/", now=1.0)
    store.record("ip-3", "/", now=2.0)  # should evict ip-1 (least recently used)

    assert len(store) == 2
    # ip-1 was evicted: recording again starts a fresh ClientState (1 request)
    state = store.record("ip-1", "/", now=3.0)
    assert len(state.request_times) == 1


def test_touching_a_client_protects_it_from_lru_eviction():
    store = SessionStore(max_clients=2)
    store.record("ip-1", "/", now=0.0)
    store.record("ip-2", "/", now=1.0)
    store.get("ip-1")  # touch ip-1 so ip-2 becomes the LRU victim instead
    store.record("ip-3", "/", now=2.0)

    assert len(store) == 2
    # ip-1 survived (still has its original 1 request from t=0), ip-2 was evicted
    assert len(store.get("ip-1").request_times) == 1
    assert len(store.get("ip-2").request_times) == 0


def test_store_never_exceeds_max_clients_under_sustained_load():
    store = SessionStore(max_clients=100)
    for i in range(10_000):
        store.record(f"ip-{i}", "/", now=float(i))
    assert len(store) <= 100
