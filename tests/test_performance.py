def test_performance():
    import time
    from app.services.key_manager import KeyManager
    from app.services.crypto_service import CryptoService
    from app.services.ml_service import MLService

    km = KeyManager("system")
    ms = MLService(retrain=False)
    cs = CryptoService("python", km, ms, "system")

    kid = km.create_key()
    data = b"x" * 1024*10
    start = time.perf_counter()
    cs.encrypt(kid, data)
    elapsed = (time.perf_counter() - start) * 1000
    assert elapsed < 500  # должно работать быстрее 0.5 сек
