from spok import setup
import dmf

def test_frank():
    msg = "hello"
    _, g, o = setup()
    aux = (g, o)
    (pk_s, sk_s) = dmf.KeyGen(aux)
    (pk_r, sk_r) = dmf.KeyGen(aux)
    (pk_j, sk_j) = dmf.KeyGen(aux)
    sig = dmf.Frank(sk_s, pk_r, pk_j, msg, aux)

    assert dmf.Verify(pk_s, sk_r, pk_j, msg, sig, aux)
    assert dmf.Judge(pk_s, pk_r, sk_j, msg, sig, aux)

def test_forge():
    msg = "hello"
    _, g, o = setup()
    aux = (g, o)
    (pk_s, sk_s) = dmf.KeyGen(aux)
    (pk_r, sk_r) = dmf.KeyGen(aux)
    (pk_j, sk_j) = dmf.KeyGen(aux)
    sig = dmf.Forge(pk_s, pk_r, pk_j, msg, aux)

    assert not dmf.Verify(pk_s, sk_r, pk_j, msg, sig, aux)
    assert not dmf.Judge(pk_s, pk_r, sk_j, msg, sig, aux)

    (pi, T, U, A, B) = sig
    spok = dmf.Create_DMF_SPoK(pk_s, pk_j, T, U, A, aux)
    assert spok.verify(msg, pi)

def test_rforge():
    msg = "hello"
    _, g, o = setup()
    aux = (g, o)
    (pk_s, sk_s) = dmf.KeyGen(aux)
    (pk_r, sk_r) = dmf.KeyGen(aux)
    (pk_j, sk_j) = dmf.KeyGen(aux)
    sig = dmf.RForge(pk_s, sk_r, pk_j, msg, aux)

    assert dmf.Verify(pk_s, sk_r, pk_j, msg, sig, aux)
    assert not dmf.Judge(pk_s, pk_r, sk_j, msg, sig, aux)

    (pi, T, U, A, B) = sig
    spok = dmf.Create_DMF_SPoK(pk_s, pk_j, T, U, A, aux)
    assert spok.verify(msg, pi)

def test_jforge():
    msg = "hello"
    _, g, o = setup()
    aux = (g, o)
    (pk_s, sk_s) = dmf.KeyGen(aux)
    (pk_r, sk_r) = dmf.KeyGen(aux)
    (pk_j, sk_j) = dmf.KeyGen(aux)
    sig = dmf.JForge(pk_s, pk_r, sk_j, msg, aux)

    assert dmf.Verify(pk_s, sk_r, pk_j, msg, sig, aux)
    assert dmf.Judge(pk_s, pk_r, sk_j, msg, sig, aux)

    (pi, T, U, A, B) = sig
    spok = dmf.Create_DMF_SPoK(pk_s, pk_j, T, U, A, aux)
    assert spok.verify(msg, pi)

if __name__ == "__main__":
    test_frank()
    test_forge()
    test_rforge()
    test_jforge()
    print("All tests pass")
