from spok import setup, Schnorr, Conjunction, Disjunction, FiatShamirSignature, \
    ChaumPedersen


def test_schnorr():
    params = setup()
    G, g, o = params
    x = o.random()
    X = x * g
    c = o.random()

    schnorr = Schnorr(X, g, o)
    t, aux = schnorr.commit(x)
    z = schnorr.response(x, t, c, aux)
    assert schnorr.verify(t, c, z)
    assert not schnorr.verify(t, z, c)

    (t_prime, z_prime) = schnorr.sim(c)
    assert schnorr.verify(t_prime, c, z_prime)

def test_conjunction():
    params = setup()
    G, g, o = params
    x = o.random()
    X = x * g
    y = o.random()
    Y = y * g
    c = o.random()

    schnorr1 = Schnorr(X, g, o)
    schnorr2 = Schnorr(Y, g, o)
    w = (x, y)
    conj = Conjunction(schnorr1, schnorr2)
    t, aux = conj.commit(w)
    z = conj.response(w, t, c, aux)
    assert conj.verify(t, c, z)

    w = (y, x)
    t, aux = conj.commit(w)
    z = conj.response(w, t, c, aux)
    assert not conj.verify(t, c, z)

def test_disjunction():
    params = setup()
    G, g, o = params
    x = o.random()
    X = x * g
    y = o.random()
    Y = y * g
    c = o.random()

    schnorr0 = Schnorr(X, g, o)
    schnorr1 = Schnorr(Y, g, o)
    w = (0, x)
    disj = Disjunction(schnorr0, schnorr1)
    t, aux = disj.commit(w)
    z = disj.response(w, t, c, aux)
    assert disj.verify(t, c, z)

    w = (1, y)
    t, aux = disj.commit(w)
    z = disj.response(w, t, c, aux)
    assert disj.verify(t, c, z)

    w = (0, y)
    t, aux = disj.commit(w)
    z = disj.response(w, t, c, aux)
    assert not disj.verify(t, c, z)

def test_conjunction_of_disjunction():
    params = setup()
    G, g, o = params
    x = o.random()
    X = x * g
    y = o.random()
    Y = y * g
    a = o.random()
    A = a * g
    b = o.random()
    B = b * g
    c = o.random()

    schnorr0 = Schnorr(X, g, o)
    schnorr1 = Schnorr(Y, g, o)
    w0 = (0, x)
    disj0 = Disjunction(schnorr0, schnorr1)

    schnorr2 = Schnorr(A, g, o)
    schnorr3 = Schnorr(B, g, o)
    w1 = (1, b)
    disj1 = Disjunction(schnorr2, schnorr3)

    conj = Conjunction(disj0, disj1)
    w = (w0, w1)
    t, aux = conj.commit(w)
    z = conj.response(w, t, c, aux)
    assert conj.verify(t, c, z)

def test_chaum_pedersen():
    params = setup()
    G, g, o = params
    alpha = o.random()
    u = alpha * g
    beta = o.random()
    v = beta * g
    gamma = (alpha * beta) % o
    w = gamma * g
    c = o.random()

    cp = ChaumPedersen(u, v, w, g, o)
    t, aux = cp.commit(beta)
    B_z = cp.response(beta, t, c, aux)
    assert cp.verify(t, c, B_z)
    assert not cp.verify(t, B_z, c)

    (t_prime, z_prime) = cp.sim(c)
    assert cp.verify(t_prime, c, z_prime)

def test_protocol_composition():
    params = setup()
    G, g, o = params
    alpha = o.random()
    u = alpha * g
    beta = o.random()
    v = beta * g
    gamma = (alpha * beta) % o
    w = gamma * g
    x = o.random()
    X = x * g
    y = o.random()
    Y = y * g
    c = o.random()

    cp = ChaumPedersen(u, v, w, g, o)
    schnorr0 = Schnorr(X, g, o)
    schnorr1 = Schnorr(Y, g, o)
    w0 = x
    w1 = (0, beta)
    disj = Disjunction(cp, schnorr1)

    conj = Conjunction(schnorr0, disj)
    w = (w0, w1)
    t, aux = conj.commit(w)
    z = conj.response(w, t, c, aux)
    assert conj.verify(t, c, z)

def test_signature():
    params = setup()
    G, g, o = params
    x = o.random()
    X = x * g
    y = o.random()
    Y = y * g
    c = o.random()

    m = "message"
    m_prime = "different_message"
    schnorr = Schnorr(X, g, o)
    signature = FiatShamirSignature(schnorr)
    s = signature.sign(m, x)
    assert signature.verify(m, s)
    assert not signature.verify(m_prime, s)

def test_signature_of_conj_of_disj():
    params = setup()
    G, g, o = params
    x = o.random()
    X = x * g
    y = o.random()
    Y = y * g
    a = o.random()
    A = a * g
    b = o.random()
    B = b * g
    c = o.random()

    schnorr0 = Schnorr(X, g, o)
    schnorr1 = Schnorr(Y, g, o)
    w0 = (0, x)
    disj0 = Disjunction(schnorr0, schnorr1)

    schnorr2 = Schnorr(A, g, o)
    schnorr3 = Schnorr(B, g, o)
    w1 = (1, b)
    disj1 = Disjunction(schnorr2, schnorr3)

    signature = FiatShamirSignature(Conjunction(disj0, disj1))

    m = "message"
    m_prime = "different_message"
    s = signature.sign(m, (w0, w1))
    assert signature.verify(m, s)
    assert not signature.verify(m_prime, s)

def test_signature_of_protocol_composition():
    params = setup()
    G, g, o = params
    alpha = o.random()
    u = alpha * g
    beta = o.random()
    v = beta * g
    gamma = (alpha * beta) % o
    w = gamma * g
    x = o.random()
    X = x * g
    y = o.random()
    Y = y * g
    c = o.random()

    cp = ChaumPedersen(u, v, w, g, o)
    schnorr0 = Schnorr(X, g, o)
    schnorr1 = Schnorr(Y, g, o)
    w0 = x
    w1 = (0, beta)
    disj = Disjunction(cp, schnorr1)

    signature = FiatShamirSignature(Conjunction(schnorr0, disj))

    m = "message"
    m_prime = "different_message"
    s = signature.sign(m, (w0, w1))
    assert signature.verify(m, s)
    assert not signature.verify(m_prime, s)

if __name__ == "__main__":
    test_schnorr()
    test_conjunction()
    test_disjunction()
    test_chaum_pedersen()
    test_protocol_composition()
    test_signature()
    test_signature_of_conj_of_disj()
    test_signature_of_protocol_composition()
    print("All tests pass")
