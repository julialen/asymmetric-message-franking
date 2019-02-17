from petlib.bn import Bn
from petlib.ec import EcGroup, EcPt

from spok import setup, Schnorr, Conjunction, Disjunction, FiatShamirSignature, \
    ChaumPedersen

def Create_DMF_SPoK(pk_s, pk_j, T, U, A, aux):
    g, o = aux
    schnorr0 = Schnorr(pk_s, g, o)
    schnorr1 = Schnorr(T, g, o)
    disj0 = Disjunction(schnorr0, schnorr1)

    cp = ChaumPedersen(pk_j, A, T, g, o)
    schnorr2 = Schnorr(U, g, o)
    disj1 = Disjunction(cp, schnorr2)

    return FiatShamirSignature(Conjunction(disj0, disj1))

def KeyGen(aux):
    g, o = aux
    sk = o.random()
    pk = sk * g
    return (pk, sk)

def Frank(sk_s, pk_r, pk_j, msg, aux):
    g, o = aux
    pk_s = sk_s * g
    alpha = o.random()
    beta = o.random()
    T = alpha * pk_j
    U = beta * pk_r
    A = alpha * g
    B = beta * g
    x = ((0, sk_s), (0, alpha))
    spok = Create_DMF_SPoK(pk_s, pk_j, T, U, A, aux)
    pi = spok.sign(msg, x)
    return (pi, T, U, A, B)

def Verify(pk_s, sk_r, pk_j, msg, sig, aux):
    (pi, T, U, A, B) = sig
    spok = Create_DMF_SPoK(pk_s, pk_j, T, U, A, aux)
    b1 = (U == (sk_r * B))
    b2 = spok.verify(msg, pi)
    return (b1 and b2)

def Judge(pk_s, pk_r, sk_j, msg, sig, aux):
    g, o = aux
    pk_j = sk_j * g
    (pi, T, U, A, B) = sig
    spok = Create_DMF_SPoK(pk_s, pk_j, T, U, A, aux)
    b1 = (T == (sk_j * A))
    b2 = spok.verify(msg, pi)
    return (b1 and b2)

def Forge(pk_s, pk_r, pk_j, msg, aux):
    g, o = aux
    alpha = o.random()
    beta = o.random()
    gamma = o.random()
    delta = o.random()
    T = gamma * g
    U = delta * g
    A = alpha * g
    B = beta * g
    x = ((1, gamma), (1, delta))
    spok = Create_DMF_SPoK(pk_s, pk_j, T, U, A, aux)
    pi = spok.sign(msg, x)
    return (pi, T, U, A, B)

def RForge(pk_s, sk_r, pk_j, msg, aux):
    g, o = aux
    pk_r = sk_r * g
    alpha = o.random()
    beta = o.random()
    gamma = o.random()
    T = gamma * g
    U = beta * pk_r
    A = alpha * g
    B = beta * g
    x = ((1, gamma), (1, beta * sk_r))
    spok = Create_DMF_SPoK(pk_s, pk_j, T, U, A, aux)
    pi = spok.sign(msg, x)
    return (pi, T, U, A, B)

def JForge(pk_s, pk_r, sk_j, msg, aux):
    g, o = aux
    pk_j = sk_j * g
    alpha = o.random()
    beta = o.random()
    T = alpha * pk_j
    U = beta * pk_r
    A = alpha * g
    B = beta * g
    x = ((1, alpha * sk_j), (0, alpha))
    spok = Create_DMF_SPoK(pk_s, pk_j, T, U, A, aux)
    pi = spok.sign(msg, x)
    return (pi, T, U, A, B)
