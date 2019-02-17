from petlib.bn import Bn
from petlib.ec import EcGroup, EcPt

from hashlib import sha256

def setup():
    G = EcGroup(714)
    g = G.generator()
    o = G.order()
    return G, g, o

class SigmaProtocol():
    """Generic sigma protocol parent class"""

    def __init__(self, o):
        self.o = o

    def commit(w):
        pass

    def challenge(self, elements):
        """Packages a challenge in a bijective way"""
        elem = [len(elements)] + elements
        elem_str = map(str, elem)
        elem_len = map(lambda x: "%s||%s" % (len(x) , x), elem_str)
        state = "|".join(elem_len)
        H = sha256()
        H.update(state.encode("utf8"))
        return Bn.from_binary(H.digest()) % self.o

    def response(w, t, c, aux):
        pass

    def verify(t, c, z):
        pass

    def sim(c):
        pass

class Schnorr(SigmaProtocol):
    """Schnorr proof of the statement ZK(w : y = g^w)"""

    def __init__(self, y, g, o):
        super().__init__(o)
        self.y = y
        self.g = g

    def commit(self, w):
        a = self.o.random()
        t = a * self.g
        return t, a

    def response(self, w, t, c, aux):
        z = (aux + (w * c)) % self.o
        return z

    def verify(self, t, c, z):
        v1 = z * self.g
        v2 = t + (c * self.y)
        return (v1 == v2)

    def sim(self, c):
        z = self.o.random()
        t = (z * self.g) - (c * self.y)
        return (t, z)

class Conjunction(SigmaProtocol):
    """Conjunctive Schnorr proof"""

    #TODO: make parameter list of proofs
    def __init__(self, sigma_protocol0, sigma_protocol1):
        assert sigma_protocol0.o == sigma_protocol1.o
        super().__init__(sigma_protocol0.o)
        self.sp0 = sigma_protocol0
        self.sp1 = sigma_protocol1

    def commit(self, w):
        assert isinstance(w, tuple)
        t0, aux0 = self.sp0.commit(w[0])
        t1, aux1 = self.sp1.commit(w[1])
        return (t0, t1), (aux0, aux1)

    def response(self, w, t, c, aux):
        assert isinstance(w, tuple)
        assert isinstance(t, tuple)
        assert isinstance(aux, tuple)
        z0 = self.sp0.response(w[0], t[0], c, aux[0])
        z1 = self.sp1.response(w[1], t[1], c, aux[1])
        return (z0, z1)

    def verify(self, t, c, z):
        assert isinstance(t, tuple)
        assert isinstance(z, tuple)
        b1 = self.sp0.verify(t[0], c, z[0])
        b2 = self.sp1.verify(t[1], c, z[1])
        return (b1 and b2)

    def sim(self, c):
        (t0, z0) = self.sp0.sim(c)
        (t1, z1) = self.sp1.sim(c)
        return ((t0, t1), (z0, z1))

class Disjunction(SigmaProtocol):
    """Disjunctive Schnorr proof"""

    def __init__(self, sigma_protocol0, sigma_protocol1):
        assert sigma_protocol0.o == sigma_protocol1.o
        super().__init__(sigma_protocol0.o)
        self.sp = (sigma_protocol0, sigma_protocol1)

    def commit(self, w):
        assert isinstance(w, tuple)
        (b, w_b) = w
        d = 1-b
        t = [None, None]
        aux = [None, None]
        c_d = self.sp[d].o.random()
        t_d, z_d = self.sp[d].sim(c_d)
        t_b, aux_b = self.sp[b].commit(w_b)
        t[b] = t_b
        t[d] = t_d
        aux_d = (c_d, z_d)
        aux[b] = aux_b
        aux[d] = aux_d
        return tuple(t), tuple(aux)

    def response(self, w, t, c, aux):
        assert isinstance(w, tuple)
        (b, w_b) = w
        d = 1-b
        c_list = [None, None]
        c_d, z_d = aux[d]
        c_b = c - c_d
        c_list[b] = c_b
        c_list[d] = c_d
        z_b = self.sp[b].response(w_b, t[b], c_b, aux[b])
        z = [c_list[0], None, None]
        z[b+1] = z_b
        z[d+1] = z_d
        return tuple(z)

    def verify(self, t, c, z):
        c_0, z_0, z_1 = z
        c_1 = c - c_0
        b0 = self.sp[0].verify(t[0], c_0, z_0)
        b1 = self.sp[1].verify(t[1], c_1, z_1)
        return (b0 and b1)

    def sim(self, c):
        c_0 = self.sp[0].o.random()
        c_1 = c - c_0
        (t0, z0) = self.sp[0].sim(c_0)
        (t1, z1) = self.sp[1].sim(c_1)
        return (c_0, (t0, t1), (z0, z1))

class ChaumPedersen(SigmaProtocol):
    """Chaum-Pedersen protocol for DH-triples"""

    def __init__(self, u, v, w, g, o):
        super().__init__(o)
        self.u = u
        self.v = v
        self.w = w
        self.g = g

    def commit(self, B):
        B_t = self.o.random()
        v_t = B_t * self.g
        w_t = B_t * self.u
        return (v_t, w_t), B_t

    def response(self, B, t, c, aux):
        B_z = (aux + (B * c)) % self.o
        return B_z

    def verify(self, t, c, B_z):
        assert isinstance(t, tuple)
        (v_t, w_t) = t
        b1 = ((B_z * self.g) == (v_t + (c * self.v)))
        b2 = ((B_z * self.u) == (w_t + (c * self.w)))
        return (b1 and b2)

    def sim(self, c):
        B_z = self.o.random()
        v_t = (B_z * self.g) - (c * self.v)
        w_t = (B_z * self.u) - (c * self.w)
        return ((v_t, w_t), B_z)

class FiatShamirSignature():
    """Fiat-Shamir protocol for signatures"""

    def __init__(self, sigma_protocol):
        self.sp = sigma_protocol

    def sign(self, m, w):
        t, aux = self.sp.commit(w)
        state = [m, t]
        c = self.sp.challenge(state)
        z = self.sp.response(w, t, c, aux)
        return (t, z)

    def verify(self, m, sig):
        (t, z) = sig
        state = [m, t]
        c = self.sp.challenge(state)
        b = self.sp.verify(t, c, z)
        return b
