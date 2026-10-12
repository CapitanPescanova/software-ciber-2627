"""AAA-19 (emisión de token) y /health. Tests de Omar."""
import os
import unittest

import jwt

from base import USUARIO, BaseTest


class TestHealth(BaseTest):
    def test_health_responde_200(self):
        r = self.client.get("/health")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json(), {"status": "ok", "module": "01-identidad"})


class TestToken(BaseTest):
    def test_1_jwt_hs256_con_claims_sub_role_iat_exp(self):
        token = self.registrar().get_json()["token"]
        self.assertEqual(jwt.get_unverified_header(token)["alg"], "HS256")
        claims = jwt.decode(token, self.jwt_secret, algorithms=["HS256"])
        for clave in ("sub", "role", "iat", "exp"):
            self.assertIn(clave, claims)
        self.assertEqual(claims["sub"], USUARIO["username"])
        self.assertEqual(claims["role"], "analista")

    def test_2_caduca_a_los_30_minutos(self):
        token = self.registrar().get_json()["token"]
        claims = jwt.decode(token, self.jwt_secret, algorithms=["HS256"])
        self.assertEqual(claims["exp"] - claims["iat"], 30 * 60)

    def test_3_la_clave_sale_del_entorno_y_sin_ella_falla_con_500(self):
        os.environ.pop("JWT_SECRET")
        r = self.registrar()
        self.assertEqual(r.status_code, 500)
        self.assertEqual(self.contar_usuarios(), 0)  # no se crea usuario si no se puede emitir el token
        self.assertEqual(self.client.get("/health").status_code, 200)  # /health sigue vivo para el CI

    def test_4_el_token_no_contiene_datos_sensibles(self):
        token = self.registrar().get_json()["token"]
        claims = jwt.decode(token, self.jwt_secret, algorithms=["HS256"])
        self.assertEqual(set(claims), {"sub", "role", "iat", "exp"})
        self.assertNotIn(USUARIO["password"], token)


if __name__ == "__main__":
    unittest.main()
