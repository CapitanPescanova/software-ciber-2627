"""AAA-18 (registro de usuarios). Tests de Jaime."""
import sqlite3
import unittest

from base import USUARIO, BaseTest


class TestRegistro(BaseTest):
    def test_1_registro_valido_201_con_token_y_user_sin_password(self):
        r = self.registrar()
        self.assertEqual(r.status_code, 201)
        cuerpo = r.get_json()
        self.assertIn("token", cuerpo)
        self.assertEqual(cuerpo["user"]["username"], USUARIO["username"])
        self.assertEqual(cuerpo["user"]["email"], USUARIO["email"])
        self.assertEqual(cuerpo["user"]["role"], "analista")
        self.assertIsInstance(cuerpo["user"]["id"], int)
        self.assertNotIn("password", cuerpo["user"])
        self.assertNotIn(USUARIO["password"], r.get_data(as_text=True))

    def test_2_usuario_o_email_repetidos_409(self):
        self.assertEqual(self.registrar().status_code, 201)
        r = self.registrar(email="otro@ciberurjc.local")  # mismo username
        self.assertEqual(r.status_code, 409)
        r = self.registrar(username="otro.usuario")  # mismo email
        self.assertEqual(r.status_code, 409)
        self.assertEqual(self.contar_usuarios(), 1)

    def test_3_datos_invalidos_400_y_no_se_crea_cuenta(self):
        casos = [
            {"username": ""},
            {"password": "corta"},
            {"username": "ab"},
            {"email": "no-es-un-email"},
        ]
        for caso in casos:
            with self.subTest(caso=caso):
                self.assertEqual(self.registrar(**caso).status_code, 400)
        r = self.client.post("/auth/register", json={"username": "solo.usuario"})
        self.assertEqual(r.status_code, 400)
        r = self.client.post("/auth/register", data="no es json", content_type="text/plain")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(self.contar_usuarios(), 0)

    def test_4_password_guardada_con_hash_y_sal_nunca_en_claro(self):
        self.registrar()
        self.registrar(username="segundo.usuario", email="segundo@ciberurjc.local")
        filas = sqlite3.connect(self.db_path).execute("SELECT password_hash FROM users").fetchall()
        hashes = [f[0] for f in filas]
        for h in hashes:
            self.assertNotEqual(h, USUARIO["password"])
            self.assertNotIn(USUARIO["password"], h)
        # Misma contraseña, hashes distintos: hay sal
        self.assertNotEqual(hashes[0], hashes[1])


if __name__ == "__main__":
    unittest.main()
