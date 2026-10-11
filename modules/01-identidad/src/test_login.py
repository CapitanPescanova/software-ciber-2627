"""AAA-3 (login). Tests de Diego."""
import unittest

from base import USUARIO, BaseTest


class TestLogin(BaseTest):
    def setUp(self):
        super().setUp()
        self.assertEqual(self.registrar().status_code, 201)

    def test_1_credenciales_correctas_200_con_token_y_user(self):
        r = self.login(username=USUARIO["username"], password=USUARIO["password"])
        self.assertEqual(r.status_code, 200)
        cuerpo = r.get_json()
        self.assertIn("token", cuerpo)
        self.assertEqual(cuerpo["user"]["username"], USUARIO["username"])

    def test_2_password_incorrecta_401_sin_token(self):
        r = self.login(username=USUARIO["username"], password="otra-contrasena")
        self.assertEqual(r.status_code, 401)
        self.assertIn("error", r.get_json())
        self.assertNotIn("token", r.get_json())

    def test_3_usuario_inexistente_401_con_el_mismo_mensaje(self):
        mala_pass = self.login(username=USUARIO["username"], password="otra-contrasena")
        no_existe = self.login(username="no.existe", password="otra-contrasena")
        self.assertEqual(no_existe.status_code, 401)
        self.assertEqual(mala_pass.get_json(), no_existe.get_json())

    def test_4_faltan_campos_400(self):
        self.assertEqual(self.login(username=USUARIO["username"]).status_code, 400)
        self.assertEqual(self.login(password=USUARIO["password"]).status_code, 400)
        self.assertEqual(self.login().status_code, 400)


if __name__ == "__main__":
    unittest.main()
