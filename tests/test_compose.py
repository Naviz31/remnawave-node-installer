import unittest

from remnawave_node.compose import compose_text, env_text


class ComposeTests(unittest.TestCase):
    def test_compose_uses_host_network_and_fixed_image(self):
        text = compose_text("remnawave/node:3.4.1")
        self.assertIn("network_mode: host", text)
        self.assertIn("remnawave/node:3.4.1", text)
        self.assertNotIn(":latest", text)

    def test_secret_is_in_env_file_not_compose(self):
        compose = compose_text()
        env = env_text(2222, "secret-value")
        self.assertNotIn("secret-value", compose)
        self.assertIn('SECRET_KEY="secret-value"', env)


if __name__ == "__main__":
    unittest.main()
