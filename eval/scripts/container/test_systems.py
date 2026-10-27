#!/usr/bin/env python3
"""Tests for the client command lines in systems.py.
Run: python3 -m unittest eval/scripts/container/test_systems.py
"""
import unittest

import systems

VARIANT = "hqc5"
ADDRESS = "127.0.0.1:12345"


class ClientCommandTest(unittest.TestCase):
    def test_every_system_binds_the_legit_source_address(self):
        for name, system in systems.SYSTEMS.items():
            with self.subTest(system=name):
                command = system.client_command(VARIANT, ADDRESS, systems.LEGIT_SOURCE_IP)
                position = command.index("--bind-ip")
                self.assertEqual(command[position + 1], systems.LEGIT_SOURCE_IP)

    def test_no_bind_option_without_a_bind_address(self):
        for name, system in systems.SYSTEMS.items():
            with self.subTest(system=name):
                self.assertNotIn("--bind-ip", system.client_command(VARIANT, ADDRESS))


if __name__ == "__main__":
    unittest.main()
