import tempfile
import unittest
from pathlib import Path

import host_state

INTERRUPTS = """\
            CPU0       CPU2       CPU3
  60:          5         10          0 IR-PCI-MSI 524288-edge enp2s0
 LOC:        100        200        300 Local timer interrupts
 ERR:          0
"""


class InterruptParsing(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        path = Path(self.directory.name) / "interrupts"
        path.write_text(INTERRUPTS)
        self.original = host_state.INTERRUPTS_FILE
        host_state.INTERRUPTS_FILE = path

    def tearDown(self):
        host_state.INTERRUPTS_FILE = self.original
        self.directory.cleanup()

    def test_counts_per_cpu_and_description(self):
        rows = host_state.interrupt_counts()
        self.assertEqual(rows["60"]["per_cpu"], {0: 5, 2: 10, 3: 0})
        self.assertEqual(rows["60"]["description"], "IR-PCI-MSI 524288-edge enp2s0")
        self.assertEqual(rows["ERR"]["per_cpu"], {0: 0})

    def test_device_interrupts_on_pinned_cores(self):
        start = {"time_monotonic": 0.0, "nic": {}, "interrupts": host_state.interrupt_counts(), "irq_affinity": {}}
        end = {"time_monotonic": 4.0, "nic": {}, "irq_affinity": {}, "interrupts": {
            "60": {"description": "", "per_cpu": {0: 5, 2: 40, 3: 0}},
            "LOC": {"description": "", "per_cpu": {0: 150, 2: 250, 3: 300}},
        }}
        deltas = host_state.counter_deltas(start, end, [0, 2])
        self.assertEqual(deltas["device_interrupts_on_pinned_cores"], {"60": {2: 30}})
        self.assertEqual(deltas["seconds"], 4.0)


if __name__ == "__main__":
    unittest.main()
