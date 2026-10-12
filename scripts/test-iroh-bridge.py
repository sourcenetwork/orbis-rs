import runpy
from pathlib import Path
import unittest

summarize = runpy.run_path(str(Path(__file__).with_name('qualify-iroh-bridge.py')))['endpoint_summary']


class EndpointSummaryTests(unittest.TestCase):
    def test_loader_failure_is_classified_without_exporting_log_payloads(self):
        state = {'Running': False, 'ExitCode': 127, 'OOMKilled': False, 'Error': ''}
        result = summarize(state, 'error while loading shared libraries: private-library.so: cannot open shared object file')
        self.assertEqual(result['error_kinds'], ['runtime_library_missing'])
        self.assertEqual(result['exit_code'], 127)
        self.assertNotIn('private-library', str(result))

    def test_panic_preserves_only_bounded_fixture_locations(self):
        state = {'Running': False, 'ExitCode': 101, 'OOMKilled': False, 'Error': ''}
        result = summarize(state, 'private panic data at crates/network/src/iroh/restart_tests.rs:137:10\n'
                           'unrelated.rs:42:1\n' * 20)
        self.assertEqual(result['panic_locations'], [{'line': 137, 'column': 10}])
        self.assertNotIn('private panic', str(result))
        self.assertNotIn('unrelated', str(result))

    def test_container_state_distinguishes_memory_failure_from_execution_failure(self):
        killed = summarize({'Running': False, 'ExitCode': 137, 'OOMKilled': True}, '')
        self.assertTrue(killed['oom_killed'])
        denied = summarize({'Running': False, 'ExitCode': 126, 'OOMKilled': False,
                            'Error': 'exec /private/path: permission denied'}, '')
        self.assertEqual(denied['error_kinds'], ['permission_denied'])
        self.assertNotIn('/private/path', str(denied))


if __name__ == '__main__':
    unittest.main()
