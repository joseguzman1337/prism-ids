import unittest

from prism.flow import Flow, FlowDirection, FlowState
from prism.hook import Hook
from prism.sticky_buffer import StickyBuffer


class ProfileTest(unittest.TestCase):
    _profile_name = 'all'
    _client = Flow(
        direction=FlowDirection.CLIENT,
        state=FlowState.ESTABLISHED,
    )
    _server = Flow(
        direction=FlowDirection.SERVER,
        state=FlowState.ESTABLISHED,
    )
    _both = Flow(
        direction=FlowDirection.BOTH,
        state=FlowState.ESTABLISHED,
    )

    def setUp(self):
        self.profile = Hook.profiles[self._profile_name]
        for k, v in self.profile.hook_names.items():
            setattr(self, k, v)


class Test_AllProfile(ProfileTest):
    def test_tcp_client(self):
        hooks = self.profile.determine(
            'tcp',
            self._client,
            (
                StickyBuffer.PKT_DATA,
            )
        )

        self.assertTupleEqual(hooks, (
            self.tcp_client,
        ))

    def test_tcp_server(self):
        hooks = self.profile.determine(
            'tcp',
            self._server,
            (
                StickyBuffer.PKT_DATA,
            )
        )

        self.assertTupleEqual(hooks, (
            self.tcp_server,
        ))

    def test_tcp_both(self):
        hooks = self.profile.determine(
            'tcp',
            self._both,
            (
                StickyBuffer.PKT_DATA,
            )
        )

        self.assertTupleEqual(hooks, (
            self.tcp_client,
            self.tcp_server,
        ))
