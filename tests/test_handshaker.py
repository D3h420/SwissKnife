#!/usr/bin/env python3

from __future__ import annotations

import types
import unittest
from pathlib import Path
from unittest import mock
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from modules import handshaker


class FakeDot11:
    def __init__(self, addr1: str, addr2: str, addr3: str, fcfield: int = 0) -> None:
        self.addr1 = addr1
        self.addr2 = addr2
        self.addr3 = addr3
        self.FCfield = fcfield


class FakeLayerBytes:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def __bytes__(self) -> bytes:
        return self.payload


class FakePacket:
    def __init__(self, layers: dict) -> None:
        self._layers = dict(layers)

    def haslayer(self, layer) -> bool:
        return layer in self._layers

    def __getitem__(self, layer):
        return self._layers[layer]


def build_eapol_key_bytes(
    key_info: int,
    replay_counter: int,
    *,
    key_data_len: int = 0,
    descriptor_type: int = 2,
    eapol_type: int = handshaker.EAPOL_TYPE_KEY,
) -> bytes:
    payload_len = handshaker.EAPOL_KEY_MIN_LEN + max(0, int(key_data_len))
    payload = bytearray(payload_len)
    payload[0] = descriptor_type
    payload[1:3] = int(key_info).to_bytes(2, "big")
    payload[3:5] = (16).to_bytes(2, "big")
    payload[5:13] = int(replay_counter).to_bytes(8, "big")
    payload[93:95] = int(key_data_len).to_bytes(2, "big")

    frame = bytearray(4 + payload_len)
    frame[0] = 2
    frame[1] = int(eapol_type)
    frame[2:4] = payload_len.to_bytes(2, "big")
    frame[4:] = payload
    return bytes(frame)


def make_eapol_packet(
    dot11_layer,
    eapol_layer,
    *,
    bssid: str,
    client: str,
    from_ap: bool,
    key_info: int,
    replay_counter: int,
    key_data_len: int = 0,
    eapol_type: int = handshaker.EAPOL_TYPE_KEY,
) -> FakePacket:
    if from_ap:
        dot11 = FakeDot11(addr1=client, addr2=bssid, addr3=bssid, fcfield=0x2)
    else:
        dot11 = FakeDot11(addr1=bssid, addr2=client, addr3=bssid, fcfield=0x1)

    eapol_bytes = build_eapol_key_bytes(
        key_info,
        replay_counter,
        key_data_len=key_data_len,
        eapol_type=eapol_type,
    )
    return FakePacket(
        {
            dot11_layer: dot11,
            eapol_layer: FakeLayerBytes(eapol_bytes),
        }
    )


class HandshakerEapolValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.dot11_layer = object()
        self.eapol_layer = object()
        self.layer_patch = mock.patch.multiple(
            handshaker,
            Dot11=self.dot11_layer,
            EAPOL=self.eapol_layer,
        )
        self.layer_patch.start()

    def tearDown(self) -> None:
        self.layer_patch.stop()

    def _parse(self, packet: FakePacket, bssid: str) -> handshaker.EapolKeyFrame:
        frame = handshaker.parse_eapol_key_frame(packet, bssid)
        self.assertIsNotNone(frame)
        return frame

    def test_parse_eapol_key_frame_and_classify_message_1(self) -> None:
        bssid = "aa:bb:cc:dd:ee:ff"
        client = "12:22:33:44:55:66"
        key_info = handshaker.KEY_INFO_PAIRWISE | handshaker.KEY_INFO_ACK

        packet = make_eapol_packet(
            self.dot11_layer,
            self.eapol_layer,
            bssid=bssid,
            client=client,
            from_ap=True,
            key_info=key_info,
            replay_counter=7,
            key_data_len=24,
        )

        frame = self._parse(packet, bssid)
        self.assertEqual(frame.client, client)
        self.assertTrue(frame.from_ap)
        self.assertTrue(frame.ack)
        self.assertFalse(frame.mic)
        self.assertEqual(handshaker.classify_4way_message(frame), 1)

    def test_parse_eapol_key_frame_rejects_non_key_type(self) -> None:
        bssid = "aa:bb:cc:dd:ee:ff"
        client = "12:22:33:44:55:66"
        key_info = handshaker.KEY_INFO_PAIRWISE | handshaker.KEY_INFO_ACK
        packet = make_eapol_packet(
            self.dot11_layer,
            self.eapol_layer,
            bssid=bssid,
            client=client,
            from_ap=True,
            key_info=key_info,
            replay_counter=1,
            eapol_type=0,
        )
        frame = handshaker.parse_eapol_key_frame(packet, bssid)
        self.assertIsNone(frame)

    def test_valid_m1_m2_m3_m4_sequence_completes_handshake(self) -> None:
        bssid = "aa:bb:cc:dd:ee:ff"
        client = "12:22:33:44:55:66"
        states: dict[str, handshaker.HandshakeProgress] = {}

        m1 = handshaker.KEY_INFO_PAIRWISE | handshaker.KEY_INFO_ACK
        m2 = handshaker.KEY_INFO_PAIRWISE | handshaker.KEY_INFO_MIC
        m3 = (
            handshaker.KEY_INFO_PAIRWISE
            | handshaker.KEY_INFO_ACK
            | handshaker.KEY_INFO_MIC
            | handshaker.KEY_INFO_SECURE
            | handshaker.KEY_INFO_INSTALL
        )
        m4 = handshaker.KEY_INFO_PAIRWISE | handshaker.KEY_INFO_MIC | handshaker.KEY_INFO_SECURE

        sequence = [
            make_eapol_packet(self.dot11_layer, self.eapol_layer, bssid=bssid, client=client, from_ap=True, key_info=m1, replay_counter=9, key_data_len=22),
            make_eapol_packet(self.dot11_layer, self.eapol_layer, bssid=bssid, client=client, from_ap=False, key_info=m2, replay_counter=9, key_data_len=18),
            make_eapol_packet(self.dot11_layer, self.eapol_layer, bssid=bssid, client=client, from_ap=True, key_info=m3, replay_counter=10, key_data_len=40),
            make_eapol_packet(self.dot11_layer, self.eapol_layer, bssid=bssid, client=client, from_ap=False, key_info=m4, replay_counter=10, key_data_len=0),
        ]

        completed = 0
        now = 100.0
        for packet in sequence:
            frame = self._parse(packet, bssid)
            _advanced, is_complete, _msg = handshaker.update_handshake_progress(states, frame, now=now)
            completed += int(is_complete)
            now += 0.4

        self.assertEqual(completed, 1)

    def test_out_of_order_sequence_is_rejected(self) -> None:
        bssid = "aa:bb:cc:dd:ee:ff"
        client = "12:22:33:44:55:66"
        states: dict[str, handshaker.HandshakeProgress] = {}

        m1 = handshaker.KEY_INFO_PAIRWISE | handshaker.KEY_INFO_ACK
        m3 = handshaker.KEY_INFO_PAIRWISE | handshaker.KEY_INFO_ACK | handshaker.KEY_INFO_MIC | handshaker.KEY_INFO_SECURE
        m4 = handshaker.KEY_INFO_PAIRWISE | handshaker.KEY_INFO_MIC | handshaker.KEY_INFO_SECURE

        sequence = [
            make_eapol_packet(self.dot11_layer, self.eapol_layer, bssid=bssid, client=client, from_ap=True, key_info=m1, replay_counter=3),
            make_eapol_packet(self.dot11_layer, self.eapol_layer, bssid=bssid, client=client, from_ap=True, key_info=m3, replay_counter=4),
            make_eapol_packet(self.dot11_layer, self.eapol_layer, bssid=bssid, client=client, from_ap=False, key_info=m4, replay_counter=4),
        ]

        completed = 0
        for packet in sequence:
            frame = self._parse(packet, bssid)
            _advanced, is_complete, _msg = handshaker.update_handshake_progress(states, frame, now=50.0)
            completed += int(is_complete)

        self.assertEqual(completed, 0)

    def test_duplicate_m3_retry_does_not_double_count(self) -> None:
        bssid = "aa:bb:cc:dd:ee:ff"
        client = "12:22:33:44:55:66"
        states: dict[str, handshaker.HandshakeProgress] = {}

        m1 = handshaker.KEY_INFO_PAIRWISE | handshaker.KEY_INFO_ACK
        m2 = handshaker.KEY_INFO_PAIRWISE | handshaker.KEY_INFO_MIC
        m3 = handshaker.KEY_INFO_PAIRWISE | handshaker.KEY_INFO_ACK | handshaker.KEY_INFO_MIC | handshaker.KEY_INFO_SECURE
        m4 = handshaker.KEY_INFO_PAIRWISE | handshaker.KEY_INFO_MIC | handshaker.KEY_INFO_SECURE

        sequence = [
            make_eapol_packet(self.dot11_layer, self.eapol_layer, bssid=bssid, client=client, from_ap=True, key_info=m1, replay_counter=10),
            make_eapol_packet(self.dot11_layer, self.eapol_layer, bssid=bssid, client=client, from_ap=False, key_info=m2, replay_counter=10),
            make_eapol_packet(self.dot11_layer, self.eapol_layer, bssid=bssid, client=client, from_ap=True, key_info=m3, replay_counter=11),
            make_eapol_packet(self.dot11_layer, self.eapol_layer, bssid=bssid, client=client, from_ap=True, key_info=m3, replay_counter=11),
            make_eapol_packet(self.dot11_layer, self.eapol_layer, bssid=bssid, client=client, from_ap=False, key_info=m4, replay_counter=11),
            make_eapol_packet(self.dot11_layer, self.eapol_layer, bssid=bssid, client=client, from_ap=False, key_info=m4, replay_counter=11),
        ]

        completed = 0
        for packet in sequence:
            frame = self._parse(packet, bssid)
            _advanced, is_complete, _msg = handshaker.update_handshake_progress(states, frame, now=200.0)
            completed += int(is_complete)

        self.assertEqual(completed, 1)


class HandshakerInterfaceMockTests(unittest.TestCase):
    def test_list_network_interfaces_parses_ip_link_output(self) -> None:
        sample = """1: lo: <LOOPBACK> mtu 65536\n2: wlan0: <BROADCAST> mtu 1500\n3: wlan1: <BROADCAST> mtu 1500\n"""
        run_result = types.SimpleNamespace(stdout=sample, returncode=0)

        with mock.patch.object(handshaker.subprocess, "run", return_value=run_result) as run_mock:
            interfaces = handshaker.list_network_interfaces()

        self.assertEqual(interfaces, ["wlan0", "wlan1"])
        run_mock.assert_called_once()

    def test_set_interface_type_returns_false_when_iw_fails(self) -> None:
        down_ok = types.SimpleNamespace(returncode=0, stderr="")
        iw_fail = types.SimpleNamespace(returncode=1, stderr="bad mode")

        with (
            mock.patch.object(handshaker.subprocess, "run", side_effect=[down_ok, iw_fail]) as run_mock,
            mock.patch.object(handshaker.time, "sleep", return_value=None),
        ):
            ok = handshaker.set_interface_type("wlan1", "monitor")

        self.assertFalse(ok)
        self.assertEqual(run_mock.call_count, 2)
        iw_cmd = run_mock.call_args_list[1].args[0]
        self.assertEqual(iw_cmd, ["iw", "dev", "wlan1", "set", "type", "monitor"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
