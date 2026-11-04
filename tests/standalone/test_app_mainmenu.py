# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

from unittest.mock import Mock

import pytest
from ledgered.devices import Device
from ragger.navigator import Navigator, NavInsID

from tests.standalone.settings import SettingID, settings_toggle


# In this test we check the behavior of the device main menu
def test_app_mainmenu(device: Device, navigator: Navigator) -> None:
    if isinstance(navigator, Mock):
        pytest.skip("Menu test requires real navigation; skipping under --no-nav")

    # Toggle both settings to exercise the full menu
    settings_toggle(
        device,
        navigator,
        [
            SettingID.SILENT_PUBKEY_EXPORT,
            SettingID.EXPERT_MODE,
            SettingID.BLIND_SIGNING,
        ],
    )

    if not device.is_nano:
        # Touch devices need to navigate to the info page and back
        navigator.navigate(
            [
                NavInsID.USE_CASE_HOME_SETTINGS,
                NavInsID.USE_CASE_SETTINGS_NEXT,
                NavInsID.USE_CASE_SETTINGS_NEXT,
                NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT,
            ],
            screen_change_before_first_instruction=False,
        )


# On first launch the settings switches must render the written defaults, not the uninitialized NVM
def test_first_launch_settings_display(
    device: Device,
    navigator: Navigator,
    default_screenshot_path,
) -> None:
    if isinstance(navigator, Mock):
        pytest.skip("Settings display check requires real navigation; skipped under --no-nav")

    if device.is_nano:
        # The settings subpage opens on Silent pubkeys; step through Expert mode and Blind signing
        open_settings = [
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
        ]
    else:
        # Page 0 shows Silent export and Expert mode, page 1 shows Blind signing
        open_settings = [
            NavInsID.USE_CASE_HOME_SETTINGS,
            NavInsID.USE_CASE_SETTINGS_NEXT,
        ]

    navigator.navigate_and_compare(
        default_screenshot_path,
        "First_launch_settings_display",
        open_settings,
        screen_change_before_first_instruction=False,
    )
