"""Build default iOS functionality section."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class FunctionalityEntry:
    present: bool = False
    explanation: str = ""


@dataclass
class IOSFunctionality:
    Camera: FunctionalityEntry = field(default_factory=FunctionalityEntry)
    Biometric_Authentication: FunctionalityEntry = field(default_factory=FunctionalityEntry)
    Networking: FunctionalityEntry = field(default_factory=FunctionalityEntry)
    Secure_RNG: FunctionalityEntry = field(default_factory=FunctionalityEntry)
    Push_Notifications: FunctionalityEntry = field(default_factory=FunctionalityEntry)
    Audio: FunctionalityEntry = field(default_factory=FunctionalityEntry)
    Contacts: FunctionalityEntry = field(default_factory=FunctionalityEntry)
    Geofencing: FunctionalityEntry = field(default_factory=FunctionalityEntry)
    Health_Data: FunctionalityEntry = field(default_factory=FunctionalityEntry)
    Location: FunctionalityEntry = field(default_factory=FunctionalityEntry)
    Maps: FunctionalityEntry = field(default_factory=FunctionalityEntry)
    Payment_Services: FunctionalityEntry = field(default_factory=FunctionalityEntry)
    SMS: FunctionalityEntry = field(default_factory=FunctionalityEntry)
    Bluetooth: FunctionalityEntry = field(default_factory=FunctionalityEntry)
    Camera_Delegation: FunctionalityEntry = field(default_factory=FunctionalityEntry)
    Calendar: FunctionalityEntry = field(default_factory=FunctionalityEntry)
    In_App_Purchases: FunctionalityEntry = field(default_factory=FunctionalityEntry)
    Keychain: FunctionalityEntry = field(default_factory=FunctionalityEntry)
    Microphone: FunctionalityEntry = field(default_factory=FunctionalityEntry)
    NFC: FunctionalityEntry = field(default_factory=FunctionalityEntry)
    Photos: FunctionalityEntry = field(default_factory=FunctionalityEntry)
    Sensors: FunctionalityEntry = field(default_factory=FunctionalityEntry)
    Telephony: FunctionalityEntry = field(default_factory=FunctionalityEntry)
    USB_Devices: FunctionalityEntry = field(default_factory=FunctionalityEntry)
    Nearby_Interaction: FunctionalityEntry = field(default_factory=FunctionalityEntry)

    def __init__(self, loaded_outputs: dict[str, Any]) -> None:
        _ = loaded_outputs
        self.Camera = FunctionalityEntry()
        self.Biometric_Authentication = FunctionalityEntry()
        self.Networking = FunctionalityEntry()
        self.Secure_RNG = FunctionalityEntry()
        self.Push_Notifications = FunctionalityEntry()
        self.Audio = FunctionalityEntry()
        self.Contacts = FunctionalityEntry()
        self.Geofencing = FunctionalityEntry()
        self.Health_Data = FunctionalityEntry()
        self.Location = FunctionalityEntry()
        self.Maps = FunctionalityEntry()
        self.Payment_Services = FunctionalityEntry()
        self.SMS = FunctionalityEntry()
        self.Bluetooth = FunctionalityEntry()
        self.Camera_Delegation = FunctionalityEntry()
        self.Calendar = FunctionalityEntry()
        self.In_App_Purchases = FunctionalityEntry()
        self.Keychain = FunctionalityEntry()
        self.Microphone = FunctionalityEntry()
        self.NFC = FunctionalityEntry()
        self.Photos = FunctionalityEntry()
        self.Sensors = FunctionalityEntry()
        self.Telephony = FunctionalityEntry()
        self.USB_Devices = FunctionalityEntry()
        self.Nearby_Interaction = FunctionalityEntry()
