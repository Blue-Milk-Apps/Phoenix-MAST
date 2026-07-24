"""Build default iOS third-party SDK section."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class AnalyticsSDKs:
    GoogleAnalytics: bool = False
    Flurry: bool = False
    Amplitude: bool = False
    Mixpanel: bool = False
    NewRelic: bool = False


@dataclass
class AdvertisingSDKs:
    Admob: bool = False
    DoubleClick: bool = False
    Chartboost: bool = False
    AppLovin: bool = False


@dataclass
class CloudStorageSDKs:
    GoogleDrive: bool = False
    Dropbox: bool = False
    OneDrive: bool = False
    Box: bool = False


@dataclass
class DeveloperToolsSDKs:
    Stripe: bool = False
    Paypal: bool = False
    Alamofire: bool = False
    Fabric: bool = False
    Parse: bool = False
    Realm: bool = False
    Bolts: bool = False


@dataclass
class IOSThirdPartySDKs:
    Analytics: AnalyticsSDKs
    Advertising: AdvertisingSDKs
    Cloud_Storage: CloudStorageSDKs
    Developer_Tools: DeveloperToolsSDKs

    def __init__(self, loaded_outputs: dict[str, Any]) -> None:
        _ = loaded_outputs
        self.Analytics = AnalyticsSDKs()
        self.Advertising = AdvertisingSDKs()
        self.Cloud_Storage = CloudStorageSDKs()
        self.Developer_Tools = DeveloperToolsSDKs()
