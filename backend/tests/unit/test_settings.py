from app.config.settings import settings


def test_settings_load():
    assert settings.app_name == "Digital Footprint Exposure Scanner"
    assert settings.environment == "dev"
    assert settings.aws_region == "ap-south-1"
