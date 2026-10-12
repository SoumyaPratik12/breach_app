from app.models.identifier import IdentifierType


def mask_identifier(
    identifier_type: IdentifierType,
    value: str,
) -> str:
    """Return a masked identifier for API responses."""
    if identifier_type == IdentifierType.EMAIL:
        local, separator, domain = value.partition("@")
        if separator and local and domain:
            return f"{local[0]}•••••@{domain}"
        return "••••"
    if identifier_type == IdentifierType.PHONE:
        digits = "".join(char for char in value if "0" <= char <= "9")
        if len(digits) <= 4:
            return "••••"
        prefix = "+" if value.strip().startswith("+") else ""
        return f"{prefix}••••••{digits[-4:]}"
    if identifier_type in {
        IdentifierType.USERNAME,
        IdentifierType.NAME,
    }:
        if not value:
            return "••••"
        return f"{value[0]}••••"
    return "••••"
