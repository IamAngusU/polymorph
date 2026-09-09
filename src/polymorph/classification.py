from __future__ import annotations

import re

from .models.types import FieldRole, Sensitivity

_SECRET = re.compile(
    r"(?:password|passwd|passwort|kennwort|pwd|secret|api[ _-]?key|access[ _-]?token|"
    r"refresh[ _-]?token|api[ _-]?token|token|bearer|private[ _-]?key|credential|credentials)",
    re.IGNORECASE,
)
_PERSONAL = re.compile(
    r"(?:e[ _-]?mail|mail[ _-]?address|phone|telefon|mobile|address|adresse|birth|dob|"
    r"first[ _-]?name|last[ _-]?name|firstname|lastname|vorname|nachname)",
    re.IGNORECASE,
)
_CONFIDENTIAL = re.compile(
    r"(?:iban|bic|swift|credit[ _-]?card|card[ _-]?number|tax[ _-]?id|steuer[ _-]?id|ssn)",
    re.IGNORECASE,
)


def classify_field_name(name: str) -> Sensitivity:
    if _SECRET.search(name):
        return Sensitivity.SECRET
    if _CONFIDENTIAL.search(name):
        return Sensitivity.CONFIDENTIAL
    if _PERSONAL.search(name):
        return Sensitivity.PERSONAL
    return Sensitivity.INTERNAL


_NATURAL_KEY = re.compile(
    r"(?:^|[ _-])(?:id|identifier|kennung|nummer|number|nr|no)(?:$|[ _-])|"
    r"(?:kundennr|customer[ _-]?number|client[ _-]?number|debitor[ _-]?nr|order[ _-]?number)",
    re.IGNORECASE,
)


def infer_role(name: str) -> FieldRole:
    if _SECRET.search(name):
        return FieldRole.CREDENTIAL
    if _NATURAL_KEY.search(name):
        return FieldRole.NATURAL_KEY
    return FieldRole.VALUE
