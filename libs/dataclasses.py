from dataclasses import dataclass, field
from typing import Any, Optional, List, Dict

@dataclass
class PyDALField:
    name: str
    field_type: str
    requires: Optional[Any] = None
    default: Optional[Any] = None
    notnull: bool = False
    unique: bool = False
    label: Optional[str] = None
    comment: Optional[str] = None
    writable: bool = True
    readable: bool = True
    length: Optional[int] = None
    other_options: Dict[str, Any] = field(default_factory=dict)

    def to_pydal_field(self):
        """
        Converts the dataclass instance into a PyDAL field definition.
        """
        field_definition = {
            "type": self.field_type,
            "requires": self.requires,
            "default": self.default,
            "notnull": self.notnull,
            "unique": self.unique,
            "label": self.label,
            "comment": self.comment,
            "writable": self.writable,
            "readable": self.readable,
            "length": self.length,
            **self.other_options,
        }
        # Remove keys with None values
        return {k: v for k, v in field_definition.items() if v is not None}