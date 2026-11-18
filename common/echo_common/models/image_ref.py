from typing import Self

from pydantic import Field

from echo_common.models.base import DomainModel


class ImageRef(DomainModel):
    """A container image reference split into name and tag."""

    name: str = Field(min_length=1, max_length=255)
    tag: str = Field(default="latest", min_length=1, max_length=128)

    @classmethod
    def parse(cls, ref: str) -> Self:
        ref = ref.strip()
        if not ref:
            raise ValueError("empty image reference")
        # Only treat the last ':' as a tag separator if it comes after the last '/'
        # (so registry ports like "localhost:5000/app" are not mistaken for tags).
        name, sep, tag = ref.rpartition(":")
        if not sep or "/" in tag:
            return cls(name=ref)
        return cls(name=name, tag=tag)

    def __str__(self) -> str:
        return f"{self.name}:{self.tag}"
