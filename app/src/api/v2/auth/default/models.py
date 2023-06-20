from datetime import datetime
from math import ceil

from pydantic import BaseModel, Field

from api.common.models import ConfigOrjsonMixin


class ResponseUserLoginHistoryEntry(BaseModel):
    created: datetime

    class Config(ConfigOrjsonMixin):
        """Model Config"""


class ResponseUserLoginHistory(BaseModel):
    """Response model for the user history login."""

    total_login_count: int
    page_size: int
    page_number: int
    total_pages: int | None = None
    next_page: int | None = None
    prev_page: int | None = None
    login_history: list[ResponseUserLoginHistoryEntry] = Field(
        default_factory=list)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.total_pages = ceil(self.total_login_count / self.page_size)

        self.next_page = (
            self.page_number + 1
            if self.page_number < self.total_pages
            else None
        )
        self.prev_page = self.page_number - 1 if self.page_number > 1 else None

    class Config(ConfigOrjsonMixin):
        """Model Config"""
