"""
Database Schemas for Daily Task Manager

Each Pydantic model represents a collection in MongoDB.
Class name lowercased is used as the collection name.
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List
from datetime import datetime

class AuthUser(BaseModel):
    """
    Collection name: "authuser"
    Stores user accounts for authentication
    """
    email: EmailStr = Field(..., description="Unique email for login")
    name: str = Field(..., min_length=1, max_length=80)
    hashed_password: str = Field(..., description="BCrypt hashed password")
    avatar_color: Optional[str] = Field(default="#6366f1")
    is_active: bool = True

class Task(BaseModel):
    """
    Collection name: "task"
    Stores tasks with scheduling and completion state
    """
    user_id: str = Field(..., description="Reference to authuser _id as string")
    title: str = Field(..., min_length=1, max_length=140)
    notes: Optional[str] = Field(default=None, max_length=1000)
    date: str = Field(..., description="ISO date string YYYY-MM-DD")
    time: Optional[str] = Field(default=None, description="HH:MM 24h time")
    priority: int = Field(default=2, ge=1, le=3, description="1=High,2=Med,3=Low")
    completed: bool = Field(default=False)
    tags: List[str] = Field(default_factory=list)

class NotificationToken(BaseModel):
    """
    Collection name: "notificationtoken"
    Stores browser notification permission/device tokens if used later
    """
    user_id: str
    token: str
    platform: Optional[str] = None
    subscribed: bool = True

