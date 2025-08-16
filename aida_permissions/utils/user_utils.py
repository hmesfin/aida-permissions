"""
Utilities for handling different User model configurations.
"""
from django.contrib.auth import get_user_model

User = get_user_model()


def get_user_identifier_field():
    """
    Get the primary identifier field for the User model.
    Returns 'email' if USERNAME_FIELD is email, otherwise USERNAME_FIELD.
    """
    return getattr(User, 'USERNAME_FIELD', 'username')


def get_user_identifier(user):
    """
    Get the identifier value for a user instance.
    Handles both username and email-based User models.
    """
    if user is None:
        return None
    
    identifier_field = get_user_identifier_field()
    identifier = getattr(user, identifier_field, None)
    
    # Fallback attempts
    if identifier is None:
        if hasattr(user, 'email') and user.email:
            return user.email
        if hasattr(user, 'username') and user.username:
            return user.username
        if hasattr(user, 'get_username'):
            return user.get_username()
    
    return identifier or str(user.pk)


def get_user_display_name(user):
    """
    Get a display name for the user.
    Tries multiple fields to find the best representation.
    """
    if user is None:
        return "Unknown"
    
    # Try get_full_name first
    if hasattr(user, 'get_full_name'):
        full_name = user.get_full_name()
        if full_name and full_name.strip():
            return full_name
    
    # Try full_name attribute
    if hasattr(user, 'full_name') and user.full_name:
        return user.full_name
    
    # Try combining first_name and last_name
    if hasattr(user, 'first_name') and hasattr(user, 'last_name'):
        name_parts = []
        if user.first_name:
            name_parts.append(user.first_name)
        if user.last_name:
            name_parts.append(user.last_name)
        if name_parts:
            return ' '.join(name_parts)
    
    # Try username or email
    identifier = get_user_identifier(user)
    if identifier:
        return identifier
    
    # Last resort
    return f"User #{user.pk}"


def get_user_search_fields():
    """
    Get appropriate search fields for the User model.
    Adapts based on available fields in the User model.
    """
    search_fields = []
    
    # Check for common identifier fields
    if hasattr(User, 'USERNAME_FIELD'):
        username_field = getattr(User, 'USERNAME_FIELD', 'username')
        search_fields.append(f"user__{username_field}")
    
    # Add common fields if they exist
    user_instance = User()
    
    if hasattr(user_instance, 'email') and 'user__email' not in search_fields:
        search_fields.append('user__email')
    
    if hasattr(user_instance, 'username') and 'user__username' not in search_fields:
        search_fields.append('user__username')
    
    if hasattr(user_instance, 'first_name'):
        search_fields.append('user__first_name')
    
    if hasattr(user_instance, 'last_name'):
        search_fields.append('user__last_name')
    
    # Always add role search fields
    search_fields.extend(['role__name', 'role__display_name'])
    
    # Ensure we have at least some search fields
    if not any(field.startswith('user__') for field in search_fields):
        search_fields.insert(0, 'user__pk')
    
    return search_fields


def get_username_or_email(user):
    """
    Get username or email for a user, whichever is available.
    """
    if hasattr(user, 'username') and user.username:
        return user.username
    if hasattr(user, 'email') and user.email:
        return user.email
    if hasattr(user, 'get_username'):
        return user.get_username()
    return str(user.pk)