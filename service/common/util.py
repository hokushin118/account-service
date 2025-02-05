"""
Utility functions.

This module contains utility functions to REST API.
"""
from flask import request, abort

from service import app
from service.common import status


######################################################################
#  U T I L I T Y   F U N C T I O N S
######################################################################
def check_content_type(media_type):
    """Checks that the media type is correct."""
    content_type = request.headers.get('Content-Type')
    if content_type and content_type == media_type:
        return
    app.logger.error("Invalid Content-Type: %s", content_type)
    abort(
        status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
        f"Content-Type must be {media_type}",
    )
