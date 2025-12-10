from celery import shared_task
from django.utils import timezone
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken
import logging

logger = logging.getLogger(__name__)


@shared_task(name='cleanup_expired_jwt_tokens')
def cleanup_expired_jwt_tokens():
    """
    Periodic task to delete expired JWT tokens from the database.
    
    This task:
    1. Identifies all OutstandingTokens with expires_at < now
    2. Deletes them (cascades to BlacklistedTokens via FK)
    3. Logs the cleanup statistics
    
    Runs daily at 2:00 AM UTC via Celery Beat.
    
    Returns:
        dict: Status and statistics of the cleanup operation
    """
    try:
        now = timezone.now()
        
        # Query expired tokens
        expired_tokens = OutstandingToken.objects.filter(expires_at__lt=now)
        count = expired_tokens.count()
        
        if count > 0:
            # Delete expired tokens (cascades to blacklisted tokens via FK)
            deleted_count, _ = expired_tokens.delete()
            logger.info(
                f"JWT Token Cleanup: Successfully deleted {deleted_count} "
                f"expired tokens (expired before {now})"
            )
            return {
                'status': 'success',
                'deleted_count': deleted_count,
                'timestamp': now.isoformat()
            }
        else:
            logger.info(f"JWT Token Cleanup: No expired tokens found at {now}")
            return {
                'status': 'success',
                'deleted_count': 0,
                'message': 'No expired tokens to clean',
                'timestamp': now.isoformat()
            }
            
    except Exception as e:
        logger.error(f"JWT Token Cleanup failed: {str(e)}", exc_info=True)
        return {
            'status': 'error',
            'error': str(e),
            'timestamp': timezone.now().isoformat()
        }
