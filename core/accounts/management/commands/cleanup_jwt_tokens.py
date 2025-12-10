from django.core.management.base import BaseCommand
from accounts.tasks import cleanup_expired_jwt_tokens


class Command(BaseCommand):
    help = 'Manually trigger cleanup of expired JWT tokens'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be deleted without actually deleting',
        )

    def handle(self, *args, **options):
        self.stdout.write('Starting JWT token cleanup...')
        
        if options['dry_run']:
            from django.utils import timezone
            from rest_framework_simplejwt.token_blacklist.models import OutstandingToken
            
            now = timezone.now()
            expired_count = OutstandingToken.objects.filter(expires_at__lt=now).count()
            
            self.stdout.write(
                self.style.WARNING(
                    f"DRY RUN: Would delete {expired_count} expired tokens (not actually deleting)"
                )
            )
            return
        
        result = cleanup_expired_jwt_tokens()
        
        if result['status'] == 'success':
            deleted_count = result.get('deleted_count', 0)
            if deleted_count > 0:
                self.stdout.write(
                    self.style.SUCCESS(
                        f"✓ Cleanup complete! Deleted {deleted_count} expired tokens"
                    )
                )
            else:
                self.stdout.write(
                    self.style.SUCCESS(
                        "✓ Cleanup complete! No expired tokens found"
                    )
                )
        else:
            error_msg = result.get('error', 'Unknown error')
            self.stdout.write(
                self.style.ERROR(f"✗ Cleanup failed: {error_msg}")
            )
