from faker import Faker
from django.core.management.base import BaseCommand
from todo.models import Task
from accounts.models import User, Profile
import random


class Command(BaseCommand):
    help = "Generating dummy tasks for test"

    def __init__(self, *args, **kwargs):
        super(Command, self).__init__(*args, **kwargs)
        self.fake = Faker()

    def handle(self, *args, **kwargs):
        user = User.objects.create_user(
            email=self.fake.email(), password="Fakepass@123456"
        )
        profile = Profile.objects.get(user=user)
        profile.first_name = self.fake.first_name()
        profile.last_name = self.fake.last_name()
        profile.bio = self.fake.text(max_nb_chars=1000)
        profile.save()
        for _ in range(5):
            Task.objects.create(
                author=profile,
                title=self.fake.text(max_nb_chars=255),
                completed=random.choice([True, False]),
            )
