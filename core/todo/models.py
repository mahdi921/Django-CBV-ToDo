from django.db import models
from django.urls import reverse

# Create your models here.


# Task model to store tasks
class Task(models.Model):
    author = models.ForeignKey("accounts.Profile", on_delete=models.CASCADE)
    title = models.CharField(max_length=255)
    completed = models.BooleanField(default=False)
    created_date = models.DateTimeField(auto_now_add=True)
    updated_date = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title

    class Meta:
        ordering = ["-created_date"]

    def get_absolute_api_url(self):
        return reverse("todo:api-v1:task-detail", kwargs={"pk": self.pk})


class Assignment(models.Model):
    """Assignment model to store sub-tasks within a task"""
    task = models.ForeignKey(Task, on_delete=models.CASCADE, related_name='assignments')
    description = models.TextField()
    completed = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    order = models.IntegerField(default=0)  # For custom ordering

    def __str__(self):
        return f"{self.task.title} - {self.description[:50]}"

    class Meta:
        ordering = ['order', '-created_at']
