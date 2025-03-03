from django.db import models

# Create your models here.


# Task model to store tasks
class Task(models.Model):
    user = models.ForeignKey("accounts.Profile", on_delete=models.CASCADE)
    title = models.CharField(max_length=255)
    completed = models.BooleanField(default=False)
    created_date = models.DateTimeField(auto_now_add=True)
    updated_date = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title

    class Meta:
        ordering = ["-created_date"]
