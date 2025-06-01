from django import forms
from todo.models import Task


class TaskForm(forms.ModelForm):

    class Meta:
        model = Task
        fields = ["title", "completed"]
        verbose_name = "Task"
        verbose_name_plural = "Tasks"
