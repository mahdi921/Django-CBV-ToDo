from django.views.generic import (
    ListView,
    CreateView,
    UpdateView,
    DeleteView,
    TemplateView,
)
from django.contrib.auth.mixins import LoginRequiredMixin
from .models import Task
from accounts.models import Profile
from .forms import TaskForm
from django.urls import reverse_lazy

# Create your views here.


class IndexView(TemplateView):
    template_name = "todo/index.html"


# TaskList view to list all tasks for a user
class TaskList(LoginRequiredMixin, ListView):
    model = Task
    context_object_name = "tasks"
    template_name = "todo/task_list.html"

    def get_queryset(self):
        return self.model.objects.filter(author=self.request.user.id)


class TaskCreateView(LoginRequiredMixin, CreateView):
    model = Task
    form_class = TaskForm
    success_url = reverse_lazy("todo:task-list")

    def form_valid(self, form):
        form.instance.author = Profile.objects.get(user=self.request.user)
        return super().form_valid(form)


class TaskEditView(LoginRequiredMixin, UpdateView):
    model = Task
    form_class = TaskForm
    success_url = reverse_lazy("todo:task-list")


class TaskDeleteView(LoginRequiredMixin, DeleteView):
    model = Task
    success_url = reverse_lazy("todo:task-list")
