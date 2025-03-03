from django.views.generic import ListView, CreateView, UpdateView, DeleteView
from django.contrib.auth.mixins import LoginRequiredMixin
from .models import Task
from accounts.models import Profile
from .forms import TaskForm

# Create your views here.


# TaskList view to list all tasks for a user
class TaskList(LoginRequiredMixin, ListView):
    model = Task
    context_object_name = "tasks"
    template_name = "todo/task_list.html"

    def get_queryset(self):
        return self.model.objects.filter(user=self.request.user.id)


class TaskCreateView(LoginRequiredMixin, CreateView):
    model = Task
    form_class = TaskForm
    success_url = '/'

    def form_valid(self, form):
        form.instance.user = Profile.objects.get(user=self.request.user)
        return super().form_valid(form)


class TaskEditView(LoginRequiredMixin, UpdateView):
    model = Task
    form_class = TaskForm
    success_url = '/'


class TaskDeleteView(LoginRequiredMixin, DeleteView):
    model = Task
    success_url = '/'
