from celery import shared_task
from todo.models import Task
from time import sleep


@shared_task
def delete_done_tasks(*args, **kwargs):
    tasks = Task.objects.filter(completed=True)
    sleep(10)
    if tasks.delete():
        print('tasks deleted!')
