import datetime 

from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User


# Create your models here.
class Question(models.Model):
    question_text = models.CharField(max_length=200)
    owner = models.ForeignKey(User, on_delete=models.CASCADE)

    def __str__(self):
        return self.question_text
    
    @property
    def total_votes(self):
        return sum(choice.votes for choice in self.choice_set.all())

class Choice(models.Model):
    question = models.ForeignKey(Question,
                                 on_delete=models.CASCADE)
    choice_text = models.CharField(max_length=200)
    votes = models.IntegerField(default=0)

    def __str__(self):
        return self.choice_text

    
class FileUpload(models.Model):
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    file = models.FileField(upload_to="uploads/")
    uploaded_at = models.DateTimeField(auto_now_add=True)
    