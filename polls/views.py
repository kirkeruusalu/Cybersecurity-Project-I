import os
from django.db.models import F
from django.urls import reverse
from django.http import HttpResponse, HttpResponseRedirect, HttpResponseForbidden
from django.template import loader
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.views import LoginView, LogoutView
from django.core.files.storage import FileSystemStorage
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, render, redirect
from django.views import generic
from .models import Choice, Question, FileUpload

"""Flaw 2: comment this out to fix flaw"""
ALLOWED_EXTENSIONS = [".pdf", ".txt"]

# Create your views here.
class IndexView(generic.ListView):
    template_name = "polls/index.html"
    context_object_name = "latest_question_list"

    def get_queryset(self):
        return Question.objects.filter(owner=self.request.user).order_by("-pub_date")[:5]
    
class DetailView(generic.DetailView):
    model = Question
    template_name = "polls/detail.html"

    """Flaw 1: comment this out to fix flaw
    def get_queryset(self):
        return Question.objects.filter(owner=self.request.user)
    """

class ResultsView(generic.DetailView):
    model = Question
    template_name = "polls/results.html"

    """Flaw 1: comment this out to fix flaw
    def get_queryset(self):
        return Question.objects.filter(owner=self.request.user)
    """

class CustomLoginView(LoginView):
    template_name = "polls/registration/login.html"

class CustomLogoutView(LogoutView):
    template_name = "polls/registration/login.html"

def beginning(request):
    return render(request, "polls/beginning.html")

def vote(request, question_id):
    question = get_object_or_404(Question, pk=question_id)

    """Flaw 1: comment this out to fix flaw
    if question.owner != request.user:
        return HttpResponseForbidden("You are not allowed to vote on this")
    """

    try:
        selected_choice = question.choice_set.get(pk=request.POST["choice"])
    except (KeyError, Choice.DoesNotExist):
        return render(
            request,
            "polls/detail.html",
            {
                "question": question,
                "error_message": "You didn't select a choice.",
            },
        )
    else:
        selected_choice.votes = F("votes") + 1
        selected_choice.save()
        return HttpResponseRedirect(reverse("polls:results", args=(question.id,)))
    
def register(request):
    if request.method == "POST":
        form = UserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect("polls:login")
    else:
        form = UserCreationForm()
    return render(request, "polls/registration/register.html", {"form": form})


@login_required
def upload_file(request):
    if request.method == "POST" and request.FILES.get("file"):
        f = request.FILES["file"]
        ext = os.path.splitext(f.name)[1].lower()
        """Flaw 2: comment this out to fix flaw"""
        if ext not in ALLOWED_EXTENSIONS:
            return HttpResponseForbidden("File type not allowed")
        upload = FileUpload(owner=request.user, file=f)
        upload.save()
        return HttpResponse("File uploaded successfully — no checks done.")
    return render(request, "polls/upload.html")
