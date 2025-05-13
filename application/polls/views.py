import os
from django.db.models import F
from django.urls import reverse
from django.core.exceptions import ValidationError
from django.http import HttpResponse, HttpResponseRedirect, HttpResponseForbidden
from django.template import loader
from django.contrib.auth import login
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.views import LoginView, LogoutView
from django.utils.decorators import method_decorator
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, render, redirect
from django.views import generic
from django.contrib import messages
import sqlite3
from .models import Choice, Question, FileUpload


import logging
logger = logging.getLogger(__name__)

# Create your views here.
@method_decorator(login_required, name='dispatch')
class IndexView(generic.ListView):
    template_name = "polls/index.html"
    context_object_name = "latest_question_list"

    def get_queryset(self):
        return Question.objects.all()
    
@method_decorator(login_required, name='dispatch')
class DetailView(generic.DetailView):
    model = Question
    template_name = "polls/detail.html"


@method_decorator(login_required, name='dispatch')
class ResultsView(generic.DetailView):
    model = Question
    template_name = "polls/results.html"

   
    def get(self, request, *args, **kwargs):
        self.object = self.get_object()
        
        context = self.get_context_data(object=self.object)
        return self.render_to_response(context)
    
    
class CustomLoginView(LoginView):
    template_name = "polls/registration/login.html"

    def form_valid(self, form):
        user = form.get_user()
       #Flaw 5 fix: logger.info(f"User '{user} logged in.")
        return super().form_valid(form)


class CustomLogoutView(LogoutView):
    template_name = "polls/registration/login.html"

    def dispatch(self, request, *args, **kwargs):
       #Flaw 5 fix: logger.info(f"User '{request.user}', logged out.")
        return super().dispatch(request, *args, **kwargs)

def beginning(request):
    return render(request, "polls/beginning.html")

@login_required
def vote(request, question_id):
    question = get_object_or_404(Question, pk=question_id)

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
        #Flaw 5 fix: logger.info(f"User '{request.user.username}' voted on question ID {question.id}, choice ID {selected_choice.id}")
        return HttpResponseRedirect(reverse("polls:results", args=(question.id,)))


def register(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password1 = request.POST.get("password1")
        password2 = request.POST.get("password2")

        if password1 != password2:
            messages.error(request, "Passwords do not match.")
            # FLaw 5 fix: logger.warning(f"Failed registration: password mismatch for '{username}'")
        elif User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists.")
            # Flaw 5 fix: logger.warning(f"Failed registration: username '{username}' already exists")
        else:
            return redirect("polls:index")

    return render(request, "polls/registration/register.html")

"""
Flaw 2 fix: use this instead of the previous register function:
def register(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password1 = request.POST.get("password1")
        password2 = request.POST.get("password2")

        if password1 != password2:
            messages.error(request, "Passwords do not match.")
            logger.warning(f"Failed registration: password mismatch for '{username}'")
        elif User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists.")
            logger.warning(f"Failed registration: username '{username}' already exists")
        else:
            
            try:
                validate_password(password1)
                user = User.objects.create_user(username=username, password=password1)
                login(request, user)
                logger.info(f"New user registered: '{username}'")
                return redirect("polls:index")
            except ValidationError as e:
                for error in e.messages:
                    messages.error(request, error)
                logger.warning(f"Failed registration for '{username}': {e.messages}")

    return render(request, "polls/registration/register.html")
"""

@login_required
def search_questions(request):
    search_term = request.GET.get("q", "").strip()

    if not search_term:
        return render(request, "polls/search.html", {"results": []})

    results = Question.objects.filter(
        question_text__icontains=search_term)

    return render(request, "polls/search_results.html", {"results": results})

@login_required
def create_question(request):
    if request.method == "POST":
        question_text = request.POST.get("question_text")
        question = Question(question_text=question_text, owner=request.user)
        question.save()

        choice_texts = request.POST.getlist("choice_text[]")
        for choice_text in choice_texts:
            if choice_text.strip():
                Choice.objects.create(question=question, choice_text=choice_text)

        return redirect("polls:detail", pk=question.id)
    return render(request, "polls/create.html")


#flawed version, both sql injection and broken access control
@login_required
def delete_question(request, question_id):
    conn = sqlite3.connect("db.sqlite3")
    cursor = conn.cursor()
    query = f"DELETE FROM polls_question WHERE id = {question_id}"
    cursor.execute(query)
    conn.commit()
    conn.close()
    messages.success(request, "Poll deleted successfully")
    return redirect("polls:index")


"""Flaw 3 and flaw 1 fix: use this function instead of the one above.
@login_required
def delete_question(request, question_id):
    question = get_object_or_404(Question, pk=question_id)

    #Flaw 1: comment this out to fix flaw
    #if question.owner != request.user:
        #return HttpResponseForbidden("You are not allowed to delete this question")

    question.delete()
    messages.success(request, "Poll deleted successfully")
    return redirect("polls:index")
"""

"""Independent fix for flaw 3 while still keeping flaw 1:
@login_required
def delete_question(request, question_id):
    question = get_object_or_404(Question, pk=question_id)
    question.delete()
    messages.success(request, "Poll deleted successfully")
    return redirect("polls:index")
"""