from django.urls import path

from . import views

app_name = "polls"
urlpatterns = [
    path("", views.beginning, name="beginning"),
    path("index/", views.IndexView.as_view(), name="index"),
    path("<int:pk>/", views.DetailView.as_view(), name="detail"),
    path("<int:pk>/results/", views.ResultsView.as_view(), name="results"),
    path("<int:question_id>/vote/", views.vote, name="vote"),
    path("<str:question_id>/delete/", views.delete_question, name="delete"),
    #Flaw 2: Uncomment the following code and delete the current url for question deletion to fix flaw
    #path("<int:question_id>/delete/", views.delete_question, name="delete"),
    path("register/", views.register, name="register"),
    path("login/", views.CustomLoginView.as_view(), name="login"),
    path("logout/", views.CustomLogoutView.as_view(), name="logout"),
    path("search/", views.search_questions, name="search"),
    path("create/", views.create_question, name="create"),
]
