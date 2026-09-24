"""Poll views (Django tutorial, parts 3-4)."""

from django.http import HttpResponse
from django.shortcuts import get_object_or_404, render
from django.views import View, generic

from .models import Question


def index(request):
    latest_question_list = Question.objects.order_by("-pub_date")[:5]
    return render(request, "polls/index.html", {"latest_question_list": latest_question_list})


def detail(request, question_id):
    question = get_object_or_404(Question, pk=question_id)
    return render(request, "polls/detail.html", {"question": question})


def vote(request, question_id):
    question = get_object_or_404(Question, pk=question_id)
    selected_choice = question.choice_set.get(pk=request.POST["choice"])
    selected_choice.votes += 1
    selected_choice.save()
    return HttpResponse(_tally(question))


class ResultsView(generic.DetailView):
    model = Question
    template_name = "polls/results.html"


class ExportView(View):
    """CSV export of one question's results."""

    def get(self, request, question_id):
        question = get_object_or_404(Question, pk=question_id)
        return HttpResponse(self.rows(question), content_type="text/csv")

    def rows(self, question):
        """Helper, not a request handler."""
        return "\n".join(f"{c.choice_text},{c.votes}" for c in question.choice_set.all())


def _tally(question):
    """Not a view — only called from ``vote``."""
    return ", ".join(f"{c.choice_text}: {c.votes}" for c in question.choice_set.all())
